#!/usr/bin/env python3
# apps/dns-collector/worker.py
"""
DNS / WHOIS / RDAP / GeoIP collector with queue-based WHOIS processing.
Consumes canonical_fqdn from Kafka topic raw.hosts (or file fallback),
resolves A/AAAA/CNAME/MX/NS via configured resolver (Unbound),
queues WHOIS lookups to avoid overwhelming external servers,
parses whois, RDAP/ASN, GeoIP, computes nameserver entropy features,
writes JSONL to /out and publishes to Kafka topic domains.resolved.
"""

import os, time, asyncio, ujson, traceback
import socket, ssl
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# DNS
import dns.resolver
import dns.exception

# WHOIS / RDAP / ASN / GeoIP
import whois
from ipwhois import IPWhois
from dateutil import parser as dateparse
try:
    import geoip2.database
except Exception:
    geoip2 = None

# Kafka / config
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "true").lower() == "true"
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
# Allow comma-separated topics; default listens to both raw.hosts and domains.candidates
INPUT_TOPICS = [t.strip() for t in os.getenv("INPUT_TOPIC", "raw.hosts,domains.candidates").split(",") if t.strip()]
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC", "domains.resolved")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/out"))
NAMESERVER = os.getenv("NAMESERVER", "unbound")
MAX_WORKERS = int(os.getenv("MAX_WORKERS", "12"))
GEOIP_CITY_DB = os.getenv("GEOIP_CITY_DB", "/configs/mmdb/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.getenv("GEOIP_ASN_DB", "/configs/mmdb/GeoLite2-ASN.mmdb")
CONSUMER_GROUP = os.getenv("CONSUMER_GROUP", "dns-collector-group")
RETRY_WAIT = float(os.getenv("RETRY_WAIT", "2.0"))
MAX_CONCURRENT_DNS = int(os.getenv("MAX_CONCURRENT_DNS", "50"))

# Optional date filter (inclusive window). If set, only allow records where
# WHOIS creation_date OR certificate notBefore date falls within the window.
# Format examples: "2025-10-01", "2025/10/01", "1/10/2025" (auto-parsed)
DATE_FILTER_START = os.getenv("DATE_FILTER_START", "").strip()
DATE_FILTER_END = os.getenv("DATE_FILTER_END", "").strip()
# Mode: 'any' (pass if either WHOIS or cert date in range) or 'both'
DATE_FILTER_MODE = os.getenv("DATE_FILTER_MODE", "any").strip().lower()

# WHOIS queue settings
WHOIS_WORKERS = int(os.getenv("WHOIS_WORKERS", "2"))  # Concurrent WHOIS lookups
WHOIS_DELAY_MS = int(os.getenv("WHOIS_DELAY_MS", "500"))  # Delay between queries

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# configure dns.resolver to use local unbound
resolver = dns.resolver.Resolver(configure=False)
try:
    import socket
    ns_ip = socket.gethostbyname(NAMESERVER)
    resolver.nameservers = [ns_ip]
except Exception:
    resolver.nameservers = ["127.0.0.1"]

resolver.timeout = 3.0
resolver.lifetime = 5.0

# geo readers (best-effort)
geo_reader_city = None
geo_reader_asn = None
if geoip2 is not None:
    try:
        if Path(GEOIP_CITY_DB).exists():
            geo_reader_city = geoip2.database.Reader(GEOIP_CITY_DB)
    except Exception as e:
        print(f"[geo] city db open error: {e}")
    try:
        if Path(GEOIP_ASN_DB).exists():
            geo_reader_asn = geoip2.database.Reader(GEOIP_ASN_DB)
    except Exception as e:
        print(f"[geo] asn db open error: {e}")

# helpers
def now_ts():
    return time.time()

def parse_date(x):
    if not x:
        return None
    try:
        if isinstance(x, (list, tuple, set)):
            x = list(x)[0] if x else None
            if x is None:
                return None
        return dateparse.parse(str(x)).timestamp()
    except Exception:
        return None

def parse_date_env(x: str):
    """Parse a flexible date string from env into unix timestamp at 00:00 UTC.
    Accepts ISO formats or common dd/mm/yyyy and mm/dd/yyyy; relies on dateutil.
    """
    if not x:
        return None
    try:
        dt = dateparse.parse(x, dayfirst=True)  # favor dd/mm/yyyy like 1/10/2025
        # Normalize to midnight UTC for inclusive window comparisons
        return datetime(dt.year, dt.month, dt.day).timestamp()
    except Exception:
        try:
            dt = dateparse.parse(x)
            return datetime(dt.year, dt.month, dt.day).timestamp()
        except Exception:
            return None

DATE_FILTER_START_TS = parse_date_env(DATE_FILTER_START)
DATE_FILTER_END_TS = parse_date_env(DATE_FILTER_END)

def ts_to_iso(ts: float):
    try:
        if ts is None:
            return None
        return time.strftime("%Y-%m-%d", time.gmtime(ts))
    except Exception:
        return None

def date_in_window(ts: float) -> bool:
    if ts is None:
        return False
    if DATE_FILTER_START_TS is None or DATE_FILTER_END_TS is None:
        return True  # no filter configured
    return (DATE_FILTER_START_TS <= ts <= (DATE_FILTER_END_TS + 86399.999))

def fetch_cert_notbefore(hostname: str, port: int = 443, timeout: float = 5.0):
    """Return certificate notBefore timestamp for a hostname if available.
    Uses a non-verifying SSL context to extract certificate dates even for invalid certs.
    Returns float timestamp or None.
    """
    if not hostname:
        return None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None
                nb = cert.get("notBefore")
                if not nb:
                    return None
                # Example: 'Oct  1 00:00:00 2025 GMT'
                try:
                    dt = datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z")
                except Exception:
                    # Fallback parse
                    dt = dateparse.parse(str(nb))
                return dt.timestamp()
    except Exception:
        return None

def shannon_entropy(s: str):
    if not s:
        return 0.0
    from collections import Counter
    import math
    c = Counter(s)
    l = len(s)
    return -sum((freq/l) * math.log2(freq/l) for freq in c.values())

# blocking whois lookup (wrap into executor)
def whois_lookup(domain):
    out = {}
    try:
        w = whois.whois(domain)
        # whois.WhoisEntry behaves like dict; some fields may be sets/lists
        out["registrar"] = w.get("registrar")
        creation_ts = parse_date(w.get("creation_date"))
        expiration_ts = parse_date(w.get("expiration_date"))
        out["creation_date"] = creation_ts
        out["expiration_date"] = expiration_ts
        out["status"] = w.get("status")
        ns_raw = w.get("name_servers") or []
        # ensure JSON-serializable list
        out["name_servers"] = list(ns_raw) if not isinstance(ns_raw, list) else ns_raw

        # Domain age features
        if creation_ts:
            now = time.time()
            domain_age_days = int((now - creation_ts) / 86400)
            out["domain_age_days"] = domain_age_days
            out["is_newly_registered"] = domain_age_days < 30
            out["is_very_new"] = domain_age_days < 7
            out["created_date_iso"] = time.strftime("%Y-%m-%d", time.gmtime(creation_ts))

        # Expiry proximity
        if expiration_ts:
            now = time.time()
            days_until_expiry = int((expiration_ts - now) / 86400)
            out["days_until_expiry"] = days_until_expiry
            out["expires_soon"] = days_until_expiry < 30
            out["expiry_date_iso"] = time.strftime("%Y-%m-%d", time.gmtime(expiration_ts))

    except Exception as e:
        out["error"] = str(e)
    return out

def ip_rdap_lookup(ip):
    out = {}
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(asn_methods=["whois", "http"])
        out["asn"] = res.get("asn")
        out["asn_cidr"] = res.get("asn_cidr")
        out["asn_date"] = res.get("asn_date")
        out["network"] = res.get("network", {})
    except Exception as e:
        out["error"] = str(e)
    return out

def geoip_lookup_ip(ip):
    out = {}
    if geo_reader_city:
        try:
            r = geo_reader_city.city(ip)
            out["country"] = r.country.iso_code
            out["city"] = r.city.name
            out["latitude"] = r.location.latitude
            out["longitude"] = r.location.longitude
        except Exception:
            pass
    if geo_reader_asn:
        try:
            r = geo_reader_asn.asn(ip)
            out["asn"] = r.autonomous_system_number
            out["asn_org"] = r.autonomous_system_organization
        except Exception:
            pass
    return out

# DNS resolution (synchronous) returns dict with answers and ttls
def resolve_all(fqdn):
    result = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "ttls": {}}
    try:
        # CNAME
        try:
            ans = resolver.resolve(fqdn, "CNAME")
            for rr in ans:
                result["CNAME"].append(str(rr.target).rstrip("."))
                ttl = getattr(rr, "ttl", 0) or 0
                result["ttls"]["CNAME"] = min(ttl, result["ttls"].get("CNAME", ttl or 0) or ttl)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            pass

        # A
        try:
            ans = resolver.resolve(fqdn, "A")
            for rr in ans:
                result["A"].append(str(rr.address))
                result["ttls"].setdefault("A", getattr(rr, "ttl", 0))
        except Exception:
            pass

        # AAAA
        try:
            ans = resolver.resolve(fqdn, "AAAA")
            for rr in ans:
                result["AAAA"].append(str(rr.address))
                result["ttls"].setdefault("AAAA", getattr(rr, "ttl", 0))
        except Exception:
            pass

        # MX
        try:
            ans = resolver.resolve(fqdn, "MX")
            for rr in ans:
                result["MX"].append(str(rr.exchange).rstrip("."))
                result["ttls"].setdefault("MX", getattr(rr, "ttl", 0))
        except Exception:
            pass

        # NS
        try:
            ans = resolver.resolve(fqdn, "NS")
            ns_list = []
            for rr in ans:
                ns_list.append(str(rr.target).rstrip("."))
                result["ttls"].setdefault("NS", getattr(rr, "ttl", 0))
            result["NS"] = ns_list
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)
    return result

# feature extraction for NS entropy / label stats
def nameserver_features(ns_list):
    data = {}
    concat = ",".join(ns_list) if ns_list else ""
    data["ns_count"] = len(ns_list)
    data["ns_concat_entropy"] = round(shannon_entropy(concat), 4)
    import re
    label_lens = []
    numeric_labels = 0
    for ns in ns_list:
        first_label = ns.split(".", 1)[0] if ns else ""
        label_lens.append(len(first_label))
        if re.search(r"\d", first_label):
            numeric_labels += 1
    data["ns_avg_label_len"] = (sum(label_lens) / len(label_lens)) if label_lens else 0.0
    data["ns_numeric_frac"] = (numeric_labels / len(ns_list)) if ns_list else 0.0
    return data

class WhoisQueue:
    """Queue-based WHOIS processor to avoid overwhelming external servers"""
    def __init__(self, num_workers=2, delay_ms=500):
        self.queue = asyncio.Queue()
        self.num_workers = num_workers
        self.delay_sec = delay_ms / 1000.0
        self.workers = []
        self.stats = {"processed": 0, "queued": 0, "errors": 0}
        
    async def worker(self, worker_id, loop, executor):
        """Worker that processes WHOIS lookups with rate limiting"""
        print(f"[whois-worker-{worker_id}] Started")
        
        while True:
            try:
                # Get next domain to lookup
                domain, result_future = await self.queue.get()
                
                if domain is None:  # Shutdown signal
                    self.queue.task_done()
                    break
                
                try:
                    # Perform WHOIS lookup
                    result = await loop.run_in_executor(executor, whois_lookup, domain)
                    result_future.set_result(result)
                    self.stats["processed"] += 1
                    
                except Exception as e:
                    result_future.set_exception(e)
                    self.stats["errors"] += 1
                    print(f"[whois-worker-{worker_id}] Error for {domain}: {e}")
                
                finally:
                    self.queue.task_done()
                    # Rate limit: wait before next query
                    await asyncio.sleep(self.delay_sec)
                    
            except Exception as e:
                print(f"[whois-worker-{worker_id}] Worker error: {e}")
                
        print(f"[whois-worker-{worker_id}] Stopped")
    
    async def start(self, loop, executor):
        """Start WHOIS worker pool"""
        for i in range(self.num_workers):
            worker = asyncio.create_task(self.worker(i, loop, executor))
            self.workers.append(worker)
        print(f"[whois-queue] Started {self.num_workers} workers (delay={self.delay_sec}s)")
    
    async def lookup(self, domain):
        """Queue a WHOIS lookup and return a future"""
        future = asyncio.Future()
        await self.queue.put((domain, future))
        self.stats["queued"] += 1
        return await future
    
    async def stop(self):
        """Stop all workers"""
        print(f"[whois-queue] Stopping... (pending: {self.queue.qsize()})")
        
        # Send shutdown signals
        for _ in range(self.num_workers):
            await self.queue.put((None, None))
        
        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        print(f"[whois-queue] Stats - processed: {self.stats['processed']}, errors: {self.stats['errors']}")

async def connect_kafka_with_retry(max_wait=120):
    """Connect to Kafka with exponential backoff retry"""
    if not KAFKA_ENABLED:
        return None, None

    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

    delay = 1.0
    waited = 0.0

    while waited < max_wait:
        consumer = None
        producer = None
        try:
            print(f"[dns] Attempting Kafka connection to {KAFKA_BOOTSTRAP}...")

            # Subscribe to all configured input topics
            consumer = AIOKafkaConsumer(
                *INPUT_TOPICS,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=CONSUMER_GROUP,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
            )

            producer = AIOKafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                linger_ms=50,
            )

            await consumer.start()
            await producer.start()

            print(f"[dns] Kafka connected successfully!")
            return consumer, producer

        except Exception as e:
            print(f"[dns] Kafka connection failed: {e}. Retrying in {delay:.1f}s...")

            # Clean up partial connections
            if consumer:
                try:
                    await consumer.stop()
                except:
                    pass
            if producer:
                try:
                    await producer.stop()
                except:
                    pass

            await asyncio.sleep(delay)
            waited += delay
            delay = min(delay * 1.5, 10.0)

    print("[dns] Could not connect to Kafka after retries. Running in file-only mode.")
    return None, None

async def process_fqdn(fqdn, orig_payload, loop, executor, whois_queue):
    """Resolve, enrich and return an enriched record."""
    ts = now_ts()
    fqdn = fqdn.strip().strip(".").lower()

    # DNS (blocking -> executor)
    dns_result = await loop.run_in_executor(executor, resolve_all, fqdn)

    # WHOIS (queued - non-blocking)
    whois_res = await whois_queue.lookup(fqdn)

    # NS features
    ns_feats = nameserver_features(dns_result.get("NS") or [])

    enriched = {
        "src": "dns",
        "observed_at": ts,
        "canonical_fqdn": fqdn,
        "registrable": orig_payload.get("registrable"),
        "seed_registrable": orig_payload.get("seed_registrable"),  # Preserve seed for tracking
        "cse_id": orig_payload.get("cse_id"),  # Preserve CSE ID
        "is_original_seed": orig_payload.get("is_original_seed", False),  # Preserve original seed flag
        "dns": dns_result,
        "ns_features": ns_feats,
        "whois": whois_res,
        "geoip": {},
        "rdap": {},
        "ttl_summary": dns_result.get("ttls") or {},
    }

    # If any A/AAAA, add IP-level enrichment using first IP
    ips = list(dns_result.get("A", []) or []) + list(dns_result.get("AAAA", []) or [])
    if ips:
        primary = ips[0]
        rdap_res = await loop.run_in_executor(executor, ip_rdap_lookup, primary)
        geo = await loop.run_in_executor(executor, geoip_lookup_ip, primary)
        enriched["rdap"] = rdap_res
        enriched["geoip"] = geo

    enriched["timestamp"] = time.time()
    enriched["stage"] = "resolved"
    return enriched

async def main():
    print("[dns] starting DNS/WHOIS collector")
    print(f"[dns] resolver nameservers={resolver.nameservers}")
    print(f"[dns] Max concurrent DNS lookups: {MAX_CONCURRENT_DNS}")
    print(f"[dns] WHOIS workers: {WHOIS_WORKERS}, delay: {WHOIS_DELAY_MS}ms")

    dns_semaphore = asyncio.Semaphore(MAX_CONCURRENT_DNS)
    file_lock = asyncio.Lock()

    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    loop = asyncio.get_event_loop()

    # Initialize WHOIS queue
    whois_queue = WhoisQueue(num_workers=WHOIS_WORKERS, delay_ms=WHOIS_DELAY_MS)
    await whois_queue.start(loop, executor)

    # Kafka (optional)
    consumer, producer = await connect_kafka_with_retry()

    # One output file per run
    tsstr = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    out_path = OUTPUT_DIR / f"domains_resolved_{tsstr}.jsonl"
    output_file = out_path.open("a", encoding="utf-8")
    print(f"[dns] Writing to: {out_path}")

    active_tasks = set()
    processed_count = 0

    async def limited_task(fqdn, payload):
        """Semaphore-guarded processing + safe file write + Kafka publish."""
        async with dns_semaphore:
            try:
                enriched = await process_fqdn(fqdn, payload, loop, executor, whois_queue)

                # Optional: date-window filter
                if DATE_FILTER_START_TS is not None and DATE_FILTER_END_TS is not None:
                    whois_res = enriched.get("whois", {}) or {}
                    created_ts = whois_res.get("creation_date")
                    created_ok = date_in_window(created_ts) if created_ts else False

                    cert_ok = False
                    cert_nb_ts = None
                    # Short-circuit to avoid unnecessary TLS probe
                    if DATE_FILTER_MODE == "any" and created_ok:
                        cert_ok = True
                    elif DATE_FILTER_MODE == "both" and not created_ok:
                        cert_ok = False
                    else:
                        try:
                            host_for_cert = enriched.get("canonical_fqdn") or fqdn
                            cert_nb_ts = await loop.run_in_executor(executor, fetch_cert_notbefore, host_for_cert)
                            if cert_nb_ts:
                                cert_ok = date_in_window(cert_nb_ts)
                        except Exception:
                            cert_ok = False

                    allow = (created_ok and cert_ok) if DATE_FILTER_MODE == "both" else (created_ok or cert_ok)
                    if not allow:
                        created_iso = whois_res.get("created_date_iso") or ts_to_iso(created_ts)
                        cert_nb_iso = ts_to_iso(cert_nb_ts)
                        win_start = ts_to_iso(DATE_FILTER_START_TS)
                        win_end = ts_to_iso(DATE_FILTER_END_TS)
                        reasons = []
                        if created_ts is None:
                            reasons.append("whois:missing")
                        elif not created_ok:
                            reasons.append("whois:out_of_range")
                        if cert_nb_ts is None:
                            reasons.append("cert:missing")
                        elif not cert_ok:
                            reasons.append("cert:out_of_range")
                        why = ",".join(reasons) if reasons else "out_of_range"
                        print(
                            f"[dns] DROP {fqdn} (date filter): window=[{win_start}..{win_end}] mode={DATE_FILTER_MODE} "
                            f"whois_created={created_iso or '-'} cert_notBefore={cert_nb_iso or '-'} "
                            f"created_ok={created_ok} cert_ok={cert_ok} why={why}"
                        )
                        return

                # Write JSONL (locked)
                async with file_lock:
                    try:
                        output_file.write(ujson.dumps(enriched) + "\n")
                        output_file.flush()
                    except Exception as e:
                        print(f"[dns] WARN file write failed for {fqdn}: {e}")

                # Kafka publish (if enabled)
                if producer:
                    try:
                        payload_bytes = ujson.dumps(enriched).encode("utf-8")
                        key_bytes = (enriched.get("registrable") or "").encode("utf-8")
                        await producer.send_and_wait(OUTPUT_TOPIC, payload_bytes, key=key_bytes)
                    except Exception as e:
                        print(f"[dns] WARN kafka send failed for {fqdn}: {e}")
            except Exception as e:
                print(f"[dns] Error processing {fqdn}: {e}")
                traceback.print_exc()

    try:
        if consumer and producer:
            print(f"[dns] Listening on topics: {', '.join(INPUT_TOPICS)}")
            try:
                async for msg in consumer:
                    try:
                        payload = ujson.loads(msg.value.decode("utf-8"))
                    except Exception:
                        continue

                    fqdn = payload.get("canonical_fqdn") or payload.get("fqdn") or payload.get("host")
                    if not fqdn:
                        continue

                    try:
                        coro = limited_task(fqdn, payload)
                        task = asyncio.create_task(coro)
                        active_tasks.add(task)
                        task.add_done_callback(lambda t: active_tasks.discard(t))
                    except Exception as e:
                        print(f"[dns] Error creating task for {fqdn}: {e}")

                    processed_count += 1

                    if processed_count % 100 == 0:
                        qsize = whois_queue.queue.qsize()
                        print(f"[dns] Processed {processed_count} domains, active tasks: {len(active_tasks)}, WHOIS queue: {qsize}")

                    # prevent unbounded growth
                    if len(active_tasks) >= MAX_CONCURRENT_DNS * 2:
                        print(f"[dns] Too many pending tasks ({len(active_tasks)}), waiting...")
                        await asyncio.sleep(1)

            except Exception as e:
                print(f"[dns] Consumer error: {e}")
                traceback.print_exc()
        else:
            print("[dns] Running in file-only mode - no Kafka consumer active")
            try:
                while True:
                    await asyncio.sleep(60)
                    qsize = whois_queue.queue.qsize()
                    print(f"[dns] Idle mode - WHOIS queue: {qsize}")
            except KeyboardInterrupt:
                pass
    
    finally:
        print("[dns] Shutting down...")
        
        if active_tasks:
            print(f"[dns] Waiting for {len(active_tasks)} active tasks to complete...")
            await asyncio.gather(*active_tasks, return_exceptions=True)
        
        # Stop WHOIS queue
        await whois_queue.stop()
        
        output_file.close()
        
        if consumer:
            try:
                await consumer.stop()
            except:
                pass
        if producer:
            try:
                await producer.stop()
            except:
                pass

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[dns] interrupted")
    except Exception as e:
        print(f"[dns] FATAL: {e}")
        traceback.print_exc()
