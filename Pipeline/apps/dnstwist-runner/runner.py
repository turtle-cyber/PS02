import os, csv, time, ujson, asyncio, subprocess, shlex, socket
from datetime import datetime
from pathlib import Path
import tldextract, idna
import redis

# Env
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "false").lower() == "true"
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "raw.hosts")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/out"))
THREADS = int(os.getenv("THREADS", "16"))
NAMESERVERS = os.getenv("NAMESERVERS", "unbound:5335")
KAFKA_RETRY_ATTEMPTS = int(os.getenv("KAFKA_RETRY_ATTEMPTS", "10"))
KAFKA_RETRY_DELAY = int(os.getenv("KAFKA_RETRY_DELAY", "5"))

# Redis config
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# Config paths mounted from /configs
DICT_DIR = Path("/configs/dictionaries")
CSE_SEEDS = Path("/configs/cse_seeds.csv")
COMMON_TLDS = (DICT_DIR / "common_tlds.dict").as_posix()
INDIA_TLDS  = (DICT_DIR / "india_tlds.dict").as_posix()
ENGLISH_DICT = (DICT_DIR / "english.dict").as_posix()
HIGH_RISK_DICT = (DICT_DIR / "high_risk.dict").as_posix()

# Fuzzer sets
PASS_A_FUZZERS = "addition,bitsquatting,homoglyph,hyphenation,insertion,omission,repetition,replacement,subdomain,transposition,vowel-swap,dictionary,tld-swap"
PASS_B_FUZZERS = "homoglyph,transposition,insertion,omission,replacement,addition,dictionary,tld-swap"
PASS_C_FUZZERS = "dictionary,tld-swap,addition,replacement"


extract = tldextract.TLDExtract(suffix_list_urls=None)  # offline PSL

async def kafka_producer():
    from aiokafka import AIOKafkaProducer
    from aiokafka.errors import KafkaConnectionError
    
    for attempt in range(1, KAFKA_RETRY_ATTEMPTS + 1):
        try:
            print(f"[kafka] Connection attempt {attempt}/{KAFKA_RETRY_ATTEMPTS}...")
            prod = AIOKafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                linger_ms=50,
                request_timeout_ms=30000,
                retry_backoff_ms=500
            )
            await prod.start()
            print("[kafka] Connected successfully!")
            return prod
        except KafkaConnectionError as e:
            if attempt < KAFKA_RETRY_ATTEMPTS:
                print(f"[kafka] Connection failed: {e}. Retrying in {KAFKA_RETRY_DELAY}s...")
                await asyncio.sleep(KAFKA_RETRY_DELAY)
            else:
                print(f"[kafka] Failed to connect after {KAFKA_RETRY_ATTEMPTS} attempts")
                raise

def get_redis_client():
    try:
        client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_connect_timeout=5)
        client.ping()
        return client
    except Exception as e:
        print(f"[redis] Warning: Could not connect: {e}")
        return None

def store_variant_stats(redis_client, domain, registered_count, unregistered_count):
    if not redis_client:
        return
    try:
        timestamp = int(time.time())
        redis_client.set(f"dnstwist:variants:{domain}", registered_count, ex=7776000)
        redis_client.set(f"dnstwist:unregistered:{domain}", unregistered_count, ex=7776000)
        redis_client.set(f"dnstwist:timestamp:{domain}", timestamp, ex=7776000)
        redis_client.zadd("dnstwist:history", {domain: timestamp})
        redis_client.incr("dnstwist:total_processed")
        redis_client.zremrangebyrank("dnstwist:history", 0, -1001)

        # Initialize feature crawler tracking
        redis_client.set(f"fcrawler:seed:{domain}:total", registered_count, ex=7776000)
        redis_client.set(f"fcrawler:seed:{domain}:crawled", 0, ex=7776000)
        redis_client.set(f"fcrawler:seed:{domain}:failed", 0, ex=7776000)
        redis_client.set(f"fcrawler:seed:{domain}:status", "pending", ex=7776000)

        print(f"[redis] Stored stats: {domain} → {registered_count} registered, {unregistered_count} unregistered")
    except Exception as e:
        print(f"[redis] Error storing stats: {e}")

def to_ascii(host: str) -> str:
    h = host.strip().strip(".").lower()
    try:
        return idna.encode(h).decode()
    except Exception:
        return h

def registrable(host: str) -> str:
    t = extract(host)
    return f"{t.domain}.{t.suffix}" if t.suffix else t.domain

def resolve_nameserver(nameserver: str) -> str:
    """Resolve nameserver hostname to IP for dnstwist (port is not supported by dnstwist CLI)."""
    if ':' in nameserver:
        host, port = nameserver.rsplit(':', 1)
    else:
        host = nameserver
    
    try:
        ip = socket.gethostbyname(host)
        return ip
    except socket.gaierror:
        print(f"[dns] Warning: Could not resolve {host}, using as-is")
        return host

def run_dnstwist(seed: str, fuzzers: str, tld_dict: str, word_dict: str = None):
    nameserver_ip = resolve_nameserver(NAMESERVERS)
    dictionary = word_dict if word_dict else ENGLISH_DICT
    cmd = f'dnstwist --registered --format json -t {THREADS} --fuzzers "{fuzzers}" ' \
          f'--nameservers {nameserver_ip} --tld {tld_dict} --dictionary {dictionary} {shlex.quote(seed)}'
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        print(f"[dnstwist] nonzero exit for {seed}: {res.stderr[:400]}")
        return []
    try:
        return ujson.loads(res.stdout) if res.stdout.strip().startswith("[") else []
    except Exception as e:
        print("[dnstwist] JSON parse error:", e)
        return []

async def emit(record: dict, prod=None, file_handle=None):
    if KAFKA_ENABLED and prod:
        try:
            await prod.send_and_wait(KAFKA_TOPIC, ujson.dumps(record).encode("utf-8"))
        except Exception as e:
            print(f"[kafka] Error sending message: {e}")
    if file_handle:
        file_handle.write(ujson.dumps(record) + "\n")

async def main():
    print("[runner] ==================== STARTING DNSTWIST RUNNER ====================")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Initialize Redis
    redis_client = get_redis_client()
    if redis_client:
        print("[redis] Connected successfully for stats tracking")
    else:
        print("[redis] Proceeding without stats tracking")

    prod = None
    if KAFKA_ENABLED:
        prod = await kafka_producer()
        # Give Kafka a moment to fully initialize the topic
        print("[kafka] Waiting 2s for topic initialization...")
        await asyncio.sleep(2)
        print("[kafka] Ready to send messages")

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_path = OUTPUT_DIR / f"dnstwist_candidates_{ts}.jsonl"
    fobj = out_path.open("a", encoding="utf-8")
    print(f"[runner] Output file: {out_path}")

    seen = set()
    seen_details = {}  # Track reasons for each domain
    domains_written = set()  # Track what we've already written to file
    
    with CSE_SEEDS.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        seeds = list(reader)

    print(f"[runner] ==================== Processing {len(seeds)} seeds ====================")
    
    for idx, row in enumerate(seeds, 1):
        cse_id = row["cse_id"].strip()
        seed_fqdn = row.get("seed_fqdn", "").strip()  # NEW: Optional seed_fqdn from CSV
        seed_reg = row["seed_registrable"].strip()
        if not seed_reg:
            continue

        # Fallback: if seed_fqdn not in CSV, use seed_registrable
        if not seed_fqdn:
            seed_fqdn = seed_reg

        print(f"\n[runner] [{idx}/{len(seeds)}] ===== Processing: {seed_reg} (seed_fqdn: {seed_fqdn}, CSE: {cse_id}) =====")

        # Mark as processing in Redis
        if redis_client:
            try:
                redis_client.set(f"dnstwist:status:{seed_reg}", "processing", ex=7776000)
                redis_client.zadd("dnstwist:queue:active", {seed_reg: int(time.time())})
                redis_client.hset(f"dnstwist:progress:{seed_reg}", mapping={
                    "started_at": str(int(time.time())),
                    "cse_id": str(cse_id)
                })
            except Exception as e:
                print(f"[redis] Error setting processing status: {e}")

        # PASS A (wide, common TLDs)
        if redis_client:
            redis_client.hset(f"dnstwist:progress:{seed_reg}", "current_pass", "A")
        print(f"[runner] Running PASS_A (common TLDs)...")
        results_a = run_dnstwist(seed_reg, PASS_A_FUZZERS, COMMON_TLDS)
        print(f"[runner] ✓ PASS_A: {len(results_a)} registered domains found")
        for r in results_a:
            fqdn = to_ascii(r.get("domain", ""))
            if not fqdn:
                continue
            
            if fqdn not in seen:
                seen.add(fqdn)
                seen_details[fqdn] = {
                    "src": "dnstwist",
                    "observed_at": time.time(),
                    "cse_id": cse_id,
                    "seed_fqdn": seed_fqdn,  # NEW: Original submitted FQDN
                    "seed_registrable": seed_reg,
                    "canonical_fqdn": fqdn,
                    "registrable": registrable(fqdn),
                    "reasons": ["dnstwist:PASS_A"],
                    "raw": r
                }
            else:
                # Domain seen before, just append reason
                if "dnstwist:PASS_A" not in seen_details[fqdn]["reasons"]:
                    seen_details[fqdn]["reasons"].append("dnstwist:PASS_A")

        # PASS B (IDN focus / India TLDs)
        if redis_client:
            redis_client.hset(f"dnstwist:progress:{seed_reg}", "current_pass", "B")
        print(f"[runner] Running PASS_B (India TLDs)...")
        results_b = run_dnstwist(seed_reg, PASS_B_FUZZERS, INDIA_TLDS)
        print(f"[runner] ✓ PASS_B: {len(results_b)} registered domains found")
        for r in results_b:
            fqdn = to_ascii(r.get("domain", ""))
            if not fqdn:
                continue
            
            if fqdn not in seen:
                seen.add(fqdn)
                seen_details[fqdn] = {
                    "src": "dnstwist",
                    "observed_at": time.time(),
                    "cse_id": cse_id,
                    "seed_fqdn": seed_fqdn,  # NEW: Original submitted FQDN
                    "seed_registrable": seed_reg,
                    "canonical_fqdn": fqdn,
                    "registrable": registrable(fqdn),
                    "reasons": ["dnstwist:PASS_B"],
                    "raw": r
                }
            else:
                if "dnstwist:PASS_B" not in seen_details[fqdn]["reasons"]:
                    seen_details[fqdn]["reasons"].append("dnstwist:PASS_B")

        # PASS C (High-risk phishing patterns)
        if redis_client:
            redis_client.hset(f"dnstwist:progress:{seed_reg}", "current_pass", "C")
        print(f"[runner] Running PASS_C (high-risk patterns)...")
        results_c = run_dnstwist(seed_reg, PASS_C_FUZZERS, COMMON_TLDS, HIGH_RISK_DICT)
        print(f"[runner] ✓ PASS_C: {len(results_c)} registered domains found")
        for r in results_c:
            fqdn = to_ascii(r.get("domain", ""))
            if not fqdn:
                continue
            
            if fqdn not in seen:
                seen.add(fqdn)
                seen_details[fqdn] = {
                    "src": "dnstwist",
                    "observed_at": time.time(),
                    "cse_id": cse_id,
                    "seed_fqdn": seed_fqdn,  # NEW: Original submitted FQDN
                    "seed_registrable": seed_reg,
                    "canonical_fqdn": fqdn,
                    "registrable": registrable(fqdn),
                    "reasons": ["dnstwist:PASS_C"],
                    "raw": r
                }
            else:
                if "dnstwist:PASS_C" not in seen_details[fqdn]["reasons"]:
                    seen_details[fqdn]["reasons"].append("dnstwist:PASS_C")
        
        # Write all NEW unique domains for this seed to file
        for fqdn in seen:
            if fqdn in seen_details and fqdn not in domains_written:
                await emit(seen_details[fqdn], prod, fobj)
                domains_written.add(fqdn)
        
        total_variants = len(results_a) + len(results_b) + len(results_c)
        print(f"[runner] ✓ Completed {seed_reg}: {total_variants} total results ({len(seen)} unique)")

        # Store stats and mark as completed in Redis
        if redis_client:
            store_variant_stats(redis_client, seed_reg, len(seen), 0)
            try:
                redis_client.set(f"dnstwist:status:{seed_reg}", "completed", ex=7776000)
                redis_client.zrem("dnstwist:queue:active", seed_reg)
                redis_client.delete(f"dnstwist:progress:{seed_reg}")
            except Exception as e:
                print(f"[redis] Error setting completed status: {e}")

    fobj.close()
    print(f"\n[runner] ==================== PROCESSING COMPLETE ====================")
    print(f"[runner] Total unique domains found: {len(seen)}")
    print(f"[runner] Output written to: {out_path}")
    print(f"[runner] File size: {out_path.stat().st_size / 1024:.2f} KB")
    
    if prod:
        await prod.stop()
        print("[kafka] Producer stopped")
    
    print("[runner] ==================== DONE ====================")
    print("[runner] Container will now exit.")

if __name__ == "__main__":
    asyncio.run(main())