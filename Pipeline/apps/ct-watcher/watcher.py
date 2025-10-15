#!/usr/bin/env python3
# apps/ct-watcher/watcher.py
# Seed-aware Certificate Transparency watcher with Kafka+JSONL output,
# periodic heartbeats, and robust auto-reconnect.
# IMPROVED: Strict token matching to reduce false positives for phishing detection

import os
import csv
import re
import time
import asyncio
import traceback
from datetime import datetime
from pathlib import Path
from functools import lru_cache

import ujson
import idna
import tldextract

# ------------------------- env & paths -------------------------

CT_URL            = os.getenv("CT_URL", "wss://certstream.calidog.io/")
OUTPUT_DIR        = Path(os.getenv("OUTPUT_DIR", "/out"))
SEEDS_PATH        = os.getenv("SEEDS_PATH", "/configs/cse_seeds.csv")
MATCH_MODE        = os.getenv("MATCH_MODE", "seed").lower()   # "seed" or "all"

KAFKA_ENABLED     = os.getenv("KAFKA_ENABLED", "true").lower() == "true"
KAFKA_BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC       = os.getenv("KAFKA_TOPIC", "raw.hosts")

HEARTBEAT_SECS    = int(os.getenv("HEARTBEAT_SECS", "30"))
RECONNECT_DELAY_S = int(os.getenv("RECONNECT_DELAY_S", "5"))
MAX_RECONNECT_S   = int(os.getenv("MAX_RECONNECT_S", "60"))
VERBOSE_LOGGING   = os.getenv("VERBOSE_LOGGING", "false").lower() == "true"

_extract = tldextract.TLDExtract(suffix_list_urls=None)

# ------------------------- helpers -------------------------

def to_ascii(host: str) -> str:
    host = (host or "").strip().strip(".").lower()
    if host.startswith("*."):
        host = host[2:]
    try:
        return idna.encode(host).decode()
    except Exception:
        return host

def registrable(host: str) -> str:
    t = _extract(host)
    return f"{t.domain}.{t.suffix}" if t.suffix else t.domain

# light noise filter (infra-y labels)
NOISE_LEFT = {
    "cpanel","cpcalendars","cpcontacts","webdisk","webmail",
    "autodiscover","autoconfig","whm","mail","ns1","ns2","imap","pop","smtp"
}
HEXISH = re.compile(r"^[a-f0-9]{16,}$", re.I)
def looks_noisy(fqdn: str) -> bool:
    left = fqdn.split(".", 1)[0]
    return left in NOISE_LEFT or bool(HEXISH.match(left))

@lru_cache(maxsize=2048)
def ld1(a: str, b: str) -> bool:
    """Levenshtein distance <= 1 quick check."""
    if a == b: return True
    la, lb = len(a), len(b)
    if abs(la - lb) > 1: return False
    if la > lb: a, b = b, a; la, lb = lb, la
    i=j=diff=0
    while i < la and j < lb:
        if a[i]==b[j]:
            i+=1; j+=1
        else:
            diff+=1
            if diff>1: return False
            if la==lb: i+=1; j+=1
            else: j+=1
    if i<la or j<lb: diff+=1
    return diff<=1

# Common words to exclude from token matching (too generic for phishing detection)
COMMON_WORDS = {
    "mail", "email", "account", "accounts", "web", "www", "app", 
    "api", "admin", "login", "secure", "bank", "net", "online",
    "service", "services", "portal", "user", "customer", "support"
}

# ------------------------- seeds -------------------------

def load_seeds(path: str):
    seeds_by_reg = {}
    brand_tokens = set()
    if not os.path.exists(path):
        print(f"[ct] WARNING: seeds file not found at {path}; running with no seed filters.")
        return seeds_by_reg, brand_tokens

    with open(path, newline="", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            cse_id = (row.get("cse_id") or "").strip() or None
            seed   = (row.get("seed_registrable") or "").strip().lower()
            seed   = to_ascii(registrable(seed))
            if not seed: continue
            seeds_by_reg[seed] = cse_id
            t = _extract(seed)
            if t.domain: 
                brand = t.domain.lower()
                # Only add non-generic brand tokens
                if brand not in COMMON_WORDS and len(brand) >= 3:
                    brand_tokens.add(brand)

    print(f"[ct] loaded {len(seeds_by_reg)} seeds "
          f"(brand tokens ≈ {', '.join(sorted(list(brand_tokens))[:8])}"
          f"{'...' if len(brand_tokens)>8 else ''})")
    return seeds_by_reg, brand_tokens

SEEDS_BY_REG, BRAND_TOKENS = load_seeds(SEEDS_PATH)

def token_hit(left_label: str):
    """
    Improved token matching for phishing detection.
    
    Rules:
    1. Exact match: leftmost label == brand token (e.g., "sbi" matches "sbi")
    2. LD1 match: leftmost label is 1 edit distance from brand token (typosquatting)
       - Only applied to tokens 5+ chars to avoid false positives on short abbreviations
    3. Standalone match: brand token appears as complete word with separators
       (e.g., "sbi-login" or "my-sbi-bank" matches "sbi")
    4. Prefix match: brand at start with separator/digit (e.g., "sbi123" matches "sbi")
    5. Suffix match: brand at end with separator/digit (e.g., "secure-sbi" matches "sbi")
    
    Excludes: Generic common words, partial substring matches
    """
    ll = (left_label or "").lower().strip()
    if not ll:
        return False, "", ""
    
    for tok in BRAND_TOKENS:
        # Skip tokens that are too generic
        if tok in COMMON_WORDS:
            continue
        
        # Skip if token is too short (< 3 chars) to avoid false positives
        if len(tok) < 3:
            continue
            
        # Rule 1: Exact match (most reliable)
        if ll == tok:
            return True, "token:exact", tok
        
        # Rule 2: LD1 match (typosquatting detection)
        # Only for longer tokens (5+ chars) to avoid false positives on abbreviations
        # e.g., "hdfc" -> "hdfc1", "icici" -> "icicj" are valid typos
        # but "sbi" -> "sb" is too short and causes false positives
        if len(tok) >= 5 and ld1(ll, tok):
            return True, "token:ld1", tok
        
        # Rule 3: Standalone word match with separators
        # Matches: sbi-bank, my-sbi, login-sbi-here, etc.
        # Won't match: subscriber, publish, republic, electronic
        pattern = rf'(^|[^a-z]){re.escape(tok)}([^a-z]|$)'
        if re.search(pattern, ll):
            return True, "token:word", tok
        
        # Rule 4: Brand token at start with separator/digit
        # Matches: sbi123, sbi-login, hdfc2024
        if ll.startswith(tok) and len(ll) > len(tok):
            next_char = ll[len(tok)]
            if next_char in '-_.' or next_char.isdigit():
                return True, "token:prefix", tok
        
        # Rule 5: Brand token at end with separator/digit
        # Matches: 123sbi, my-sbi, secure-hdfc
        if ll.endswith(tok) and len(ll) > len(tok):
            prev_char = ll[len(ll) - len(tok) - 1]
            if prev_char in '-_.' or prev_char.isdigit():
                return True, "token:suffix", tok
    
    return False, "", ""

# ------------------------- kafka -------------------------

async def kafka_connect():
    if not KAFKA_ENABLED:
        print("[ct] Kafka disabled (KAFKA_ENABLED=false)")
        return None
    from aiokafka import AIOKafkaProducer
    delay = 1
    while True:
        try:
            prod = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP, linger_ms=50)
            await prod.start()
            print(f"[ct] Kafka connected at {KAFKA_BOOTSTRAP}")
            return prod
        except Exception as e:
            print(f"[ct] Kafka not ready: {e}; retrying in {delay}s")
            await asyncio.sleep(delay)
            delay = min(delay*2, 10)

async def kafka_send(prod, topic: str, payload: dict):
    if not prod: return
    try:
        await prod.send_and_wait(
            topic,
            ujson.dumps(payload).encode("utf-8"),
            key=(payload.get("registrable") or "").encode("utf-8"),
        )
    except Exception as e:
        print(f"[ct] WARN kafka send failed: {e}")

# ------------------------- heartbeat -------------------------

class Metrics:
    def __init__(self):
        self.started = time.time()
        self.msgs = 0
        self.certs = 0
        self.domains = 0
        self.emitted = 0
        self.unique = 0
        self.last_msg = None
        self.last_emit = None
        self.reasons = {}

    def bump_reason(self, r: str):
        self.reasons[r] = self.reasons.get(r, 0) + 1

async def heartbeat(metrics: Metrics, prod):
    while True:
        await asyncio.sleep(HEARTBEAT_SECS)
        up = int(time.time() - metrics.started)
        since_msg  = int(time.time() - metrics.last_msg)  if metrics.last_msg  else None
        since_emit = int(time.time() - metrics.last_emit) if metrics.last_emit else None
        top = sorted(metrics.reasons.items(), key=lambda kv: kv[1], reverse=True)[:5]
        top_s = ", ".join([f"{k}:{v}" for k,v in top]) if top else "-"
        print(f"[ct][hb] up={up}s msgs={metrics.msgs} certs={metrics.certs} "
              f"domains={metrics.domains} emitted={metrics.emitted} unique={metrics.unique} "
              f"last_msg={since_msg}s last_emit={since_emit}s reasons[{top_s}]")
        # optional heartbeat to Kafka for ops dashboards
        payload = {
            "src": "ct",
            "type": "heartbeat",
            "observed_at": time.time(),
            "stats": {
                "uptime_s": up, "msgs": metrics.msgs, "certs": metrics.certs,
                "domains": metrics.domains, "emitted": metrics.emitted,
                "unique": metrics.unique, "last_msg_s": since_msg, "last_emit_s": since_emit,
                "top_reasons": dict(top)
            }
        }
        if prod:
            try:
                await prod.send_and_wait(KAFKA_TOPIC, ujson.dumps(payload).encode("utf-8"), key=b"_heartbeat_")
            except Exception as e:
                print(f"[ct] WARN heartbeat kafka send failed: {e}")

# ------------------------- certstream loop -------------------------

def build_callback(seen: set, metrics: Metrics, fobj, prod_ref, loop):
    """Build callback that can schedule kafka sends on the event loop."""
    first_message = {"seen": False}
    
    def on_message(message, context=None):
        """Certstream message callback - context may be None."""
        try:
            metrics.msgs += 1
            metrics.last_msg = time.time()
            
            # Handle both string and dict messages
            if isinstance(message, str):
                try:
                    message = ujson.loads(message)
                except Exception as e:
                    print(f"[ct] Failed to parse message string: {e}")
                    return
            
            # Log first few messages to verify callback is working
            if not first_message["seen"]:
                first_message["seen"] = True
                print(f"[ct] ✓ CALLBACK INVOKED! First message received!")
                print(f"[ct]   Type: {type(message)}")
                if isinstance(message, dict):
                    print(f"[ct]   Message keys: {list(message.keys())}")
                    print(f"[ct]   Message type: {message.get('message_type')}")

            if not isinstance(message, dict):
                return
            
            msg_type = message.get("message_type")
            if msg_type != "certificate_update":
                return
            
            if metrics.certs == 0:
                print(f"[ct] ✓ Processing first certificate!")
            
            metrics.certs += 1
            data = message.get("data", {}) or {}
            leaf = data.get("leaf_cert", {}) or {}
            all_domains = leaf.get("all_domains", []) or []
            metrics.domains += len(all_domains)

            for raw in all_domains:
                fqdn = to_ascii(raw)
                if not fqdn:
                    continue
                if looks_noisy(fqdn):
                    continue
                if fqdn in seen:
                    continue

                reg = registrable(fqdn)

                reasons = []
                cse_id = None
                seed_reg = None

                # 1) exact registrable seed match
                if reg in SEEDS_BY_REG:
                    cse_id = SEEDS_BY_REG[reg]
                    seed_reg = reg
                    reasons.append("seed:registrable:eq")

                # 2) brand token hit on left label (IMPROVED MATCHING)
                if not reasons and BRAND_TOKENS:
                    left = fqdn.split(".", 1)[0]
                    hit, why, tok = token_hit(left)
                    if hit:
                        reasons.append(f"seed:{why}:{tok}")
                        # map token → a seed/cse (best-effort)
                        for sreg, cid in SEEDS_BY_REG.items():
                            if _extract(sreg).domain.lower() == tok:
                                cse_id = cid; seed_reg = sreg; break

                # filter depending on mode
                if MATCH_MODE == "seed" and not reasons:
                    continue
                if not reasons:
                    reasons.append("ct:test_all")  # firehose label

                # record & emit
                seen.add(fqdn)
                metrics.unique = len(seen)
                metrics.emitted += 1
                metrics.last_emit = time.time()
                for r in reasons:
                    metrics.bump_reason(r)

                obj = {
                    "src": "ct",
                    "observed_at": time.time(),
                    "canonical_fqdn": fqdn,
                    "registrable": reg,
                    "cse_id": cse_id,
                    "seed_registrable": seed_reg,
                    "reasons": reasons,
                }

                # Log first few emissions
                if metrics.emitted <= 10:
                    print(f"[ct] Emitting #{metrics.emitted}: {fqdn} (reasons: {reasons})")
                
                try:
                    line = ujson.dumps(obj) + "\n"
                    fobj.write(line)
                    fobj.flush()
                except Exception as write_err:
                    print(f"[ct] ERROR writing to file: {write_err}")
                    traceback.print_exc()

                prod = prod_ref.get("prod")
                if prod and loop:
                    # Schedule kafka send on the event loop from this thread
                    asyncio.run_coroutine_threadsafe(
                        kafka_send(prod, KAFKA_TOPIC, obj),
                        loop
                    )

        except Exception as e:
            print(f"[ct] ERROR processing message: {e}")
            traceback.print_exc()

    return on_message

def test_raw_websocket():
    """Test raw websocket connection to diagnose issues."""
    import websocket
    if VERBOSE_LOGGING:
        print("[ct] Testing raw websocket connection...")
    try:
        if VERBOSE_LOGGING:
            websocket.enableTrace(True)
        ws = websocket.create_connection(CT_URL, timeout=15)
        if VERBOSE_LOGGING:
            print("[ct] ✓ Raw websocket connected!")
        
        ws.settimeout(10)
        msg = ws.recv()
        if VERBOSE_LOGGING:
            print(f"[ct] ✓ Received message ({len(msg)} bytes)")
        ws.close()
        return True
    except Exception as e:
        print(f"[ct] ✗ Websocket test FAILED: {e}")
        if VERBOSE_LOGGING:
            traceback.print_exc()
        return False

async def run_certstream_loop(prod, out_prefix: Path):
    """Run certstream in a thread executor so async tasks can run."""
    from certstream.core import listen_for_events

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Test raw websocket first
    print("[ct] Running connectivity test...")
    if not await asyncio.get_event_loop().run_in_executor(None, test_raw_websocket):
        print("[ct] ✗ Cannot connect to certstream - check network/firewall")
        print("[ct] Possible issues:")
        print("[ct]   - Docker network restrictions")
        print("[ct]   - certstream.calidog.io is down")
        print("[ct]   - Firewall blocking websocket connections")
        return

    backoff = RECONNECT_DELAY_S
    seen = set()
    metrics = Metrics()
    loop = asyncio.get_event_loop()
    
    # Start heartbeat task
    hb_task = asyncio.create_task(heartbeat(metrics, prod))
    prod_ref = {"prod": prod}

    attempt = 0
    while True:
        attempt += 1
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        segment = OUTPUT_DIR / f"{out_prefix.stem}_{ts}.jsonl"
        
        print(f"[ct] opening new segment: {segment}")
        fobj = segment.open("a", encoding="utf-8", buffering=1)
        
        try:
            callback = build_callback(seen, metrics, fobj, prod_ref, loop)
            
            print(f"[ct] [attempt #{attempt}] connecting to certstream at {CT_URL}...")
            
            connection_opened = {"opened": False}
            error_seen = {"error": None}
            
            def on_open_wrapper():
                """Certstream calls this with NO arguments."""
                connection_opened["opened"] = True
                print("[ct] ✓ certstream connection OPENED (websocket handshake successful)")
            
            def on_error_wrapper(err):
                """Certstream calls this with just the error."""
                error_seen["error"] = err
                print(f"[ct] ✗ certstream ERROR callback triggered: {err}")
                traceback.print_exc()
            
            # CRITICAL: Run the blocking certstream listener in a thread executor
            # so the asyncio event loop can continue processing heartbeats and kafka sends
            print("[ct] Starting listen_for_events in executor thread...")
            
            await loop.run_in_executor(
                None,
                lambda: listen_for_events(
                    callback,
                    url=CT_URL,
                    skip_heartbeats=False,
                    on_open=on_open_wrapper,
                    on_error=on_error_wrapper,
                )
            )
            
            print(f"[ct] listen_for_events returned (connection_opened={connection_opened['opened']}, error={error_seen['error']})")
            print(f"[ct] will reconnect in {backoff}s...")
            
        except Exception as e:
            print(f"[ct] certstream exception in executor: {e}")
            traceback.print_exc()
            print(f"[ct] will reconnect in {backoff}s")
        
        finally:
            fobj.close()
        
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, MAX_RECONNECT_S)

    hb_task.cancel()  # unreachable but clean

# ------------------------- main -------------------------

async def main():
    print("[ct] ===== CT Watcher Starting =====")
    print(f"[ct] Mode: {MATCH_MODE.upper()} | Seeds: {len(SEEDS_BY_REG)} | Brands: {len(BRAND_TOKENS)}")
    print(f"[ct] Kafka: {'ENABLED' if KAFKA_ENABLED else 'DISABLED'} | Heartbeat: {HEARTBEAT_SECS}s")
    if VERBOSE_LOGGING:
        print(f"[ct] VERBOSE_LOGGING=true (detailed debug output enabled)")
        print(f"[ct] CT_URL={CT_URL}")
        print(f"[ct] SEEDS_PATH={SEEDS_PATH}")
        print(f"[ct] Kafka bootstrap={KAFKA_BOOTSTRAP} topic={KAFKA_TOPIC}")
        print(f"[ct] Excluded {len(COMMON_WORDS)} common words from token matching")

    base_ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_prefix = OUTPUT_DIR / f"ct_candidates_{base_ts}"

    prod = await kafka_connect() if KAFKA_ENABLED else None
    
    try:
        await run_certstream_loop(prod, out_prefix)
    finally:
        if prod:
            try: 
                await prod.stop()
            except Exception: 
                pass
        print("[ct] Shutdown complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[ct] interrupted; exiting")
    except Exception as e:
        print(f"[ct] FATAL: {e}")
        traceback.print_exc()