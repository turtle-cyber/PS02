import os, csv, time, ujson, asyncio, subprocess, shlex, socket, traceback
from datetime import datetime
from pathlib import Path
import tldextract, idna

# Env
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "true").lower() == "true"
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_INPUT_TOPIC = os.getenv("KAFKA_INPUT_TOPIC", "raw.hosts")
KAFKA_OUTPUT_TOPIC = os.getenv("KAFKA_OUTPUT_TOPIC", "raw.hosts")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/out"))
THREADS = int(os.getenv("THREADS", "16"))
NAMESERVERS = os.getenv("NAMESERVERS", "unbound")
KAFKA_RETRY_ATTEMPTS = int(os.getenv("KAFKA_RETRY_ATTEMPTS", "10"))
KAFKA_RETRY_DELAY = int(os.getenv("KAFKA_RETRY_DELAY", "5"))
PROCESS_CSV_ON_STARTUP = os.getenv("PROCESS_CSV_ON_STARTUP", "true").lower() == "true"

# Config paths
DICT_DIR = Path("/configs/dictionaries")
CSE_SEEDS = Path("/configs/cse_seeds.csv")
COMMON_TLDS = (DICT_DIR / "common_tlds.dict").as_posix()
INDIA_TLDS  = (DICT_DIR / "india_tlds.dict").as_posix()
ENGLISH_DICT = (DICT_DIR / "english.dict").as_posix()
HIGH_RISK_DICT = (DICT_DIR / "high_risk.dict").as_posix()

# Fuzzer sets - simplified for live processing
LIVE_FUZZERS = "addition,bitsquatting,homoglyph,hyphenation,insertion,omission,repetition,replacement,transposition,vowel-swap,tld-swap"
PASS_A_FUZZERS = "addition,bitsquatting,homoglyph,hyphenation,insertion,omission,repetition,replacement,subdomain,transposition,vowel-swap,dictionary,tld-swap"
PASS_B_FUZZERS = "homoglyph,transposition,insertion,omission,replacement,addition,dictionary,tld-swap"
PASS_C_FUZZERS = "dictionary,tld-swap,addition,replacement"

extract = tldextract.TLDExtract(suffix_list_urls=None)

def _nameserver_ip():
    host = NAMESERVERS.rsplit(":", 1)[0] if ":" in NAMESERVERS else NAMESERVERS
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host

def registrable(domain):
    """Extract registrable domain (eTLD+1)"""
    parts = extract(domain)
    if parts.suffix:
        return f"{parts.domain}.{parts.suffix}".lower()
    return parts.domain.lower()

def to_ascii(s):
    """Convert IDN to ASCII if needed"""
    if not s:
        return ""
    try:
        return idna.encode(s).decode("ascii").lower()
    except Exception:
        return s.lower()

def run_dnstwist(seed, fuzzers, tld_dict, registered_only=True):
    """Run dnstwist with given parameters"""
    cmd = [
        "dnstwist",
        "--threads", str(THREADS),
        "--nameservers", _nameserver_ip(),
        "--format", "json",
        "--fuzzers", fuzzers,
        "--tld", tld_dict,
        seed
    ]

    # Only add --registered flag if requested (for CSV seeds)
    # For live processing, we skip --registered to get all variants
    if registered_only:
        cmd.insert(5, "--registered")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )

        if result.returncode != 0:
            print(f"[dnstwist] Command failed with return code {result.returncode}")
            if result.stderr:
                print(f"[dnstwist] stderr: {result.stderr[:500]}")
            return []

        data = ujson.loads(result.stdout)

        # For live processing (registered_only=False), return ALL variants
        # For CSV seeds (registered_only=True), only return registered ones
        if registered_only:
            filtered = [r for r in data if r.get("dns_a")]
            print(f"[dnstwist] Generated {len(data)} variants, {len(filtered)} are registered")
            return filtered
        else:
            print(f"[dnstwist] Generated {len(data)} total variants (registered + unregistered)")
            return data

    except Exception as e:
        print(f"[dnstwist] Error running dnstwist for {seed}: {e}")
        return []

async def kafka_producer():
    """Create Kafka producer with retry"""
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
            print("[kafka] Producer connected successfully!")
            return prod
        except KafkaConnectionError as e:
            if attempt < KAFKA_RETRY_ATTEMPTS:
                print(f"[kafka] Connection failed: {e}. Retrying in {KAFKA_RETRY_DELAY}s...")
                await asyncio.sleep(KAFKA_RETRY_DELAY)
            else:
                print(f"[kafka] Failed to connect after {KAFKA_RETRY_ATTEMPTS} attempts")
                raise

async def kafka_consumer():
    """Create Kafka consumer with retry"""
    from aiokafka import AIOKafkaConsumer
    from aiokafka.errors import KafkaConnectionError

    for attempt in range(1, KAFKA_RETRY_ATTEMPTS + 1):
        try:
            print(f"[kafka] Consumer connection attempt {attempt}/{KAFKA_RETRY_ATTEMPTS}...")
            cons = AIOKafkaConsumer(
                KAFKA_INPUT_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id="dnstwist-runner",
                auto_offset_reset="latest",
                enable_auto_commit=True,
                request_timeout_ms=30000,
                session_timeout_ms=60000,        # Increased from 45s
                heartbeat_interval_ms=20000,     # Increased from 15s  
                max_poll_interval_ms=600000,     # 10 minutes for slow dnstwist runs
                max_poll_records=1,              # Process one domain at a time
            )
            await cons.start()
            print(f"[kafka] Consumer connected to topic: {KAFKA_INPUT_TOPIC}")
            return cons
        except KafkaConnectionError as e:
            if attempt < KAFKA_RETRY_ATTEMPTS:
                print(f"[kafka] Consumer connection failed: {e}. Retrying in {KAFKA_RETRY_DELAY}s...")
                await asyncio.sleep(KAFKA_RETRY_DELAY)
            else:
                print(f"[kafka] Consumer failed to connect after {KAFKA_RETRY_ATTEMPTS} attempts")
                raise

async def emit(record, producer, file_handle=None):
    """Emit record to Kafka and/or file"""
    if producer and KAFKA_ENABLED:
        try:
            fqdn = record.get("canonical_fqdn", "")
            await producer.send(
                KAFKA_OUTPUT_TOPIC,
                key=fqdn.encode("utf-8"),
                value=ujson.dumps(record).encode("utf-8")
            )
        except Exception as e:
            print(f"[kafka] Error sending {fqdn}: {e}")

    if file_handle:
        file_handle.write(ujson.dumps(record) + "\n")
        file_handle.flush()

async def process_domain(domain, cse_id, producer, file_handle, seen_set):
    """
    Process a single domain through DNSTwist
    Returns number of new variants found
    """
    # Extract registrable domain
    seed_reg = registrable(domain)

    # Skip if we've already processed this registrable domain recently
    if seed_reg in seen_set:
        print(f"[dnstwist] Skipping {seed_reg} (already processed)")
        return 0

    seen_set.add(seed_reg)

    print(f"\n[dnstwist] ===== Processing: {seed_reg} (CSE: {cse_id or 'UNKNOWN'}) =====")

    # Run DNSTwist with --registered flag to only get variants that resolve
    print(f"[dnstwist] Generating variants (checking DNS for registered domains)...")
    results = run_dnstwist(seed_reg, LIVE_FUZZERS, COMMON_TLDS, registered_only=True)

    if not results:
        print(f"[dnstwist] ⚠️ No registered variants found for {seed_reg}")
        print(f"[dnstwist] This means none of the generated variants are actually registered/resolving")
        return 0

    print(f"[dnstwist] ✓ Found {len(results)} registered variant domains")

    # Emit all variants
    count = 0
    for r in results:
        fqdn = to_ascii(r.get("domain", ""))
        if not fqdn:
            continue

        record = {
            "src": "dnstwist",
            "observed_at": time.time(),
            "cse_id": cse_id or "UNKNOWN",
            "seed_registrable": seed_reg,
            "canonical_fqdn": fqdn,
            "registrable": registrable(fqdn),
            "reasons": ["dnstwist:live"],
            "fuzzer": r.get("fuzzer"),
            "raw": r
        }

        await emit(record, producer, file_handle)
        count += 1

    print(f"[dnstwist] ✓ Completed {seed_reg}: {count} variants emitted")
    return count

async def process_csv_seeds(producer, file_handle):
    """Process seeds from CSV file (one-time on startup)"""
    if not PROCESS_CSV_ON_STARTUP:
        print("[runner] Skipping CSV processing (PROCESS_CSV_ON_STARTUP=false)")
        return set()

    if not CSE_SEEDS.exists():
        print(f"[runner] CSV file not found: {CSE_SEEDS}")
        return set()

    seen = set()

    with CSE_SEEDS.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        seeds = list(reader)

    print(f"\n[runner] ==================== Processing {len(seeds)} CSV seeds ====================")

    for idx, row in enumerate(seeds, 1):
        cse_id = row["cse_id"].strip()
        seed_reg = row["seed_registrable"].strip()
        if not seed_reg:
            continue

        print(f"\n[runner] [{idx}/{len(seeds)}] ===== Processing: {seed_reg} (CSE: {cse_id}) =====")

        # PASS A (wide, common TLDs)
        print(f"[runner] Running PASS_A (common TLDs)...")
        results_a = run_dnstwist(seed_reg, PASS_A_FUZZERS, COMMON_TLDS)
        print(f"[runner] ✓ PASS_A: {len(results_a)} registered domains found")

        # PASS B (India TLDs)
        print(f"[runner] Running PASS_B (India TLDs)...")
        results_b = run_dnstwist(seed_reg, PASS_B_FUZZERS, INDIA_TLDS)
        print(f"[runner] ✓ PASS_B: {len(results_b)} registered domains found")

        # PASS C (high-risk)
        print(f"[runner] Running PASS_C (high-risk patterns)...")
        results_c = run_dnstwist(seed_reg, PASS_C_FUZZERS, HIGH_RISK_DICT)
        print(f"[runner] ✓ PASS_C: {len(results_c)} registered domains found")

        # Emit all results
        count = 0
        for pass_name, results in [("PASS_A", results_a), ("PASS_B", results_b), ("PASS_C", results_c)]:
            for r in results:
                fqdn = to_ascii(r.get("domain", ""))
                if not fqdn:
                    continue

                record = {
                    "src": "dnstwist",
                    "observed_at": time.time(),
                    "cse_id": cse_id,
                    "seed_registrable": seed_reg,
                    "canonical_fqdn": fqdn,
                    "registrable": registrable(fqdn),
                    "reasons": [f"dnstwist:{pass_name}"],
                    "fuzzer": r.get("fuzzer"),
                    "raw": r
                }

                await emit(record, producer, file_handle)
                count += 1

        print(f"[runner] ✓ Completed {seed_reg}: {count} variants emitted")
        seen.add(seed_reg)

    print(f"\n[runner] ==================== CSV PROCESSING COMPLETE ====================")
    print(f"[runner] Total seeds processed: {len(seen)}")

    return seen

async def main():
    print("[runner] ==================== STARTING DNSTWIST CONTINUOUS RUNNER ====================")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    producer = None
    consumer = None

    # Create output file
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_path = OUTPUT_DIR / f"dnstwist_variants_{ts}.jsonl"
    fobj = out_path.open("a", encoding="utf-8")
    print(f"[runner] Output file: {out_path}")

    # Track processed domains to avoid duplicates
    seen_registrables = set()
    processed_count = 0
    variant_count = 0

    try:
        # Connect to Kafka
        if KAFKA_ENABLED:
            producer = await kafka_producer()
            await asyncio.sleep(2)  # Wait for topic initialization
            consumer = await kafka_consumer()

        # Step 1: Process CSV seeds on startup
        csv_seen = await process_csv_seeds(producer, fobj)
        seen_registrables.update(csv_seen)

        # Step 2: Enter continuous consumption mode
        print(f"\n[runner] ==================== ENTERING CONTINUOUS MODE ====================")
        print(f"[runner] Listening to topic: {KAFKA_INPUT_TOPIC}")
        print(f"[runner] Emitting variants to: {KAFKA_OUTPUT_TOPIC}")
        print(f"[runner] Ready to process user-submitted domains...")

        if consumer:
            async for msg in consumer:
                try:
                    payload = ujson.loads(msg.value.decode("utf-8"))
                except Exception as e:
                    print(f"[kafka] Failed to parse message: {e}")
                    continue

                # Extract domain from message
                domain = payload.get("fqdn") or payload.get("canonical_fqdn") or payload.get("domain")
                if not domain:
                    continue

                # Get CSE ID if available
                cse_id = payload.get("cse_id")

                # Check if this is a DNSTwist variant (avoid infinite loop)
                if payload.get("src") == "dnstwist":
                    continue  # Skip our own variants

                print(f"\n[runner] 📥 Received domain: {domain} (CSE: {cse_id or 'N/A'})")

                # Process domain through DNSTwist
                try:
                    variants_found = await process_domain(domain, cse_id, producer, fobj, seen_registrables)
                    processed_count += 1
                    variant_count += variants_found

                    # Log stats periodically
                    if processed_count % 10 == 0:
                        print(f"\n[stats] Processed {processed_count} domains, generated {variant_count} variants")

                except Exception as e:
                    print(f"[dnstwist] Error processing {domain}: {e}")
                    traceback.print_exc()

        else:
            # No Kafka - just keep running
            print("[runner] No Kafka consumer - entering idle mode")
            while True:
                await asyncio.sleep(60)
                print(f"[runner] Idle... (processed {processed_count} domains, {variant_count} variants)")

    except KeyboardInterrupt:
        print("\n[runner] Received shutdown signal")

    except Exception as e:
        print(f"[runner] Fatal error: {e}")
        traceback.print_exc()

    finally:
        print("\n[runner] ==================== SHUTTING DOWN ====================")
        print(f"[stats] Total domains processed: {processed_count}")
        print(f"[stats] Total variants generated: {variant_count}")
        print(f"[stats] Output file: {out_path} ({out_path.stat().st_size / 1024:.2f} KB)")

        fobj.close()

        if producer:
            await producer.stop()
            print("[kafka] Producer stopped")

        if consumer:
            await consumer.stop()
            print("[kafka] Consumer stopped")

        print("[runner] ==================== SHUTDOWN COMPLETE ====================")

if __name__ == "__main__":
    asyncio.run(main())
