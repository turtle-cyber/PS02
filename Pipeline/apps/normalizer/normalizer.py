import os, asyncio, ujson, idna, tldextract, time, redis
from pathlib import Path

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP","kafka:9092")
INPUT_TOPIC = os.getenv("INPUT_TOPIC","raw.hosts")
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC","domains.candidates")
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED","true").lower() == "true"
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR","/out"))

ALLOWLIST = Path("/configs/allowlist.txt")
DENYLIST  = Path("/configs/denylist.txt")

RHOST = os.getenv("REDIS_HOST","redis")
RPORT = int(os.getenv("REDIS_PORT","6379"))
DEDUP_TTL = int(os.getenv("DEDUP_TTL_SECS","10368000"))

extract = tldextract.TLDExtract(suffix_list_urls=None)

def to_ascii(host: str) -> str:
    host = host.strip().strip(".").lower()
    try: return idna.encode(host).decode()
    except Exception: return host

def registrable(host: str) -> str:
    t = extract(host)
    return f"{t.domain}.{t.suffix}" if t.suffix else t.domain

def load_list(path: Path):
    if not path.exists(): return set()
    return set([l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")])

async def get_kafka(total_wait=120):
    if not KAFKA_ENABLED:
        return (None, None)
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
    delay, waited = 1.0, 0.0
    while waited < total_wait:
        try:
            consumer = AIOKafkaConsumer(
                INPUT_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id="normalizer",
            )
            producer = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP, linger_ms=50)
            await consumer.start()
            await producer.start()
            print(f"[normalizer] Kafka connected at {KAFKA_BOOTSTRAP}")
            return (consumer, producer)
        except Exception as e:
            print(f"[normalizer] Kafka not ready ({e}); retrying in {delay:.1f}s")
            await asyncio.sleep(delay)
            waited += delay
            delay = min(delay * 2, 10.0)
    print("[normalizer] Kafka unavailable after retries. Falling back to file output.")
    return (None, None)

async def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    allow = load_list(ALLOWLIST); deny = load_list(DENYLIST)
    r = redis.Redis(host=RHOST, port=RPORT, decode_responses=True)

    consumer, producer = await get_kafka()
    out_f = (OUTPUT_DIR / "domains.candidates.jsonl").open("a", encoding="utf-8") if not producer else None

    async def emit(obj):
        if producer:
            await producer.send_and_wait(OUTPUT_TOPIC, ujson.dumps(obj).encode("utf-8"))
        else:
            out_f.write(ujson.dumps(obj) + "\n")

    if consumer:
        async for msg in consumer:
            try:
                data = ujson.loads(msg.value)
            except Exception:
                continue
            fqdn = to_ascii(data.get("canonical_fqdn","") or data.get("fqdn",""))
            if not fqdn: continue
            # policy gates
            if any(fqdn.endswith(x) for x in deny): continue
            if allow and not any(fqdn.endswith(x) for x in allow): pass  # optional: gate to specific suffixes

            key = f"first_seen:{fqdn}"
            if r.setnx(key, str(time.time())):
                r.expire(key, DEDUP_TTL)
            else:
                continue  # already seen

            obj = {
                "src": data.get("src",""),
                "observed_at": data.get("observed_at", time.time()),
                "canonical_fqdn": fqdn,
                "registrable": registrable(fqdn),
                "cse_id": data.get("cse_id"),
                "seed_fqdn": data.get("seed_fqdn"),  # NEW: Preserve seed_fqdn
                "seed_registrable": data.get("seed_registrable"),
                "reasons": data.get("reasons", [])
            }
            await emit(obj)
    else:
        print("[normalizer] No Kafka; expecting pre-batched JSONL at /out/raw.hosts.jsonl (not provided in this MVP).")
        # You can add a file-ingest path here if you prefer.

    if consumer: await consumer.stop()
    if producer: await producer.stop()
    if out_f: out_f.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
