import os, sys, json, time, signal, logging
from typing import Optional, Tuple
from urllib.parse import urlparse

import ujson
from kafka import KafkaConsumer, KafkaProducer, TopicPartition

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP") or os.environ.get("KAFKA_BROKERS", "kafka:9092")
IN_TOPIC  = os.environ.get("IN_TOPIC", "http.probed")
OUT_TOPIC = os.environ.get("OUT_TOPIC", "phish.urls.crawl")
GROUP_ID  = os.environ.get("GROUP_ID", "url-router")
AUTO_RESET = os.environ.get("AUTO_OFFSET_RESET", "latest")
FORCE_EARLIEST_ON_START = os.environ.get("FORCE_EARLIEST_ON_START", "0") == "1"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger("router")

def graceful_exit(signum, frame):
    log.info("exiting url-router")
    sys.exit(0)

for s in (signal.SIGINT, signal.SIGTERM):
    signal.signal(s, graceful_exit)

def make_consumer() -> KafkaConsumer:
    c = KafkaConsumer(
        IN_TOPIC,
        bootstrap_servers=BOOTSTRAP,
        group_id=GROUP_ID,
        enable_auto_commit=True,
        auto_offset_reset=AUTO_RESET,
        value_deserializer=lambda v: v,  # raw bytes; we ujson.loads later
        consumer_timeout_ms=1000,
        max_poll_records=200,
    )
    if FORCE_EARLIEST_ON_START:
        # Seek to earliest once on start (no-op after first commit)
        c.poll(timeout_ms=0)
        assignment = c.assignment()
        if assignment:
            log.info("FORCE_EARLIEST_ON_START=1 -> seeking to beginning on first assignment")
            c.seek_to_beginning(*assignment)
    return c

def make_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        acks="all",
        linger_ms=10,
        value_serializer=lambda v: ujson.dumps(v).encode("utf-8"),
    )

# ---------- schema helpers ----------

def first_non_empty(*vals) -> Optional[str]:
    for v in vals:
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None

def extract_url_and_meta(rec: dict) -> Tuple[Optional[str], dict]:
    """
    Try many shapes we've seen:
      - top-level: final_url / url
      - nested: rec["result"]["final_url"], rec["http"]["final_url"], etc.
      - http-fetcher format: rec["final"]["url"]
    Also forward any helpful context (status, title, registrable, cse_id).
    
    Skip failed probes (ok=False) early.
    """
    # Skip failed HTTP probes from http-fetcher
    if rec.get("ok") is False:
        return None, {}
    
    # common keys
    url = first_non_empty(
        rec.get("final_url"),
        rec.get("url"),
    )

    # Check for http-fetcher's format: final.url
    if isinstance(rec.get("final"), dict):
        url = first_non_empty(url, rec["final"].get("url"))

    # typical nested containers
    for k in ("result", "http", "http_result", "artifact", "artifacts", "data"):
        if isinstance(rec.get(k), dict):
            r2 = rec[k]
            url = first_non_empty(
                url,
                r2.get("final_url"),
                r2.get("url"),
                r2.get("location"),  # sometimes redirects land here
            )

    meta = {}
    # pass through a few useful fields if present
    for key in ("status", "status_code", "title", "registrable", "cse_id", "brand", "seed_registrable"):
        if key in rec and rec.get(key) is not None:
            meta[key] = rec[key]
        # also check nested (including final object from http-fetcher)
        for k in ("result", "http", "http_result", "artifact", "artifacts", "data", "final"):
            if isinstance(rec.get(k), dict) and key in rec[k] and rec[k].get(key) is not None:
                meta.setdefault(key, rec[k][key])

    return url, meta

def normalize_url(u: str) -> Optional[str]:
    try:
        # ensure scheme
        if not u.lower().startswith(("http://", "https://")):
            u = "http://" + u
        p = urlparse(u)
        if not p.netloc:
            return None
        # strip auth fragments; keep query (feature-crawler handles)
        norm = f"{p.scheme}://{p.netloc}{p.path or '/'}"
        if p.query:
            norm += f"?{p.query}"
        if p.fragment:
            norm += f"#{p.fragment}"
        return norm
    except Exception:
        return None

def build_output(url: str, meta: dict) -> dict:
    out = {
        "schema_version": "v1",
        "url": url,
        "ts": int(time.time() * 1000),
    }
    # surface helpful hints to feature-crawler
    if "registrable" in meta:
        out["registrable"] = meta["registrable"]
    if "cse_id" in meta:
        out["cse_id"] = meta["cse_id"]
    if "title" in meta:
        out["title"] = meta["title"]
    if "status" in meta:
        out["status"] = meta["status"]
    if "status_code" in meta:
        out["status_code"] = meta["status_code"]
    return out

def main():
    log.info(f"starting url-router | bootstrap={BOOTSTRAP} in={IN_TOPIC} out={OUT_TOPIC}")
    consumer = make_consumer()
    producer = make_producer()

    forwarded = 0
    dropped = 0

    log.info(f"url-router ready, waiting for messages...")

    while True:
        batch = consumer.poll(timeout_ms=1000, max_records=500)
        if not batch:
            continue
        for tp, msgs in batch.items():
            for msg in msgs:
                try:
                    rec = ujson.loads(msg.value)
                except Exception as e:
                    dropped += 1
                    log.debug(f"DROP decode_error offset={msg.offset}: {e}")
                    continue

                url, meta = extract_url_and_meta(rec)
                if not url:
                    dropped += 1
                    log.warning(f"DROP no_url offset={msg.offset} key={msg.key} rec_keys={list(rec.keys())}")
                    continue

                norm = normalize_url(url)
                if not norm:
                    dropped += 1
                    log.debug(f"DROP bad_url offset={msg.offset} url={url!r}")
                    continue

                out = build_output(norm, meta)
                try:
                    producer.send(OUT_TOPIC, value=out)
                    forwarded += 1
                    if forwarded % 10 == 0 or LOG_LEVEL == "DEBUG":
                        log.info(f"FWD#{forwarded} -> {norm}")
                except Exception as e:
                    dropped += 1
                    log.error(f"ERROR produce offset={msg.offset}: {e}")

        # flush periodically
        producer.flush(timeout=2)

if __name__ == "__main__":
    main()