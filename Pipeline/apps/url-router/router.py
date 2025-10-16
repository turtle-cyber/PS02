import os, sys, json, time, signal, logging
from typing import Optional, Tuple
from urllib.parse import urlparse

import ujson
from kafka import KafkaConsumer, KafkaProducer, TopicPartition

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP") or os.environ.get("KAFKA_BROKERS", "kafka:9092")
IN_TOPIC  = os.environ.get("IN_TOPIC", "http.probed")
OUT_TOPIC = os.environ.get("OUT_TOPIC", "phish.urls.crawl")
INACTIVE_TOPIC = os.environ.get("INACTIVE_TOPIC", "phish.urls.inactive")  # NEW: Inactive domains
SEED_TOPIC = os.environ.get("SEED_TOPIC", "phish.urls.seeds")  # NEW: Seed domains (bypass feature-crawler)
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

    NEW: Returns special marker for failed probes (ok=False) instead of skipping.
    """
    # Mark failed HTTP probes for special handling (monitoring queue)
    if rec.get("ok") is False:
        return "INACTIVE_DOMAIN", rec  # Special marker
    
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
    
    # CRITICAL: Extract CSE ID from all possible locations
    cse_id = first_non_empty(
        rec.get("cse_id"),
        rec.get("id"),
        rec.get("cse"),
        rec.get("canonical_id"),
    )
    
    # Check nested structures for CSE ID
    for k in ("result", "http", "http_result", "artifact", "artifacts", "data", "final"):
        if isinstance(rec.get(k), dict):
            cse_id = first_non_empty(
                cse_id,
                rec[k].get("cse_id"),
                rec[k].get("id"),
                rec[k].get("cse"),
                rec[k].get("canonical_id"),
            )
    
    if cse_id:
        meta["cse_id"] = cse_id
    
    # pass through a few useful fields if present
    for key in ("status", "status_code", "title", "registrable", "brand", "seed_fqdn", "seed_registrable", "canonical_fqdn", "fqdn"):
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
    
    # CRITICAL: Always include CSE ID if present
    if "cse_id" in meta:
        out["cse_id"] = meta["cse_id"]
    
    # surface helpful hints to feature-crawler
    if "registrable" in meta:
        out["registrable"] = meta["registrable"]
    if "title" in meta:
        out["title"] = meta["title"]
    if "status" in meta:
        out["status"] = meta["status"]
    if "status_code" in meta:
        out["status_code"] = meta["status_code"]
    if "brand" in meta:
        out["brand"] = meta["brand"]
    if "canonical_fqdn" in meta:
        out["canonical_fqdn"] = meta["canonical_fqdn"]
    if "seed_registrable" in meta:
        out["seed_registrable"] = meta["seed_registrable"]
    
    return out

def is_seed_domain(meta: dict) -> bool:
    """
    Determine if this record is a seed domain itself (not a variant).
    NEW: Seed criteria: canonical_fqdn == seed_fqdn (exact FQDN match)
    """
    canonical_fqdn = meta.get("canonical_fqdn") or meta.get("fqdn", "")
    seed_fqdn = meta.get("seed_fqdn", "")

    # If no seed_fqdn, it's not part of lookalike tracking
    if not seed_fqdn:
        return False

    # If canonical FQDN matches seed FQDN, this IS the seed
    if canonical_fqdn and seed_fqdn and canonical_fqdn == seed_fqdn:
        return True

    return False

def build_seed_output(meta: dict) -> dict:
    """
    Build output record for seed domains (includes full HTTP probe + DNS data).
    Seeds bypass feature-crawler and go directly to chroma-ingestor.
    """
    out = {
        "schema_version": "v1",
        "registrable": meta.get("registrable"),
        "canonical_fqdn": meta.get("canonical_fqdn") or meta.get("fqdn"),
        "seed_fqdn": meta.get("seed_fqdn"),  # NEW: Original submitted FQDN
        "seed_registrable": meta.get("seed_registrable"),
        "ts": int(time.time() * 1000),
        "is_seed": True,  # Marker for chroma-ingestor
    }

    # Include CSE ID
    if "cse_id" in meta:
        out["cse_id"] = meta["cse_id"]

    # Include URL if available
    if "url" in meta:
        out["url"] = meta["url"]

    # Include all DNS/WHOIS/HTTP data from meta
    for key in ["status", "status_code", "title", "brand", "fqdn"]:
        if key in meta and meta.get(key) is not None:
            out[key] = meta[key]

    return out

# In the main loop, add debug logging:
def main():
    log.info(f"starting url-router | bootstrap={BOOTSTRAP} in={IN_TOPIC} out={OUT_TOPIC} inactive={INACTIVE_TOPIC} seed={SEED_TOPIC}")
    consumer = make_consumer()
    producer = make_producer()

    forwarded = 0
    dropped = 0
    inactive_queued = 0  # NEW: Track inactive domains
    seeds_routed = 0  # NEW: Track seed domains

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

                # NEW: Handle inactive domains (ok: false)
                if url == "INACTIVE_DOMAIN":
                    try:
                        registrable = meta.get("registrable") or meta.get("canonical_fqdn") or meta.get("fqdn")
                        if registrable:
                            inactive_rec = {
                                "schema_version": "v1",
                                "registrable": registrable,
                                "canonical_fqdn": meta.get("canonical_fqdn") or registrable,
                                "cse_id": meta.get("cse_id"),
                                "seed_registrable": meta.get("seed_registrable"),
                                "status": "inactive",
                                "failure_type": meta.get("error", "connection_failed"),
                                "ts": int(time.time() * 1000),
                                "reasons": ["http_probe_failed"],
                            }
                            producer.send(INACTIVE_TOPIC, value=inactive_rec)
                            inactive_queued += 1
                            if inactive_queued % 10 == 0 or LOG_LEVEL == "DEBUG":
                                log.info(f"INACTIVE#{inactive_queued} -> {registrable} (reason: {inactive_rec['failure_type']})")
                    except Exception as e:
                        log.error(f"ERROR inactive domain offset={msg.offset}: {e}")
                    continue

                if not url:
                    dropped += 1
                    log.warning(f"DROP no_url offset={msg.offset} key={msg.key} rec_keys={list(rec.keys())}")
                    continue

                norm = normalize_url(url)
                if not norm:
                    dropped += 1
                    log.debug(f"DROP bad_url offset={msg.offset} url={url!r}")
                    continue

                # NEW: Check if this is a seed domain
                if is_seed_domain(meta):
                    # Route seed to SEED_TOPIC (bypasses feature-crawler)
                    seed_out = build_seed_output(meta)
                    try:
                        producer.send(SEED_TOPIC, value=seed_out)
                        seeds_routed += 1
                        if seeds_routed % 10 == 0 or LOG_LEVEL == "DEBUG":
                            cse_info = f" [cse={seed_out.get('cse_id')}]" if seed_out.get('cse_id') else ""
                            log.info(f"SEED#{seeds_routed} -> {seed_out.get('registrable')}{cse_info} (bypassing feature-crawler)")
                    except Exception as e:
                        dropped += 1
                        log.error(f"ERROR produce seed offset={msg.offset}: {e}")
                    continue

                # This is a variant - route to feature-crawler
                out = build_output(norm, meta)

                # DEBUG: Log CSE ID and seed_registrable presence (CRITICAL for feature-crawler tracking)
                if "cse_id" in meta:
                    log.debug(f"CSE_ID found: {meta['cse_id']} for {norm}")
                else:
                    log.warning(f"CSE_ID missing for {norm} - check upstream data source")

                if "seed_registrable" not in meta:
                    log.warning(f"seed_registrable missing for {norm} - feature-crawler tracking will fail!")

                try:
                    producer.send(OUT_TOPIC, value=out)
                    forwarded += 1
                    if forwarded % 10 == 0 or LOG_LEVEL == "DEBUG":
                        cse_info = f" [cse={out.get('cse_id')}]" if out.get('cse_id') else ""
                        seed_info = f" [seed={out.get('seed_registrable')}]" if out.get('seed_registrable') else ""
                        log.info(f"FWD#{forwarded} -> {norm}{cse_info}{seed_info}")
                except Exception as e:
                    dropped += 1
                    log.error(f"ERROR produce offset={msg.offset}: {e}")

        # flush periodically
        producer.flush(timeout=2)

if __name__ == "__main__":
    main()