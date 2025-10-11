#!/usr/bin/env python3
# apps/monitor-scheduler/scheduler.py
"""
Monitor scheduler for suspicious/parked domains.
Consumes verdicts with monitoring metadata, tracks them in Redis,
and re-queues expired domains for re-crawl.
"""
import os, asyncio, ujson as json, time, redis
from datetime import datetime
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

# Config
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
VERDICTS_TOPIC = os.getenv("VERDICTS_TOPIC", "phish.rules.verdicts")
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC", "raw.hosts")
GROUP_ID = os.getenv("GROUP_ID", "monitor-scheduler")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
CHECK_INTERVAL = int(os.getenv("MONITOR_CHECK_INTERVAL", "86400"))  # 24h
MAX_RECHECKS = int(os.getenv("MAX_RECHECKS", "3"))

# Redis keys
MONITOR_QUEUE = "monitoring:queue"  # Sorted set: member=domain, score=monitor_until
MONITOR_META_PREFIX = "monitoring:meta:"  # Hash: domain metadata

def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

async def process_verdict(msg, r_client):
    """Store monitoring metadata for domains requiring follow-up"""
    try:
        payload = json.loads(msg.value) if msg.value else {}
    except Exception:
        return

    monitor_until = payload.get("monitor_until")
    if not monitor_until:
        return  # Not a monitoring verdict

    registrable = payload.get("registrable") or payload.get("canonical_fqdn", "")
    if not registrable:
        return

    monitor_reason = payload.get("monitor_reason") or "unknown"
    verdict = payload.get("verdict") or "unknown"
    url = payload.get("url") or ""
    first_seen = payload.get("first_seen") or datetime.utcnow().isoformat()

    # Check if already monitoring
    meta_key = f"{MONITOR_META_PREFIX}{registrable}"
    existing = r_client.hgetall(meta_key)

    if existing:
        # Already monitoring, update metadata
        recheck_count = int(existing.get("recheck_count", "0"))
        if recheck_count >= MAX_RECHECKS:
            print(f"[monitor] {registrable} reached max rechecks ({MAX_RECHECKS}), skipping")
            return
        r_client.hset(meta_key, "recheck_count", recheck_count)
    else:
        # New monitoring entry - ensure all values are non-None strings
        r_client.hset(meta_key, mapping={
            "verdict": str(verdict),
            "monitor_reason": str(monitor_reason),
            "first_seen": str(first_seen),
            "recheck_count": "0",
            "url": str(url),
        })
        print(f"[monitor] Added {registrable} to monitoring queue (reason: {monitor_reason}, until: {monitor_until})")

    # Add/update in sorted set
    r_client.zadd(MONITOR_QUEUE, {registrable: monitor_until})

async def check_expired(producer, r_client):
    """Scan for expired monitoring periods and re-queue domains"""
    now = int(time.time())
    expired = r_client.zrangebyscore(MONITOR_QUEUE, 0, now)

    if not expired:
        return

    print(f"[monitor] Found {len(expired)} expired domains to re-check")

    for domain in expired:
        meta_key = f"{MONITOR_META_PREFIX}{domain}"
        meta = r_client.hgetall(meta_key)

        if not meta:
            # Metadata missing, remove from queue
            r_client.zrem(MONITOR_QUEUE, domain)
            continue

        recheck_count = int(meta.get("recheck_count", "0"))

        if recheck_count >= MAX_RECHECKS:
            print(f"[monitor] {domain} reached max rechecks, removing from queue")
            r_client.zrem(MONITOR_QUEUE, domain)
            r_client.delete(meta_key)
            continue

        # Re-queue for crawl
        requeue_msg = {
            "src": "monitor-scheduler",
            "canonical_fqdn": domain,
            "registrable": domain,
            "observed_at": time.time(),
            "reasons": [f"Re-check #{recheck_count + 1} for {meta.get('monitor_reason', 'unknown')}"],
            "recheck": True,
            "recheck_count": recheck_count + 1,
        }

        try:
            await producer.send_and_wait(OUTPUT_TOPIC, json.dumps(requeue_msg).encode("utf-8"))
            print(f"[monitor] Re-queued {domain} (recheck #{recheck_count + 1})")

            # Update recheck count and remove from monitoring queue
            r_client.hincrby(meta_key, "recheck_count", 1)
            r_client.zrem(MONITOR_QUEUE, domain)
        except Exception as e:
            print(f"[monitor] Failed to re-queue {domain}: {e}")

async def main():
    print("[monitor] Starting monitor scheduler")
    print(f"[monitor] Redis: {REDIS_HOST}:{REDIS_PORT}")
    print(f"[monitor] Check interval: {CHECK_INTERVAL}s ({CHECK_INTERVAL/3600:.1f}h)")
    print(f"[monitor] Max rechecks: {MAX_RECHECKS}")

    r_client = get_redis()

    # Kafka consumer/producer
    consumer = AIOKafkaConsumer(
        VERDICTS_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda v: v if v else None,
    )

    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: v if isinstance(v, bytes) else v.encode("utf-8"),
    )

    await consumer.start()
    await producer.start()

    # Background task for periodic checking
    last_check = 0

    try:
        async for msg in consumer:
            await process_verdict(msg, r_client)

            # Periodic check for expired
            now = time.time()
            if now - last_check >= CHECK_INTERVAL:
                await check_expired(producer, r_client)
                last_check = now

                # Stats
                queue_size = r_client.zcard(MONITOR_QUEUE)
                print(f"[monitor] Queue size: {queue_size} domains")

    finally:
        await consumer.stop()
        await producer.stop()
        print("[monitor] Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
