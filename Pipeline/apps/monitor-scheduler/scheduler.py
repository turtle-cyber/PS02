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
INACTIVE_TOPIC = os.getenv("INACTIVE_TOPIC", "phish.urls.inactive")  # NEW: Inactive domains
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC", "raw.hosts")
GROUP_ID = os.getenv("GROUP_ID", "monitor-scheduler")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
CHECK_INTERVAL = int(os.getenv("MONITOR_CHECK_INTERVAL", "86400"))  # 24h
MAX_RECHECKS = int(os.getenv("MAX_RECHECKS", "3"))

# Inactive domain monitoring config
INACTIVE_CHECK_INTERVALS = [7*86400, 30*86400, 90*86400]  # 7d, 30d, 90d
UNREGISTERED_CHECK_INTERVALS = [30*86400, 90*86400, 180*86400]  # 30d, 90d, 180d
MAX_INACTIVE_CHECKS = int(os.getenv("MAX_INACTIVE_CHECKS", "3"))

# Redis keys
MONITOR_QUEUE = "monitoring:queue"  # Sorted set: member=domain, score=monitor_until (active monitoring)
INACTIVE_QUEUE = "monitoring:inactive"  # NEW: Sorted set for inactive/unregistered domains
MONITOR_META_PREFIX = "monitoring:meta:"  # Hash: domain metadata
INACTIVE_META_PREFIX = "monitoring:meta:inactive:"  # NEW: Inactive domain metadata

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

async def process_inactive_domain(msg, r_client):
    """Store inactive/unregistered domain for periodic monitoring"""
    try:
        payload = json.loads(msg.value) if msg.value else {}
    except Exception:
        return

    registrable = payload.get("registrable") or payload.get("canonical_fqdn", "")
    if not registrable:
        return

    status = payload.get("status", "inactive")  # "inactive" or "unregistered"
    cse_id = payload.get("cse_id", "")
    seed = payload.get("seed_registrable", "")
    reasons = payload.get("reasons", [])

    # Determine check intervals based on status
    intervals = UNREGISTERED_CHECK_INTERVALS if status == "unregistered" else INACTIVE_CHECK_INTERVALS
    first_check_delay = intervals[0]

    # Check if already monitoring
    meta_key = f"{INACTIVE_META_PREFIX}{registrable}"
    if r_client.exists(meta_key):
        return  # Already tracking

    # Store metadata
    next_check = int(time.time()) + first_check_delay
    r_client.hset(meta_key, mapping={
    "status": str(status or "inactive"),
    "cse_id": str(cse_id or ""),
    "seed": str(seed or ""),
    "reasons": ",".join(reasons or []),
    "check_count": "0",
    "first_seen": str(int(time.time())),
    })
    r_client.zadd(INACTIVE_QUEUE, {registrable: next_check})
    print(f"[monitor] Added inactive {registrable} (status: {status}, next check: {first_check_delay/86400:.0f}d)")

async def check_inactive_domains(producer, r_client):
    """Check inactive/unregistered domains for registration/activation"""
    import socket
    now = int(time.time())
    expired = r_client.zrangebyscore(INACTIVE_QUEUE, 0, now)

    if not expired:
        return

    print(f"[monitor] Checking {len(expired)} inactive domains")

    for domain in expired:
        meta_key = f"{INACTIVE_META_PREFIX}{domain}"
        meta = r_client.hgetall(meta_key)

        if not meta:
            r_client.zrem(INACTIVE_QUEUE, domain)
            continue

        check_count = int(meta.get("check_count", "0"))
        status = meta.get("status", "inactive")

        if check_count >= MAX_INACTIVE_CHECKS:
            print(f"[monitor] {domain} reached max inactive checks, removing")
            r_client.zrem(INACTIVE_QUEUE, domain)
            r_client.delete(meta_key)
            continue

        # Quick DNS check
        try:
            socket.gethostbyname(domain)
            is_registered = True
        except:
            is_registered = False

        if is_registered:
            print(f"[monitor] {domain} is now ACTIVE/REGISTERED! Re-queuing for crawl...")
            # Re-queue to raw.hosts for full processing
            requeue_msg = {
                "src": "inactive-monitor",
                "canonical_fqdn": domain,
                "registrable": domain,
                "observed_at": time.time(),
                "cse_id": meta.get("cse_id", ""),
                "reasons": [f"newly_active (was: {status})"],
            }
            await producer.send_and_wait(OUTPUT_TOPIC, json.dumps(requeue_msg).encode("utf-8"))
            r_client.zrem(INACTIVE_QUEUE, domain)
            r_client.delete(meta_key)
        else:
            # Schedule next check
            intervals = UNREGISTERED_CHECK_INTERVALS if status == "unregistered" else INACTIVE_CHECK_INTERVALS
            if check_count < len(intervals):
                next_delay = intervals[check_count]
                next_check = now + next_delay
                r_client.zadd(INACTIVE_QUEUE, {domain: next_check})
                r_client.hincrby(meta_key, "check_count", 1)
                print(f"[monitor] {domain} still {status}, next check in {next_delay/86400:.0f}d")
            else:
                r_client.zrem(INACTIVE_QUEUE, domain)
                r_client.delete(meta_key)

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

    # Kafka consumer/producer - consume BOTH verdicts and inactive domains
    consumer = AIOKafkaConsumer(
        VERDICTS_TOPIC,
        INACTIVE_TOPIC,  # NEW: Also consume inactive domains
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
            # Route based on topic
            if msg.topic == INACTIVE_TOPIC:
                await process_inactive_domain(msg, r_client)
            else:
                await process_verdict(msg, r_client)

            # Periodic check for expired (both active and inactive)
            now = time.time()
            if now - last_check >= CHECK_INTERVAL:
                await check_expired(producer, r_client)
                await check_inactive_domains(producer, r_client)  # NEW: Check inactive too
                last_check = now

                # Stats
                queue_size = r_client.zcard(MONITOR_QUEUE)
                inactive_size = r_client.zcard(INACTIVE_QUEUE)
                print(f"[monitor] Queue size: {queue_size} active, {inactive_size} inactive")

    finally:
        await consumer.stop()
        await producer.stop()
        print("[monitor] Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
