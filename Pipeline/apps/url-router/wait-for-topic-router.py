import os, time, sys, subprocess
print("============================================================")
print("URL Router Pre-Flight Check")
print("Kafka:", os.getenv("KAFKA_BOOTSTRAP", os.getenv("KAFKA_BROKERS", "")))
print("Topic:", os.getenv("IN_TOPIC", ""))
print("Max Wait:", f"{os.getenv('MAX_WAIT_SECONDS', '300')}s")
print("============================================================")

from kafka import KafkaConsumer, TopicPartition
from kafka.errors import NoBrokersAvailable

bootstrap = os.getenv("KAFKA_BOOTSTRAP", os.getenv("KAFKA_BROKERS", "kafka:9092"))
topic = os.getenv("IN_TOPIC", "")
max_wait = int(os.getenv("MAX_WAIT_SECONDS", "300"))

if not topic:
    raise SystemExit("[wait-router] IN_TOPIC is empty")

start = time.time()
while True:
    try:
        consumer = KafkaConsumer(
            bootstrap_servers=bootstrap,
            auto_offset_reset="earliest",
            enable_auto_commit=False,
            request_timeout_ms=15000,
            api_version_auto_timeout_ms=15000,
        )
        md = consumer.topics()
        # triggers metadata fetch
        if topic not in md:
            if time.time() - start > max_wait:
                raise SystemExit(f"[wait-router] Topic '{topic}' not found within {max_wait}s")
            print(f"[wait-router] Topic '{topic}' doesn't exist yet, waiting 5s...")
            time.sleep(5)
            continue

        tp = TopicPartition(topic, 0)
        consumer.assign([tp])
        consumer.seek_to_beginning(tp)
        beg = consumer.position(tp)
        consumer.seek_to_end(tp)
        end = consumer.position(tp)
        n = max(0, end - beg)
        print(f"[wait-router] Partition 0: {n} messages (offsets {beg}-{end})")
        if n > 0:
            print(f"[wait-router] ✓ Topic '{topic}' has {n} message(s) ready!")
            print("============================================================")
            print("[wait-router] ✓ All pre-flight checks passed!")
            print("[wait-router] Starting URL Router...")
            print("============================================================")
            consumer.close()
            break
        if time.time() - start > max_wait:
            raise SystemExit(f"[wait-router] Topic '{topic}' had 0 messages for {max_wait}s")
        print(f"[wait-router] Topic '{topic}' exists but has 0 messages, waiting 5s...")
        time.sleep(5)
    except NoBrokersAvailable:
        if time.time() - start > max_wait:
            raise
        print(f"[wait-router] Waiting for Kafka broker at {bootstrap}...")
        time.sleep(5)

# Now start the actual router
result = subprocess.run([sys.executable, "-u", "/workspace/router.py"])
sys.exit(result.returncode)