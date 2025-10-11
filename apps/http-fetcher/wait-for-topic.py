#!/usr/bin/env python3
"""
Wait for Kafka topic to have messages before starting the main process.
This ensures http-fetcher only starts when dns-collector has populated data.
"""
import sys
import time
import os
from kafka import KafkaConsumer, TopicPartition
from kafka.errors import NoBrokersAvailable, UnknownTopicOrPartitionError

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
TOPIC = os.getenv("INPUT_TOPIC", "domains.resolved")
MAX_WAIT_SECONDS = int(os.getenv("MAX_WAIT_SECONDS", "300"))  # 5 minutes max
CHECK_INTERVAL = 5

def wait_for_kafka():
    """Wait for Kafka broker to be available"""
    print(f"[wait] Waiting for Kafka broker at {KAFKA_BOOTSTRAP}...")
    start = time.time()
    
    while time.time() - start < MAX_WAIT_SECONDS:
        try:
            consumer = KafkaConsumer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                consumer_timeout_ms=1000,
                api_version=(2, 0, 0)
            )
            consumer.close()
            print(f"[wait] ✓ Kafka broker available")
            return True
        except NoBrokersAvailable:
            print(f"[wait] Kafka not ready, retrying in {CHECK_INTERVAL}s...")
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            print(f"[wait] Error connecting to Kafka: {e}")
            time.sleep(CHECK_INTERVAL)
    
    print(f"[wait] ✗ Kafka broker not available after {MAX_WAIT_SECONDS}s")
    return False

def wait_for_topic_messages():
    """Wait for topic to exist AND have at least one message"""
    print(f"[wait] Waiting for topic '{TOPIC}' to have messages...")
    start = time.time()
    
    while time.time() - start < MAX_WAIT_SECONDS:
        try:
            consumer = KafkaConsumer(
                bootstrap_servers=KAFKA_BOOTSTRAP,
                consumer_timeout_ms=1000,
                auto_offset_reset='earliest',
                api_version=(2, 0, 0)
            )
            
            # Check if topic exists
            topics = consumer.topics()
            if TOPIC not in topics:
                print(f"[wait] Topic '{TOPIC}' doesn't exist yet, waiting {CHECK_INTERVAL}s...")
                consumer.close()
                time.sleep(CHECK_INTERVAL)
                continue
            
            # Get partitions for the topic
            partitions = consumer.partitions_for_topic(TOPIC)
            if not partitions:
                print(f"[wait] Topic '{TOPIC}' has no partitions yet, waiting {CHECK_INTERVAL}s...")
                consumer.close()
                time.sleep(CHECK_INTERVAL)
                continue
            
            # Check message count across all partitions
            total_messages = 0
            for partition in partitions:
                tp = TopicPartition(TOPIC, partition)
                consumer.assign([tp])
                
                # Get beginning and end offsets
                beginning_offset = consumer.beginning_offsets([tp])[tp]
                end_offset = consumer.end_offsets([tp])[tp]
                messages_in_partition = end_offset - beginning_offset
                total_messages += messages_in_partition
                
                print(f"[wait] Partition {partition}: {messages_in_partition} messages (offsets {beginning_offset}-{end_offset})")
            
            consumer.close()
            
            if total_messages > 0:
                print(f"[wait] ✓ Topic '{TOPIC}' has {total_messages} message(s) ready!")
                return True
            else:
                print(f"[wait] Topic '{TOPIC}' exists but has 0 messages, waiting {CHECK_INTERVAL}s...")
                time.sleep(CHECK_INTERVAL)
                
        except UnknownTopicOrPartitionError:
            print(f"[wait] Topic '{TOPIC}' not found, waiting {CHECK_INTERVAL}s...")
            time.sleep(CHECK_INTERVAL)
        except Exception as e:
            print(f"[wait] Error checking topic: {e}")
            time.sleep(CHECK_INTERVAL)
    
    print(f"[wait] ✗ Topic '{TOPIC}' did not receive messages after {MAX_WAIT_SECONDS}s")
    return False

def main():
    print("=" * 60)
    print(f"HTTP Fetcher Pre-Flight Check")
    print(f"Kafka: {KAFKA_BOOTSTRAP}")
    print(f"Topic: {TOPIC}")
    print(f"Max Wait: {MAX_WAIT_SECONDS}s")
    print("=" * 60)
    
    # Step 1: Wait for Kafka broker
    if not wait_for_kafka():
        print("[wait] FAILED: Kafka broker unavailable")
        sys.exit(1)
    
    # Step 2: Wait for topic to have messages
    if not wait_for_topic_messages():
        print("[wait] FAILED: Topic has no messages")
        sys.exit(1)
    
    print("=" * 60)
    print("[wait] ✓ All pre-flight checks passed!")
    print("[wait] Starting HTTP Fetcher...")
    print("=" * 60)
    
    # Import and run the main fetcher
    import subprocess
    result = subprocess.run([sys.executable, "-u", "/app/fetcher.py"])
    sys.exit(result.returncode)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[wait] Interrupted")
        sys.exit(130)