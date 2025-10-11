import json
import os
from typing import Iterator
from kafka import KafkaConsumer, KafkaProducer

def make_consumer(topic: str, group_id: str = "feature-crawler") -> KafkaConsumer:
    brokers = os.getenv("KAFKA_BROKERS", "localhost:9092")
    return KafkaConsumer(
        topic,
        bootstrap_servers=brokers.split(","),
        group_id=group_id,
        enable_auto_commit=True,
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        key_deserializer=lambda v: v.decode("utf-8") if v else None,
        consumer_timeout_ms=30000,
        max_poll_records=50,
    )

def make_producer() -> KafkaProducer:
    brokers = os.getenv("KAFKA_BROKERS", "localhost:9092")
    return KafkaProducer(
        bootstrap_servers=brokers.split(","),
        value_serializer=lambda v: json.dumps(v, separators=(",", ":")).encode("utf-8"),
        key_serializer=lambda v: v.encode("utf-8") if v else None,
        linger_ms=10,
        acks="all",
    )

def iter_messages(consumer: KafkaConsumer) -> Iterator:
    for msg in consumer:
        yield msg
