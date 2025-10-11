FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY normalizer.py /app/normalizer.py

ENV KAFKA_BOOTSTRAP=kafka:9092 \
    INPUT_TOPIC=raw.hosts \
    OUTPUT_TOPIC=domains.candidates \
    KAFKA_ENABLED=true \
    OUTPUT_DIR=/out \
    REDIS_HOST=redis \
    REDIS_PORT=6379 \
    DEDUP_TTL_SECS=10368000

VOLUME ["/out"]
CMD ["python", "-u", "/app/normalizer.py"]
