FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl jq bash && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY watcher.py /app/watcher.py

# Defaults (override in compose)
ENV KAFKA_ENABLED=true \
    KAFKA_BOOTSTRAP=kafka:9092 \
    KAFKA_TOPIC=raw.hosts \
    OUTPUT_DIR=/out \
    CT_URL=wss://certstream.calidog.io/ \
    SUSPICIOUS_TLDS_FILE=/configs/defaults.india.yml

VOLUME ["/out"]
CMD ["python", "-u", "/app/watcher.py"]
