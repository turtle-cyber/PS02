FROM python:3.11-slim

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential curl \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# dnstwist with extras (no Chromium/phash in this producer)
RUN pip install --no-cache-dir "dnstwist[full]"

COPY runner.py /app/runner.py
COPY runner_continuous.py /app/runner_continuous.py

# defaults (you can override in compose)
ENV KAFKA_ENABLED=true \
    KAFKA_BOOTSTRAP=kafka:9092 \
    KAFKA_INPUT_TOPIC=raw.hosts \
    KAFKA_OUTPUT_TOPIC=raw.hosts \
    OUTPUT_DIR=/out \
    THREADS=16 \
    NAMESERVERS=unbound:5335 \
    PROCESS_CSV_ON_STARTUP=true \
    RUNNER_MODE=continuous

VOLUME ["/out"]

# Use continuous runner by default, fallback to one-shot
CMD ["sh", "-c", "if [ \"$RUNNER_MODE\" = \"continuous\" ]; then python -u /app/runner_continuous.py; else python -u /app/runner.py; fi"]
