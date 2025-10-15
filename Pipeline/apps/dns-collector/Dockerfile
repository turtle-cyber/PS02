# apps/dns-collector/Dockerfile
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

# system deps: choose a concrete netcat provider and add ca-certificates
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential \
      libmaxminddb0 \
      libmaxminddb-dev \
      netcat-openbsd \
      curl \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# create workdir
WORKDIR /app

# copy requirements and install python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# copy app
COPY . /app

# default envs (tune via docker-compose)
ENV KAFKA_ENABLED=true \
    KAFKA_BOOTSTRAP=kafka:9092 \
    INPUT_TOPIC=raw.hosts \
    OUTPUT_TOPIC=domains.resolved \
    NAMESERVER=unbound \
    MAX_WORKERS=12 \
    GEOIP_CITY_DB=/configs/mmdb/GeoLite2-City.mmdb \
    GEOIP_ASN_DB=/configs/mmdb/GeoLite2-ASN.mmdb \
    CONSUMER_GROUP=dns-collector-group \
    RETRY_WAIT=2.0

# Fix: Run worker.py (the actual file name)
CMD ["python", "worker.py"]