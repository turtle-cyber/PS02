FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /workspace

# System bits if you want tldextract to be fast/quiet
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy code into the image (don’t rely on host bind for the wait script)
COPY router.py wait-for-topic-router.py ./

ENTRYPOINT ["/usr/bin/tini","--"]
CMD bash -lc "\
  echo '============================================================'; \
  echo 'URL Router Pre-Flight Check'; \
  echo 'Kafka:' ${KAFKA_BOOTSTRAP:-$KAFKA_BROKERS}; \
  echo 'Topic:' ${IN_TOPIC}; \
  echo 'Max Wait:' ${MAX_WAIT_SECONDS:-300}s; \
  echo '============================================================'; \
  python -u /workspace/wait-for-topic-router.py && \
  exec python -u /workspace/router.py \
"
