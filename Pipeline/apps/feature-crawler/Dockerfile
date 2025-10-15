# Use official image with browsers & deps preinstalled
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

# We'll install OCR + fonts and keep everything else minimal
USER root
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr tesseract-ocr-eng fonts-liberation ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Install Python deps (note: playwright already in base image, see requirements change below)
COPY requirements.txt .
RUN pip install -r requirements.txt

# Add kafka-python for the wait script
RUN pip install --no-cache-dir kafka-python==2.0.2

# App code
COPY . /workspace

# Copy wait script
COPY wait-for-topic-crawler.py /workspace/wait-for-topic-crawler.py
RUN chmod +x /workspace/wait-for-topic-crawler.py

# Defaults (override via compose)
ENV IN_TOPIC=phish.urls.crawl \
    OUT_TOPIC_RAW=phish.http.crawled \
    OUT_TOPIC_FEAT=phish.features.page \
    KAFKA_BROKERS=kafka:9092 \
    KAFKA_BOOTSTRAP=kafka:9092 \
    OUT_DIR=/workspace/out \
    NAV_TIMEOUT_MS=15000 \
    PLAYWRIGHT_HEADLESS=1 \
    USER_AGENT="" \
    CONFIG_FILE=/workspace/configs/feature_crawler.yml \
    MAX_WAIT_SECONDS=300

# Prepare writable dirs and hand off to pwuser (non-root)
RUN mkdir -p /workspace/out/screenshots /workspace/out/pdfs /workspace/out/html /workspace/out/hars /workspace/out/ocr \
 && chown -R pwuser:pwuser /workspace

USER pwuser

# Use the wait script as entrypoint
CMD ["python", "-u", "/workspace/wait-for-topic-crawler.py"]