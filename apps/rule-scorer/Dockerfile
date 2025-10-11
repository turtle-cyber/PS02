# apps/rule-scorer/Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# System deps for building optional decompressors (snappy/zstd)
RUN apt-get update -y \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential gcc g++ \
      libsnappy-dev \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Create non-root user FIRST
RUN useradd -m -u 10001 appuser

WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install -r requirements.txt

# App code
COPY worker.py /app/worker.py

# Create output dir for optional JSONL mirror with correct permissions
RUN mkdir -p /out \
 && chown -R appuser:appuser /app /out

# Switch to non-root user
USER appuser

# No ports exposed (Kafka client only)
CMD ["python", "-u", "worker.py"]