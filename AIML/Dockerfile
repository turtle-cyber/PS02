FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Upgrade pip, setuptools, and wheel
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Copy requirements first (for layer caching)
COPY requirements.txt .

# Install PyTorch packages first (better stability)
RUN pip install --no-cache-dir torch==2.2.0 torchvision==0.17.0

# Install open-clip-torch separately to ensure proper dependency resolution
RUN pip install --no-cache-dir open-clip-torch==2.24.0

# Install remaining dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code (Python files and directories)
COPY *.py .
COPY api/ ./api/
COPY common/ ./common/
COPY data_prep/ ./data_prep/
COPY detectors/ ./detectors/

# Note: models/ directory structure includes:
#   - models/anomaly/ (Isolation Forest)
#   - models/vision/cse_index_updated/ (CLIP embeddings)
#   - models/vision/autoencoder_new/ (Visual autoencoder)
#   - models/text/semantic_anomaly/ (NEW: Text Sentence-BERT)
#   - models/url/url_anomaly/ (NEW: URL anomaly detector)
#   - models/js/js_anomaly/ (NEW: JS behavior detector)

# Copy model files (explicitly include despite .dockerignore)
COPY models/ ./models/

# Copy essential data files (baseline profiles and training data)
COPY data/ ./data/

# Create necessary directories for all models
RUN mkdir -p /out \
    /app/models/anomaly \
    /app/models/vision/cse_index_updated \
    /app/models/vision/autoencoder_new \
    /app/models/text/semantic_anomaly \
    /app/models/url/url_anomaly \
    /app/models/js/js_anomaly \
    /app/data/training

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Expose API port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the AIML service
CMD ["python", "-u", "aiml_service.py"]
