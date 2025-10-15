FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Add kafka-python for the wait script
RUN pip install --no-cache-dir kafka-python==2.0.2

COPY fetcher.py /app/fetcher.py
COPY wait-for-topic.py /app/wait-for-topic.py
RUN chmod +x /app/wait-for-topic.py

# Use the wait script as entrypoint
CMD ["python", "-u", "/app/wait-for-topic.py"]