# Quick Start Guide - URL Submission Frontend

## Start the Frontend

### 1. Build and Start All Services

```bash
cd infra
docker-compose up -d
```

### 2. Wait for Services to be Ready

```bash
# Check all services are running
docker-compose ps

# Watch frontend-api logs
docker logs -f frontend-api
```

Wait until you see:
```
✅ Kafka producer connected successfully
✅ Server listening on port 3000
```

### 3. Open the Frontend

Open your browser and go to: **http://localhost:3000**

You should see:
- 🛡️ **Phishing Detection Pipeline** page
- ✅ **Connected to pipeline** status (green indicator)

---

## 📝 Submit Your First URL

### Via Web Interface (Recommended)

1. Open **http://localhost:3000**
2. Enter a URL or domain in the text box:
   - Example: `https://fake-sbi-login.com`
   - Or just: `suspicious-domain.com`
3. (Optional) Add Brand/CSE ID: `SBI`
4. (Optional) Add notes: `Testing submission flow`
5. Click **🚀 Submit for Analysis**

You should see:
```
✅ Successfully Submitted!

Domain: fake-sbi-login.com
Kafka Topic: raw.hosts
Partition: 0 | Offset: 12345
Pipeline: full (includes DNSTwist variant generation)
Processing Time: 3-5 minutes
```

### Via API (curl)

```bash
curl -X POST http://localhost:3000/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://test-phishing-site.com",
    "cse_id": "SBI",
    "notes": "Testing via API"
  }'
```

---

## 🔍 Track Your Submission

### Step 1: Check Frontend API Logs

```bash
docker logs -f frontend-api
```

Look for these log entries:
```
[info] 🎯 New submission request {"input":"https://test-phishing-site.com"}
[info] 🔍 Extracted domain {"extracted":"test-phishing-site.com"}
[info] 📤 Submitting to Kafka {"domain":"test-phishing-site.com"}
[info] ✅ Successfully submitted to Kafka {"partition":0,"offset":"12345"}
[info] 🎉 Submission successful
```

### Step 2: Verify in Kafka

```bash
# Check if message reached Kafka
docker exec -it kafka kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic raw.hosts \
  --from-beginning \
  --max-messages 5 | grep "test-phishing-site.com"
```

You should see a JSON message with your domain.

### Step 3: Track Through Pipeline

Watch each stage process your domain:

```bash
# Terminal 1: Normalizer
docker logs -f normalizer | grep "test-phishing-site.com"

# Terminal 2: DNS Collector
docker logs -f dns-collector | grep "test-phishing-site.com"

# Terminal 3: HTTP Fetcher
docker logs -f http-fetcher | grep "test-phishing-site.com"

# Terminal 4: Feature Crawler
docker logs -f feature-crawler | grep "test-phishing-site.com"

# Terminal 5: ChromaDB Ingestor
docker logs -f chroma-ingestor | grep "test-phishing-site.com"
```

---

## View Results in ChromaDB

### After 3-5 minutes, query ChromaDB:

```python
import chromadb

# Connect to ChromaDB
client = chromadb.HttpClient(host='localhost', port=8000)
collection = client.get_collection("domains")

# Get your domain
results = collection.get(ids=["test-phishing-site.com"])

if results['ids']:
    print("✅ Domain found in ChromaDB!")

    metadata = results['metadatas'][0]

    print(f"\n📋 Analysis Results:")
    print(f"  URL: {metadata.get('url')}")
    print(f"  Verdict: {metadata.get('final_verdict')} (confidence: {metadata.get('confidence')})")
    print(f"  Risk Score: {metadata.get('risk_score')}/100")
    print(f"  Country: {metadata.get('country')}")
    print(f"  Domain Age: {metadata.get('domain_age_days')} days")
    print(f"  Newly Registered: {metadata.get('is_newly_registered')}")
    print(f"  Self-Signed Cert: {metadata.get('is_self_signed')}")
    print(f"  Has Credential Form: {metadata.get('has_credential_form')}")

    # Monitoring status (if applicable)
    if metadata.get('requires_monitoring'):
        import datetime
        monitor_until = datetime.datetime.fromtimestamp(metadata.get('monitor_until', 0))
        print(f"\n⏰ Monitoring Status:")
        print(f"  Requires Monitoring: {metadata.get('requires_monitoring')}")
        print(f"  Reason: {metadata.get('monitor_reason')}")
        print(f"  Monitor Until: {monitor_until.strftime('%Y-%m-%d')}")

    print(f"\n📄 Full Metadata:")
    import json
    print(json.dumps(metadata, indent=2))
else:
    print("⏳ Still processing... wait a bit longer")
```

### Or use the REST API:

```bash
# Query via API (you'll need to create this endpoint or use Python client)
curl http://localhost:8000/api/v1/collections/domains/get \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"ids": ["test-phishing-site.com"]}'
```

## Troubleshooting

### Frontend shows "Pipeline unavailable"

**Problem:** Kafka not connected

**Solution:**
```bash
# Check Kafka is healthy
docker ps | grep kafka
docker exec kafka kafka-topics --bootstrap-server localhost:9092 --list

# Restart frontend-api
docker-compose restart frontend-api

# Check logs
docker logs frontend-api
```

### Submission returns 400 "Invalid domain format"

**Problem:** Domain doesn't match validation regex

**Solution:**
- Use proper domain format: `example.com` or `sub.example.com`
- Include `http://` or `https://` for URLs
- No spaces or special characters

### Domain not in ChromaDB after 5 minutes

**Check each stage:**

```bash
# 1. Was it submitted?
docker logs frontend-api | grep "your-domain.com"

# 2. Did normalizer process it?
docker logs normalizer | grep "your-domain.com"

# 3. Did DNS resolve?
docker logs dns-collector | grep "your-domain.com"

# 4. If DNS failed, check for NXDOMAIN
docker logs dns-collector --tail=100 | grep -A 5 "your-domain.com"

# 5. Did HTTP fetcher probe it?
docker logs http-fetcher | grep "your-domain.com"

# 6. Did it get crawled?
docker logs feature-crawler | grep "your-domain.com"

# 7. Was it ingested?
docker logs chroma-ingestor | grep "your-domain.com"
```

## You're All Set!

Your phishing detection pipeline with frontend is now running!

**Access Points:**
- 🌐 Frontend: http://localhost:3000
- 🏥 Health Check: http://localhost:3000/health
- 📊 ChromaDB: http://localhost:8000
- 🔧 Kafka: localhost:9092

**Submit a URL and watch it flow through the entire pipeline!** 🚀
