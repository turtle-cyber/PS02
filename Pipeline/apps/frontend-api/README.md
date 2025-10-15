# Frontend API - Phishing Detection Pipeline

Simple one-page web frontend with Node.js API for submitting URLs to the phishing detection pipeline.

## Features

- ✅ **Simple One-Page UI** - Clean, modern interface for URL submission
- ✅ **Dual-Flow Pipeline** - Choose between direct analysis or full variant generation
- ✅ **Node.js + Express API** - RESTful API with Kafka integration
- ✅ **Comprehensive Logging** - Winston logger tracking every step
- ✅ **Health Checks** - Real-time pipeline connectivity status
- ✅ **Rate Limiting** - Protection against abuse
- ✅ **Security Headers** - Helmet.js for security best practices
- ✅ **Docker Integration** - Fully containerized and integrated into pipeline

## Quick Start

### Option 1: Run with Docker Compose (Recommended)

```bash
cd infra
docker-compose up -d frontend-api
```

Access the frontend at: **http://localhost:3000**

### Option 2: Run Locally for Development

```bash
cd apps/frontend-api
npm install
npm start
```

Or with nodemon for auto-reload:

```bash
npm run dev
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server port |
| `KAFKA_BROKERS` | `localhost:9092` | Kafka broker addresses (comma-separated) |
| `KAFKA_TOPIC` | `raw.hosts` | Target Kafka topic for submissions |
| `LOG_LEVEL` | `info` | Winston log level (debug, info, warn, error) |

## Pipeline Flows

The frontend API supports **two submission flows**:

### 1. Direct Flow (Default - Checkbox Unchecked) ⚡

**Target Topic:** `domains.candidates`
**Processing Time:** 2-3 minutes
**Use Case:** Fast analysis of specific suspicious URLs reported by users

**Flow:**
```
Frontend → domains.candidates → DNS Collector → HTTP Fetcher →
URL Router → Feature Crawler → ChromaDB
```

**What it skips:**
- ❌ DNSTwist variant generation
- ❌ CT-Watcher monitoring

### 2. Full Flow (Checkbox Checked) 📋

**Target Topic:** `raw.hosts`
**Processing Time:** 3-5 minutes
**Use Case:** Brand monitoring with typosquatting variant detection

**Flow:**
```
Frontend → raw.hosts → DNSTwist (generates ~50+ variants) →
Normalizer → DNS Collector → HTTP Fetcher → URL Router →
Feature Crawler → ChromaDB
```

**Additional processing:**
- ✅ DNSTwist variant generation (~50+ domain variants)
- ✅ CT-Watcher monitoring

---

## API Endpoints

### `GET /health`

Health check endpoint showing Kafka connectivity status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-01-15T10:30:00.000Z",
  "uptime": 123.45,
  "kafka": {
    "connected": true,
    "brokers": ["kafka:9092"],
    "topic": "raw.hosts"
  }
}
```

### `POST /api/submit`

Submit a URL or domain for phishing analysis.

**Request Body:**
```json
{
  "url": "https://suspicious-site.com",
  "cse_id": "SBI",
  "notes": "User reported suspicious link",
  "use_full_pipeline": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` or `domain` | string | ✅ Yes | URL or domain to analyze |
| `cse_id` | string | No | Brand identifier (e.g., "SBI", "ICICI") |
| `notes` | string | No | Additional context |
| `use_full_pipeline` | boolean | No | `true` = Full flow with DNSTwist, `false` = Direct flow (default) |

**Response (Success - Direct Flow):**
```json
{
  "success": true,
  "message": "Domain submitted successfully for analysis",
  "domain": "suspicious-site.com",
  "original_input": "https://suspicious-site.com",
  "kafka_topic": "domains.candidates",
  "kafka_partition": 0,
  "kafka_offset": "12345",
  "estimated_processing_time": "2-3 minutes",
  "pipeline": "direct (skips DNSTwist/CT-Watcher)",
  "timestamp": "2025-01-15T10:30:00.000Z"
}
```

**Response (Success - Full Flow):**
```json
{
  "success": true,
  "message": "Domain submitted successfully for analysis",
  "domain": "suspicious-site.com",
  "original_input": "https://suspicious-site.com",
  "kafka_topic": "raw.hosts",
  "kafka_partition": 0,
  "kafka_offset": "12345",
  "estimated_processing_time": "3-5 minutes",
  "pipeline": "full (includes DNSTwist variant generation)",
  "timestamp": "2025-01-15T10:30:00.000Z"
}
```

**Response (Error):**
```json
{
  "success": false,
  "error": "Invalid domain format",
  "domain": "invalid..com"
}
```

### `POST /api/submit-bulk`

Submit multiple URLs/domains at once for bulk analysis. **Bypasses rate limiting** for bulk operations.

**Request Body:**
```json
{
  "urls": [
    "https://example1.com",
    "https://example2.com",
    "example3.com"
  ],
  "use_full_pipeline": false,
  "cse_id": "SBI",
  "notes": "Bulk import from security report"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `urls` | array | ✅ Yes | Array of URLs or domains (max 10,000) |
| `use_full_pipeline` | boolean | No | `true` = Full flow with DNSTwist, `false` = Direct flow (default) |
| `cse_id` | string | No | Brand identifier for all URLs |
| `notes` | string | No | Shared notes for the batch |

**Response (Success):**
```json
{
  "success": true,
  "message": "Bulk submission completed",
  "summary": {
    "total_submitted": 100,
    "successfully_queued": 98,
    "failed": 2,
    "kafka_topic": "domains.candidates",
    "pipeline": "direct (skips DNSTwist/CT-Watcher)"
  },
  "timing": {
    "submission_time_ms": 1234,
    "estimated_time_per_url": "2-3 minutes",
    "estimated_total_minutes": 245,
    "estimated_completion": "2025-01-15T14:30:00.000Z"
  },
  "results": [
    {
      "index": 0,
      "url": "https://example1.com",
      "domain": "example1.com",
      "status": "queued",
      "partition": 0,
      "offset": "12345"
    }
  ],
  "errors": [
    {
      "index": 5,
      "url": "invalid..domain",
      "error": "Invalid domain format"
    }
  ]
}
```

**Features:**
- ✅ Supports up to 10,000 URLs per request
- ✅ Validates each URL individually
- ✅ Returns detailed results for each URL
- ✅ Reports errors for invalid URLs without failing entire batch
- ✅ Progress logging every 100 URLs
- ✅ Estimates total processing time

### `GET /api/stats`

Get API statistics.

**Response:**
```json
{
  "uptime_seconds": 1234,
  "kafka_connected": true,
  "kafka_topic": "raw.hosts",
  "timestamp": "2025-01-15T10:30:00.000Z"
}
```

### `GET /`

Serves the frontend HTML page.

## Logging

All logs are output in JSON format using Winston. Console logs include colorized output for easy reading.

### Log Levels and Events

| Event | Level | Description |
|-------|-------|-------------|
| Server start | `info` | Server listening on port |
| Kafka connection | `info` | Kafka producer connected |
| Incoming request | `info` | HTTP request received |
| Domain extraction | `info` | Domain extracted from URL |
| Kafka submission | `info` | Message sent to Kafka |
| Submission success | `info` | Complete submission details |
| Validation error | `warn` | Invalid input rejected |
| Kafka error | `error` | Kafka connection/send failure |
| Unhandled error | `error` | Unexpected errors |

### Example Log Output

```
2025-01-15T10:30:00.000Z [info] 🚀 Starting Phishing Detection Frontend API
2025-01-15T10:30:00.100Z [info] 📋 Configuration: PORT=3000, KAFKA_BROKERS=kafka:9092, KAFKA_TOPIC=raw.hosts
2025-01-15T10:30:01.000Z [info] 🔌 Connecting to Kafka...
2025-01-15T10:30:02.000Z [info] ✅ Kafka producer connected successfully
2025-01-15T10:30:03.000Z [info] ✅ Server listening on port 3000
2025-01-15T10:30:10.000Z [info] 📥 Incoming request {"method":"POST","path":"/api/submit","ip":"172.25.0.1"}
2025-01-15T10:30:10.010Z [info] 🎯 New submission request {"input":"https://fake-sbi.com","cse_id":"SBI"}
2025-01-15T10:30:10.020Z [info] 🔍 Extracted domain {"input":"https://fake-sbi.com","extracted":"fake-sbi.com"}
2025-01-15T10:30:10.030Z [info] 📤 Submitting to Kafka {"topic":"raw.hosts","domain":"fake-sbi.com"}
2025-01-15T10:30:10.100Z [info] ✅ Successfully submitted to Kafka {"domain":"fake-sbi.com","partition":0,"offset":"12345"}
2025-01-15T10:30:10.110Z [info] 🎉 Submission successful {"domain":"fake-sbi.com","duration_ms":100}
```

## Viewing Logs

### Docker Logs

```bash
# Follow logs in real-time
docker logs -f frontend-api

# Last 100 lines
docker logs --tail=100 frontend-api

# Since last 10 minutes
docker logs --since=10m frontend-api
```

### Filter Logs by Level

```bash
# Only errors
docker logs frontend-api 2>&1 | grep "\"level\":\"error\""

# Only submissions
docker logs frontend-api 2>&1 | grep "Submission"
```

## Testing the Submission Flow

### 1. Check Frontend is Running

```bash
curl http://localhost:3000/health
```

Expected: `{"status":"healthy","kafka":{"connected":true}}`

### 2. Submit a Test Domain

**Direct Flow (Default - Fast Analysis):**
```bash
curl -X POST http://localhost:3000/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://test-phishing-site.com",
    "cse_id": "TEST",
    "notes": "Testing direct flow",
    "use_full_pipeline": false
  }'
```

Expected: `{"success":true,"domain":"test-phishing-site.com","kafka_topic":"domains.candidates","pipeline":"direct (skips DNSTwist/CT-Watcher)",...}`

**Full Flow (With DNSTwist Variants):**
```bash
curl -X POST http://localhost:3000/api/submit \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://test-phishing-site.com",
    "cse_id": "TEST",
    "notes": "Testing full flow with variants",
    "use_full_pipeline": true
  }'
```

Expected: `{"success":true,"domain":"test-phishing-site.com","kafka_topic":"raw.hosts","pipeline":"full (includes DNSTwist variant generation)",...}`

**Bulk Submission (100 URLs at once):**
```bash
curl -X POST http://localhost:3000/api/submit-bulk \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://site1.com",
      "https://site2.com",
      "https://site3.com"
    ],
    "use_full_pipeline": false,
    "cse_id": "TEST"
  }'
```

Expected: `{"success":true,"summary":{"total_submitted":3,"successfully_queued":3},"timing":{"estimated_total_minutes":8},...}`

### 3. Verify Submission in Kafka

**For Direct Flow (domains.candidates topic):**
```bash
docker exec -it kafka kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic domains.candidates \
  --from-beginning \
  --max-messages 1
```

**For Full Flow (raw.hosts topic):**
```bash
docker exec -it kafka kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic raw.hosts \
  --from-beginning \
  --max-messages 1
```

Expected: You should see your submitted domain in JSON format

### 4. Track Through Pipeline

Watch the logs of each service to see your domain progress:

```bash
# Normalizer
docker logs -f normalizer | grep "test-phishing-site.com"

# DNS Collector
docker logs -f dns-collector | grep "test-phishing-site.com"

# HTTP Fetcher
docker logs -f http-fetcher | grep "test-phishing-site.com"

# Feature Crawler
docker logs -f feature-crawler | grep "test-phishing-site.com"

# ChromaDB Ingestor
docker logs -f chroma-ingestor | grep "test-phishing-site.com"
```

### 5. Query Results in ChromaDB (after 3-5 minutes)

```python
import chromadb

client = chromadb.HttpClient(host='localhost', port=8000)
collection = client.get_collection("domains")

# Check if your domain was processed
results = collection.get(ids=["test-phishing-site.com"])

if results['ids']:
    print("✅ Domain found in ChromaDB!")
    print(results['metadatas'][0])
else:
    print("⏳ Still processing or check failed stages")
```

## Security Features

- **Rate Limiting**: 100 requests per 15 minutes per IP
- **Helmet.js**: Security headers (XSS protection, HSTS, etc.)
- **CORS**: Configured for cross-origin requests
- **Input Validation**: Domain format validation
- **Non-root User**: Docker container runs as non-root user

## Troubleshooting

### Frontend shows "Pipeline unavailable"

**Check Kafka connection:**
```bash
docker logs frontend-api | grep "Kafka"
```

**Verify Kafka is healthy:**
```bash
docker ps | grep kafka
docker logs kafka --tail=20
```

### Submission returns 503 error

**Kafka not ready.** Wait a few seconds and try again:
```bash
docker exec -it kafka kafka-topics --bootstrap-server localhost:9092 --list
```

### Domain not appearing in ChromaDB

**Check each stage:**
1. Frontend logs: Was submission successful?
2. Kafka topic: Is message in `raw.hosts`?
3. Normalizer logs: Did it process the domain?
4. DNS Collector logs: Did DNS resolution work?
5. ChromaDB Ingestor logs: Did it ingest the record?

## Development

### Project Structure

```
frontend-api/
├── server.js           # Main Express server
├── public/
│   └── index.html     # Frontend UI
├── package.json       # Dependencies
├── Dockerfile         # Container definition
├── .dockerignore      # Files to exclude from image
└── README.md          # This file
```

### Making Changes

1. Edit `server.js` or `public/index.html`
2. Rebuild and restart:
   ```bash
   cd infra
   docker-compose up -d --build frontend-api
   ```
3. Check logs:
   ```bash
   docker logs -f frontend-api
   ```

## Bulk Submission

The API supports bulk URL submission for processing large batches efficiently.

### Features

- **High Volume**: Process up to 10,000 URLs in a single request
- **No Rate Limiting**: Bulk endpoint bypasses standard rate limits
- **Error Tolerance**: Invalid URLs don't fail the entire batch
- **Progress Tracking**: Returns detailed results for each URL
- **Both Flows**: Supports direct and full pipeline modes

### Use Cases

1. **Security Report Processing**: Import IOC lists from threat intelligence
2. **Incident Response**: Analyze multiple suspicious URLs from a security event
3. **Brand Monitoring**: Bulk upload domains for typosquatting analysis
4. **Historical Analysis**: Process archived URL lists

### Performance Expectations

| Batch Size | Direct Flow | Full Flow (with DNSTwist) |
|------------|-------------|---------------------------|
| 100 URLs | ~4 hours | ~7 hours + variants |
| 1,000 URLs | ~40 hours | ~70 hours + variants |
| 10,000 URLs | ~17 days | ~29 days + variants |

**Note**: These are sequential processing times. See "Scaling" section to improve throughput.

### Example: CSV to JSON Conversion

```javascript
// Node.js example: Convert CSV to bulk submission
const fs = require('fs');
const csv = require('csv-parser');
const axios = require('axios');

const urls = [];

fs.createReadStream('suspicious_urls.csv')
  .pipe(csv())
  .on('data', (row) => {
    urls.push(row.url); // Assuming CSV has 'url' column
  })
  .on('end', async () => {
    console.log(`Submitting ${urls.length} URLs...`);

    const response = await axios.post('http://localhost:3000/api/submit-bulk', {
      urls: urls,
      use_full_pipeline: false,
      cse_id: 'BULK_IMPORT',
      notes: 'CSV import from security report'
    });

    console.log(`Success: ${response.data.summary.successfully_queued}`);
    console.log(`Failed: ${response.data.summary.failed}`);
  });
```

### Scaling for Bulk Processing

To improve throughput for large batches:

1. **Scale Feature Crawler** (biggest bottleneck):
   ```yaml
   # In docker-compose.yml
   feature-crawler:
     deploy:
       replicas: 5  # 5x faster processing
   ```

2. **Increase Concurrency**:
   ```yaml
   dns-collector:
     environment:
       - MAX_CONCURRENT_DNS=100  # Default: 50

   http-fetcher:
     environment:
       - CONCURRENCY=40  # Default: 20
   ```

3. **Monitor Queue Depth**:
   ```bash
   docker exec -it kafka kafka-consumer-groups.sh \
     --bootstrap-server localhost:9092 \
     --describe --group chroma-ingestor
   ```

---

## Integration with Pipeline

The frontend-api supports **two submission modes**:

### Direct Flow (Default) ⚡
```
Frontend → domains.candidates → DNS Collector → HTTP Fetcher →
URL Router → Feature Crawler → ChromaDB
```

**Processing includes:**
- ✅ DNS resolution
- ✅ WHOIS lookup (domain age detection)
- ✅ GeoIP enrichment
- ✅ HTTP/HTTPS probing
- ✅ SSL certificate analysis
- ✅ Webpage feature extraction
- ✅ JavaScript analysis
- ✅ Favicon hashing
- ✅ Storage in ChromaDB

**Total processing time:** ~2-3 minutes

### Full Flow (Checkbox Enabled) 📋
```
Frontend → raw.hosts → DNSTwist → Normalizer → DNS Collector → HTTP Fetcher →
URL Router → Feature Crawler → ChromaDB
```

**Additional processing:**
- ✅ All features from Direct Flow PLUS:
- ✅ DNSTwist variant generation (~50+ typosquatting variants)
- ✅ CT-Watcher certificate monitoring
- ✅ Normalizer deduplication

**Total processing time:** ~3-5 minutes

## Next Steps

1. Submit a test URL through the frontend
2. Monitor logs to track progress
3. Query ChromaDB after 3-5 minutes for results
4. Build analytics dashboards on top of the API
5. Add authentication for production use

## Links

- Frontend: http://localhost:3000
- API Health: http://localhost:3000/health
- Submit API: http://localhost:3000/api/submit
- ChromaDB: http://localhost:8000
