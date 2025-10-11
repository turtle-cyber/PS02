# Frontend Integration Guide

## How to Submit URLs/Domains for Analysis

There are **two entry points** depending on whether you want to include CT-Watcher and DNSTwist processing:

### Option A: Full Pipeline - Kafka Topic `raw.hosts` (Recommended)

Submit to **`raw.hosts`** to go through the **complete pipeline including CT-Watcher and DNSTwist**.

**Full Pipeline Flow**:
```
Frontend → raw.hosts → Normalizer → DNS Collector → HTTP Fetcher → URL Router → Feature Crawler → ChromaDB
```

**Use this when**:
- ✅ Submitting seed domains for permutation generation
- ✅ You want DNSTwist to generate typosquatting variants
- ✅ First-time brand monitoring setup
- ✅ You want CT-Watcher to monitor certificate transparency logs

**Example**: Submit `sbi.co.in` → DNSTwist generates `sbi-online.com`, `sbii.co.in`, etc.

### Option B: Direct to DNS Collector - Kafka Topic `domains.candidates` ⚡

Submit to **`domains.candidates`** to **skip CT-Watcher and DNSTwist** and go directly to DNS enrichment.

**Direct Flow**:
```
Frontend → domains.candidates → DNS Collector → HTTP Fetcher → URL Router → Feature Crawler → ChromaDB
```

**Use this when**:
- ✅ Analyzing a specific suspicious URL/domain reported by a user
- ✅ You already have the exact domain and don't need variants
- ✅ Faster processing (skips Normalizer deduplication and DNSTwist)
- ✅ Re-analyzing a domain that was already processed

**Example**: User reports `fake-sbi-login.com` → Analyze this exact domain immediately

---

## Which Entry Point Should I Use?

| Scenario | Entry Point | Reason |
|----------|-------------|--------|
| User reports suspicious URL | `domains.candidates` | Direct analysis, no need for variants |
| Monitoring a brand (e.g., "SBI") | `raw.hosts` | Generate typosquatting variants |
| Re-scanning an existing domain | `domains.candidates` | Skip deduplication cache |
| Bulk upload of specific domains | `domains.candidates` | Faster, no permutation overhead |
| Initial seed domain setup | `raw.hosts` | Full pipeline with DNSTwist |

---

## Implementation Options

### Option 1: Direct Kafka Producer (Recommended for Backend)

If your frontend has a backend API, use a Kafka producer:

#### A) Submit to `raw.hosts` (Full Pipeline)

```python
from kafka import KafkaProducer
import json
import time

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

def submit_domain_full_pipeline(domain_or_url):
    """Submit a domain or URL for FULL analysis (includes DNSTwist)"""

    # Extract domain from URL if needed
    if domain_or_url.startswith('http'):
        from urllib.parse import urlparse
        domain = urlparse(domain_or_url).hostname
    else:
        domain = domain_or_url.strip()

    message = {
        "fqdn": domain,
        "source": "frontend_submission",
        "timestamp": int(time.time())
    }

    producer.send('raw.hosts', value=message)
    producer.flush()

    return {"status": "submitted", "domain": domain, "pipeline": "full"}

# Example usage
submit_domain_full_pipeline("sbi.co.in")  # Will generate variants
```

#### B) Submit to `domains.candidates` (Skip to DNS Collector) ⚡

```python
def submit_domain_direct(domain_or_url, cse_id=None):
    """Submit a domain or URL DIRECTLY to DNS Collector (skips CT-Watcher/DNSTwist)"""

    # Extract domain from URL if needed
    if domain_or_url.startswith('http'):
        from urllib.parse import urlparse
        domain = urlparse(domain_or_url).hostname
    else:
        domain = domain_or_url.strip()

    message = {
        "fqdn": domain,
        "canonical_fqdn": domain,
        "registrable": domain,  # Will be normalized by DNS collector
        "source": "frontend_direct_submission",
        "cse_id": cse_id,
        "timestamp": int(time.time())
    }

    producer.send('domains.candidates', value=message)
    producer.flush()

    return {"status": "submitted", "domain": domain, "pipeline": "direct"}

# Example usage
submit_domain_direct("fake-sbi-login.com", cse_id="SBI")  # Analyze this specific domain
submit_domain_direct("https://phishing-site.co.in/login")  # Direct from URL
```

### Option 2: REST API Endpoint

Create a simple API endpoint that your frontend can POST to:

```python
from flask import Flask, request, jsonify
from kafka import KafkaProducer
import json
import time

app = Flask(__name__)

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

@app.route('/api/submit-domain', methods=['POST'])
def submit_domain():
    """
    Submit a domain or URL for phishing analysis

    Request body:
    {
        "url": "https://suspicious-site.com",
        "cse_id": "SBI",           # Optional: brand identifier
        "notes": "Reported by user",  # Optional
        "pipeline": "direct"       # Optional: "full" or "direct" (default: "direct")
    }

    Pipeline options:
    - "full": raw.hosts → Normalizer → DNSTwist (generates variants) → DNS Collector...
    - "direct": domains.candidates → DNS Collector directly (faster, no variants)
    """
    data = request.get_json()
    url_or_domain = data.get('url') or data.get('domain')

    if not url_or_domain:
        return jsonify({"error": "Missing 'url' or 'domain' field"}), 400

    pipeline_mode = data.get('pipeline', 'direct')  # Default to direct

    # Extract domain
    if url_or_domain.startswith('http'):
        from urllib.parse import urlparse
        domain = urlparse(url_or_domain).hostname
    else:
        domain = url_or_domain.strip()

    # Choose pipeline
    if pipeline_mode == 'full':
        # Full pipeline (includes DNSTwist)
        topic = 'raw.hosts'
        message = {
            "fqdn": domain,
            "source": "frontend_submission",
            "cse_id": data.get('cse_id'),
            "notes": data.get('notes'),
            "timestamp": int(time.time())
        }
        processing_time = "3-5 minutes (includes variant generation)"
    else:
        # Direct to DNS Collector (skip CT-Watcher/DNSTwist)
        topic = 'domains.candidates'
        message = {
            "fqdn": domain,
            "canonical_fqdn": domain,
            "registrable": domain,
            "source": "frontend_direct_submission",
            "cse_id": data.get('cse_id'),
            "notes": data.get('notes'),
            "timestamp": int(time.time())
        }
        processing_time = "2-3 minutes (direct analysis)"

    # Send to Kafka
    producer.send(topic, value=message)
    producer.flush()

    return jsonify({
        "status": "submitted",
        "domain": domain,
        "pipeline": pipeline_mode,
        "kafka_topic": topic,
        "message": f"Domain submitted for analysis. Expected processing time: {processing_time}"
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### Frontend JavaScript Example

```javascript
// React/Vue/Plain JS example

// Option 1: Direct pipeline (default) - Skip CT-Watcher/DNSTwist
async function submitDomainDirect(url, cseId = 'SBI') {
    try {
        const response = await fetch('http://localhost:5000/api/submit-domain', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: url,
                cse_id: cseId,
                notes: 'User reported suspicious link',
                pipeline: 'direct'  // Skip to DNS Collector
            })
        });

        const result = await response.json();

        if (response.ok) {
            console.log('✅ Domain submitted:', result.domain);
            console.log(`⚡ Pipeline: ${result.pipeline}, Topic: ${result.kafka_topic}`);
            alert(`${result.domain} submitted! ${result.message}`);
        } else {
            console.error('❌ Submission failed:', result.error);
        }
    } catch (error) {
        console.error('Network error:', error);
    }
}

// Option 2: Full pipeline - Include DNSTwist variant generation
async function submitDomainFull(url, cseId = 'SBI') {
    try {
        const response = await fetch('http://localhost:5000/api/submit-domain', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: url,
                cse_id: cseId,
                notes: 'Seed domain for variant generation',
                pipeline: 'full'  // Include DNSTwist
            })
        });

        const result = await response.json();

        if (response.ok) {
            console.log('✅ Seed domain submitted:', result.domain);
            alert(`${result.domain} submitted! ${result.message}`);
        }
    } catch (error) {
        console.error('Network error:', error);
    }
}

// Usage examples
submitDomainDirect('https://fake-sbi-login.com');  // Analyze this specific URL
submitDomainFull('sbi.co.in');  // Generate variants like sbi-online.com, sbii.co.in
```

---

## Pipeline Comparison Summary

| Feature | `raw.hosts` (Full) | `domains.candidates` (Direct) ⚡ |
|---------|-------------------|----------------------------------|
| **Entry Point** | Very beginning | After Normalizer |
| **Includes DNSTwist** | ✅ Yes | ❌ No |
| **Includes CT-Watcher** | ✅ Yes | ❌ No |
| **Generates Variants** | ✅ Yes (typosquatting) | ❌ No |
| **Redis Deduplication** | ✅ Yes | ❌ Skipped |
| **Processing Time** | 3-5 minutes | 2-3 minutes |
| **Best For** | Seed domains, brand monitoring | User-reported URLs, specific domains |
| **Kafka Topic** | `raw.hosts` | `domains.candidates` |

---

## Message Formats

### Format for `raw.hosts` (Full Pipeline)

**Minimal Format:**
```json
{
    "fqdn": "suspicious-domain.com"
}
```

**Recommended Format:**
```json
{
    "fqdn": "suspicious-domain.com",
    "source": "frontend_submission",
    "cse_id": "SBI",
    "timestamp": 1704067200,
    "notes": "User reported via contact form",
    "submitter_ip": "192.168.1.100"
}
```

### Format for `domains.candidates` (Direct Pipeline) ⚡

**Minimal Format:**
```json
{
    "fqdn": "fake-sbi-login.com",
    "canonical_fqdn": "fake-sbi-login.com",
    "registrable": "fake-sbi-login.com"
}
```

**Recommended Format:**
```json
{
    "fqdn": "fake-sbi-login.com",
    "canonical_fqdn": "fake-sbi-login.com",
    "registrable": "fake-sbi-login.com",
    "source": "frontend_direct_submission",
    "cse_id": "SBI",
    "timestamp": 1704067200,
    "notes": "User reported suspicious link"
}
```

### Field Descriptions

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `fqdn` | ✅ Yes | string | Domain name (e.g., "example.com") |
| `canonical_fqdn` | For `domains.candidates` | string | Normalized FQDN (usually same as fqdn) |
| `registrable` | For `domains.candidates` | string | Registrable domain (eTLD+1) |
| `source` | No | string | Source identifier (e.g., "frontend", "api") |
| `cse_id` | No | string | Brand identifier (e.g., "SBI", "ICICI") |
| `timestamp` | No | int | Unix timestamp of submission |
| `notes` | No | string | Additional context or metadata |
| `submitter_ip` | No | string | IP address of submitter (for logging) |

---

## Processing Timeline

### Full Pipeline (`raw.hosts`):

| Stage | Duration | Description |
|-------|----------|-------------|
| **Normalizer** | <1 sec | Deduplicates and extracts registrable domain |
| **DNS Collector** | 5-10 sec | DNS resolution, WHOIS lookup, GeoIP enrichment |
| **HTTP Fetcher** | 10-30 sec | HTTP/HTTPS probing, SSL certificate analysis |
| **URL Router** | <1 sec | Filters URLs ready for crawling |
| **Feature Crawler** | 30-60 sec | Screenshot, HTML analysis, JavaScript detection |
| **ChromaDB Ingestor** | <5 sec | Store in vector database |

**Total Time**: ~3-5 minutes (includes variant generation)

### Direct Pipeline (`domains.candidates`): ⚡

| Stage | Duration | Description |
|-------|----------|-------------|
| **DNS Collector** | 5-10 sec | DNS resolution, WHOIS lookup, GeoIP enrichment |
| **HTTP Fetcher** | 10-30 sec | HTTP/HTTPS probing, SSL certificate analysis |
| **URL Router** | <1 sec | Filters URLs ready for crawling |
| **Feature Crawler** | 30-60 sec | Screenshot, HTML analysis, JavaScript detection |
| **ChromaDB Ingestor** | <5 sec | Store in vector database |

**Total Time**: ~2-3 minutes (skips Normalizer and DNSTwist)

---

## Checking Submission Status

To check if a domain has been processed, query ChromaDB (see CHROMADB_QUERY_GUIDE.md):

```python
# Check if domain exists in ChromaDB
collection = client.get_collection("domains")

results = collection.get(
    ids=["suspicious-domain.com"]  # Use registrable domain as ID
)

if results['ids']:
    print("✅ Domain has been processed!")
    print(results['metadatas'][0])
else:
    print("⏳ Domain still processing or not found")
```

---

## Docker Compose Setup

Add the REST API service to your `docker-compose.yml`:

```yaml
services:
  frontend-api:
    build: ./apps/frontend-api
    ports:
      - "5000:5000"
    environment:
      - KAFKA_BOOTSTRAP_SERVERS=kafka:9092
      - KAFKA_TOPIC=raw.hosts
    depends_on:
      - kafka
    restart: unless-stopped
```

---

## Security Considerations

### 1. Rate Limiting
Implement rate limiting to prevent abuse:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/submit-domain', methods=['POST'])
@limiter.limit("10 per minute")  # 10 submissions per minute per IP
def submit_domain():
    # ... your code
```

### 2. Input Validation
Always validate domains:

```python
import re

def is_valid_domain(domain):
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def submit_domain():
    domain = extract_domain(data.get('url'))

    if not is_valid_domain(domain):
        return jsonify({"error": "Invalid domain format"}), 400

    # Proceed with submission...
```

### 3. Authentication (Optional)
For production, add API key authentication:

```python
@app.route('/api/submit-domain', methods=['POST'])
def submit_domain():
    api_key = request.headers.get('X-API-Key')

    if api_key != os.getenv('VALID_API_KEY'):
        return jsonify({"error": "Invalid API key"}), 401

    # Proceed...
```

---

## Troubleshooting

### Issue: Domain not appearing in ChromaDB

**Possible causes**:
1. ❌ Domain doesn't resolve (no DNS records) → Check `domains.resolved` topic
2. ❌ HTTP fetcher couldn't connect → Check `http.probed` topic
3. ❌ Already in Redis cache (recently processed) → Normalizer skipped it
4. ❌ Failed during crawling → Check `phish.urls.failed` topic

**Solution**: Check Kafka topics to see where the domain stopped:

```bash
# Check if domain reached normalizer
docker exec -it kafka kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic domains.candidates \
  --from-beginning | grep "your-domain.com"

# Check if domain was enriched
docker exec -it kafka kafka-console-consumer.sh \
  --bootstrap-server localhost:9092 \
  --topic domains.resolved \
  --from-beginning | grep "your-domain.com"
```

### Issue: Submission seems slow

**Solution**: Check service logs:

```bash
# Check normalizer logs
docker logs normalizer --tail=50

# Check DNS collector logs
docker logs dns-collector --tail=50

# Check feature crawler logs
docker logs feature-crawler --tail=50
```

---

## Example: Complete Frontend Flow

```javascript
// 1. User submits URL via form
document.getElementById('submit-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const url = document.getElementById('url-input').value;

    // 2. Show loading state
    showLoading('Submitting domain for analysis...');

    // 3. Submit to API
    const result = await submitDomain(url);

    if (result.status === 'submitted') {
        // 4. Poll for results
        showLoading(`Analyzing ${result.domain}... (this may take 2-5 minutes)`);

        setTimeout(async () => {
            // 5. Query ChromaDB for results
            const analysis = await queryDomainResults(result.domain);

            // 6. Display results
            displayResults(analysis);
        }, 120000);  // Wait 2 minutes before checking
    }
});

async function queryDomainResults(domain) {
    const response = await fetch(`http://localhost:8000/api/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            query: domain,
            where: { "registrable": domain }
        })
    });

    return await response.json();
}
```

---

## Next Steps

1. ✅ Implement the REST API endpoint
2. ✅ Test submission with sample domains
3. ✅ Integrate with your frontend UI
4. ✅ Set up monitoring for failed submissions
5. 📖 Read [CHROMADB_QUERY_GUIDE.md](CHROMADB_QUERY_GUIDE.md) to query results
