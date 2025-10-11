# Phishing Detection Pipeline - System Overview

## What We Built

A **real-time domain monitoring and analysis pipeline** designed to detect potential phishing domains targeting specific brands (like SBI Bank). The system ingests domains from multiple sources, enriches them with DNS/WHOIS/GeoIP data, and stores them in a vector database for semantic search and analysis.

---

## System Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│  CT-Watcher     │────▶│    Kafka     │────▶│   Normalizer    │
│ (Certstream)    │     │  Message Bus │     │ (Deduplication) │
└─────────────────┘     └──────────────┘     └─────────────────┘
                              │                        │
┌─────────────────┐           │                        ▼
│ DNSTwist Runner │───────────┘              ┌─────────────────┐
│ (Permutations)  │                          │ DNS Collector   │
└─────────────────┘                          │ (DNS/WHOIS/Geo) │
                                             └─────────────────┘
                                                      │
                                             ┌────────┴─────────┐
                                             ▼                  ▼
                                    ┌─────────────────┐  ┌─────────────┐
                                    │ HTTP Fetcher    │  │ ChromaDB    │
                                    │ (SSL/HTTP Probe)│  │ Ingestor    │
                                    └─────────────────┘  └─────────────┘
                                             │                  │
                                             ▼                  │
                                    ┌─────────────────┐         │
                                    │  URL Router     │         │
                                    │ (Filter URLs)   │         │
                                    └─────────────────┘         │
                                             │                  │
                                             ▼                  │
                                    ┌─────────────────┐         │
                                    │Feature Crawler  │         │
                                    │ (Screenshots,   │─────────┘
                                    │  Features, JS)  │
                                    └─────────────────┘
                                             │
                                             ▼
                                      ┌─────────────┐
                                      │  ChromaDB   │
                                      │Vector Store │
                                      └─────────────┘
```

---

## Components Breakdown

### 1. **Data Sources**

#### **CT-Watcher** (Certificate Transparency Monitor)
- **What it does**: Listens to real-time certificate transparency logs via CertStream
- **How it works**: 
  - Connects to `wss://certstream.calidog.io/`
  - Filters certificates for domains matching seed patterns (e.g., "sbi", "sbicard")
  - Extracts domain names from certificates
- **Output**: Publishes raw domain names to Kafka topic `raw.hosts`

#### **DNSTwist Runner**
- **What it does**: Generates domain permutations/typosquatting variants
- **How it works**:
  - Takes seed domains from config (e.g., `sbi.co.in`, `sbicard.com`)
  - Generates variations: homoglyphs, additions, omissions, transpositions
  - Examples: `sbl.co.in`, `sbii.co.in`, `sbi-online.com`
- **Output**: Publishes permuted domains to `raw.hosts`

### 2. **Processing Pipeline**

#### **Kafka** (Message Bus)
- **Role**: Central nervous system of the pipeline
- **Topics**:
  - `raw.hosts` - Unprocessed domain names
  - `domains.candidates` - Deduplicated, normalized domains
  - `domains.resolved` - Fully enriched domains with DNS/WHOIS/GeoIP
  - `http.probed` - HTTP/SSL probing results
  - `phish.urls.crawl` - URLs ready for feature extraction
  - `phish.features.page` - Extracted page features
  - `phish.urls.failed` - Dead letter queue for failed crawls
- **Why Kafka**: Decouples services, enables replay, handles backpressure

#### **Redis**
- **Role**: Deduplication cache
- **Usage**: Stores seen domains with TTL (120 days) to prevent reprocessing

#### **Unbound**
- **Role**: Local recursive DNS resolver
- **Why needed**: Fast, reliable DNS lookups without external rate limits

### 3. **Enrichment Services**

#### **Normalizer**
- **What it does**: Cleans and deduplicates domains
- **Process**:
  1. Extracts FQDN and registrable domain
  2. Checks Redis cache (skip if seen recently)
  3. Adds metadata (CSE ID, seed domain, reasons)
  4. Publishes to `domains.candidates`

#### **DNS Collector** (Enhanced)
- **What it does**: Enriches domains with network intelligence
- **Data collected**:
  - **DNS Records**: A, AAAA, CNAME, MX, NS, TXT
  - **WHOIS**: Registrar, creation date, expiry, domain age
    - ✨ **NEW**: Domain age detection (< 7 days, < 30 days flags)
    - ✨ **NEW**: Days until expiry calculation
  - **GeoIP**: Country, city, coordinates
  - **ASN**: Autonomous System Number, organization
  - **RDAP**: Extended registry data
  - **NS Features**: Nameserver patterns, entropy analysis
- **Concurrency**: Limited to 50 concurrent lookups (prevents crashes)
- **File Safety**: Async locks prevent corruption
- **Output**: Publishes enriched records to `domains.resolved`

#### **HTTP Fetcher** (Enhanced)
- **What it does**: Probes domains via HTTP/HTTPS with deep SSL analysis
- **Data collected**:
  - Response codes, redirects
  - Page titles, body content
  - ✨ **NEW**: Comprehensive SSL certificate analysis
    - Self-signed detection
    - Certificate age (< 7 days, < 30 days)
    - Domain mismatch detection
    - Trusted CA validation
    - Certificate risk scoring
  - Response times
- **Output**: Publishes to `http.probed`

#### **URL Router** (New)
- **What it does**: Filters and routes valid HTTP URLs for feature extraction
- **Filters**: Only routes URLs that successfully responded to HTTP probe
- **Output**: Publishes to `phish.urls.crawl`

#### **Feature Crawler** (New) ✨
- **What it does**: Deep analysis of webpage content and behavior
- **Capabilities**:
  - **Redirect Tracking**: Full chain tracking (HTTP + JS redirects)
  - **Screenshot Capture**: Full-page screenshots of final destination
  - **PDF Generation**: Archival PDF of final page
  - **Favicon Hashing**: MD5/SHA256 for brand impersonation detection
  - **Enhanced Form Analysis**:
    - Detects forms submitting to IP addresses
    - Flags suspicious TLDs (.tk, .ml, .ga, .xyz, etc.)
    - Identifies localhost/private IP submissions
  - **JavaScript Analysis**:
    - Obfuscation detection (eval, atob, fromCharCode)
    - Keylogger pattern detection
    - Form manipulation detection
    - Redirect script detection
  - **Feature Extraction**:
    - URL structure (length, entropy, subdomains, special chars)
    - IDN/homograph detection
    - HTML content analysis
    - External links, iframes, scripts
- **Retry Logic**: 3 attempts with dead letter queue for failures
- **Output**: Publishes to `phish.features.page` and `phish.urls.failed`

### 4. **Storage & Search**

#### **ChromaDB Ingestor** (Enhanced)
- **What it does**: Converts enriched domain + feature data into searchable vectors
- **Process**:
  1. Consumes from Kafka (`domains.resolved` AND `phish.features.page`)
  2. ✨ **NEW**: Merges domain and feature data by registrable domain
  3. Transforms JSON records into dense text representations
  4. Generates embeddings using `sentence-transformers/all-MiniLM-L6-v2`
  5. Upserts into ChromaDB with 30+ metadata fields
- **Merging Strategy**: Uses tldextract for consistent registrable domain extraction
- **Batching**: Processes 128 documents at a time for efficiency

#### **ChromaDB Vector Database** (Enhanced)
- **What it stores**:
  - **Documents**: Unified text representations of domain + webpage intelligence
  - **Embeddings**: 384-dimensional vectors
  - **Metadata** (30+ fields):
    - **Domain Age**: domain_age_days, is_newly_registered, is_very_new
    - **SSL**: is_self_signed, cert_age_days, trusted_issuer, cert_risk_score
    - **Forms**: has_credential_form, suspicious_form_count, has_suspicious_forms
    - **JavaScript**: js_obfuscated, js_keylogger, js_risk_score
    - **Favicon**: favicon_md5, favicon_sha256
    - **Redirects**: redirect_count, had_redirects
    - **Traditional**: CSE ID, registrable domain, country, registrar, etc.
- **Capabilities**:
  - Semantic search ("find domains similar to phishing patterns")
  - Similarity matching (cosine distance)
  - ✨ **NEW**: Advanced metadata filtering (combine multiple risk indicators)
- **Persistence**: Data stored in `/volumes/chroma`

---

## Data Flow Example

Let's trace a suspicious domain through the system:

### **Input**: Certificate for `sbi-secure-login.com` detected

```
1. CT-Watcher
   ├─ Receives cert from CertStream
   ├─ Matches pattern "sbi"
   └─ Publishes: {"host": "sbi-secure-login.com", "reasons": ["ct_match"], "cse_id": "SBI"}
              ↓
2. Normalizer (via Kafka: raw.hosts)
   ├─ Extracts: FQDN=sbi-secure-login.com, registrable=sbi-secure-login.com
   ├─ Checks Redis: Not seen before
   ├─ Adds: seed_registrable=sbi.co.in, timestamp
   └─ Publishes to: domains.candidates
              ↓
3. DNS Collector (via Kafka: domains.candidates)
   ├─ Queries DNS:
   │  ├─ A: 185.234.219.123
   │  ├─ MX: mail.sbi-secure-login.com
   │  └─ NS: ns1.malicious-hosting.ru
   ├─ WHOIS: Registrar=Namecheap, Created=2025-10-01
   ├─ GeoIP: Russia, Moscow
   ├─ ASN: AS12345 (SuspiciousHosting LLC)
   └─ Publishes to: domains.resolved
              ↓
4. HTTP Fetcher (via Kafka: domains.resolved)
   ├─ GET https://sbi-secure-login.com
   ├─ Response: 200 OK
   ├─ Title: "State Bank of India - Secure Login"
   ├─ Body contains: login form, SBI logos
   └─ Publishes to: http.probed
              ↓
5. ChromaDB Ingestor (via Kafka: domains.resolved)
   ├─ Transforms to text:
   │  "Domain: sbi-secure-login.com
   │   Registrable: sbi-secure-login.com
   │   Brand/CSE: SBI (seed: sbi.co.in)
   │   Reasons: ct_match
   │   DNS -> A: 185.234.219.123 MX: mail.sbi-secure-login.com NS: ns1.malicious-hosting.ru
   │   WHOIS -> Registrar: Namecheap Created: 2025-10-01
   │   Network -> ASN: AS12345 SuspiciousHosting LLC
   │   Geo -> Russia / Moscow"
   ├─ Generates embedding (384-dim vector)
   └─ Upserts to ChromaDB
              ↓
6. ChromaDB Vector Store
   └─ Now searchable via semantic queries
```

---

## Key Features

### **Real-Time Detection**
- Processes domains within seconds of certificate issuance
- Kafka streaming enables sub-second latency

### **Multi-Source Intelligence**
- Certificate Transparency logs (passive monitoring)
- DNSTwist permutations (proactive generation)

### **Rich Enrichment**
- DNS records reveal infrastructure patterns
- WHOIS shows registration timelines
- GeoIP identifies hosting locations
- ASN reveals network providers

### **Semantic Search**
- Vector embeddings enable similarity matching
- Query: "Russian hosting with recent registration" finds relevant domains
- No exact keyword matching needed

### **Deduplication**
- Redis cache prevents reprocessing
- 120-day TTL balances freshness vs. efficiency

### **Scalability**
- Kafka handles 1000s of messages/sec
- Parallel consumers (12 DNS workers, 20 HTTP workers)
- ChromaDB HNSW index enables fast search at scale

---

## Use Cases

### 1. **Threat Hunting**
```python
# Find domains similar to known phishing
collection.query("phishing login page SBI bank credentials")
```

### 2. **Brand Monitoring**
```python
# Find all domains mentioning a brand
collection.get(where={"cse_id": "SBI"})
```

### 3. **Infrastructure Analysis**
```python
# Find domains on suspicious hosting
collection.query("Russia Namecheap recent registration")
```

### 4. **Pattern Detection**
```python
# Find lookalike domains
collection.query("sbi secure login online banking")
```

---

## Configuration Files

- **`cse_seeds.csv`**: Brand seeds (sbi.co.in, sbicard.com, etc.)
- **`unbound.conf`**: DNS resolver config
- **`docker-compose.yml`**: Service orchestration
- **GeoIP databases**: `GeoLite2-City.mmdb`, `GeoLite2-ASN.mmdb`

---

## Output Formats

All services write JSONL files to `/out` directory:
- `domains_candidates_*.jsonl`
- `domains_resolved_*.jsonl`
- `http_probed_*.jsonl`

These serve as:
- Backup/audit trail
- Batch reprocessing source
- Forensic analysis data

---