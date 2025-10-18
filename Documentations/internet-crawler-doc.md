# Phishing Detection Pipeline - System Overview

---

## System Architecture

```
               ┌─────────────────────────────────────────────────────────────────┐
               │                     USER SUBMITS DOMAIN                         │
               │                   (via Frontend or API)                         │
               └────────────────────────────┬────────────────────────────────────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │  raw.hosts   │ (Kafka Topic)
                                     │    topic     │
                                     └──────┬───────┘
                                            │
                                   ┌────────┴────────┐
                                   │                 │
                                   ▼                 ▼
                         ┌──────────────────┐  ┌──────────────┐
                         │   DNSTwist       │  │  CT-Watcher  │
                         │   Tracks:        │  │  (monitors   │
                         │   • Registered   │  │   certstream)│ 
                         │    • Unregistered│  │              │ 
                         └────────┬─────────┘  └──────┬───────┘
                                  │                   │
                     ┌────────────┴──────┐            │
                     │                   │            │
                     ▼                   ▼            ▼
                 Generates          Publishes     Publishes
                 variants:          variants       matching
                 - myvi.in          back to     certificates
                 - my-vi.in         raw.hosts      to raw.hosts
                 - myvii.in            │               │
                 - myv1.in             └───────┬───────┘
                 - etc.                        │
                                               ▼
                                        ┌──────────────┐
                                        │  raw.hosts   │ (now contains original + variants)
                                        │    topic     │
                                        └──────┬───────┘
                                               │
                                               ▼
                                        ┌──────────────┐     
                                        │    Kafka     │
                                        │  Message Bus │
                                        └──────┬───────┘
                                               │
                                               ▼
                                        ┌──────────────┐
                                        │  Normalizer  │ (dedup + extract registrable)
                                        └──────┬───────┘
                                               │
                                               ▼
                                        ┌──────────────┐
                                        │ DNS Collector│ (DNS/WHOIS/GeoIP/Domain Age)
                                        │  x3 REPLICAS │
                                        └──────┬───────┘
                                               │
                                               ▼
                                        ┌─────────────────┐
                                        │ HTTP Fetcher    │
             ┌──────────────────────────│ (SSL/HTTP Probe)│
             │                          └─────────────────┘
             │                                    │
             │                          ┌─────────┴─────────┐
             │                          ▼                   ▼
             │                 ┌─────────────────┐ [http.probed topic]
             │                 │  URL Router     │
             │                 │                 │
             │                 │ Routes:         │
             │                 │ • Active → Crawl│
             │                 │ • Inactive→Queue│
             │                 └─────────────────┘
             │                          │
             │                ┌─────────┴─────────┐
             │                ▼                   ▼
             │       ┌──────────────────┐    [phish.urls.inactive] 
             │       │ Feature Crawler  │             │
             │       │   x3 REPLICAS    │             │
             │       │ (Screenshots,    │             │
             │       │  Features, JS)   │             │
             │       └──────────────────┘             │
             │                │                       │
             │                ▼                       │
             │       ┌──────────────┐                 │
             │       │  Rule Scorer │                 │
             │       │(Risk Analysis)│                │
             │       └──────────────┘                 │
             │                │                       │
             │                ▼                       │
             │       [phish.rules.verdicts]           │
             │                │                       │
             │                ▼                       ▼
             │       ┌────────────────────────────────────────┐
             │       │          Monitor Scheduler             │ 
             │       │                                        │
             │       │         Monitors:                      │
             │       │         • Suspicious/Parked (90d)      │
             │       │         • Inactive (7/30/90d)          │
             └───────│         • Unregistered (30/90/180d)    │
                     └────────────────────────────────────────┘
                                            │
                                            ▼
                                 ┌───────────────────────┐
                                 │   ChromaDB            │
                                 │   Ingestor            │
                                 │                       │
                                 │   Consumes 5 topics:  │
                                 │   1. domains.resolved │
                                 │   2. features.page    │
                                 │   3. urls.failed      │
                                 │   4. rules.verdicts   │
                                 │   5. urls.inactive    │
                                 └───────────────────────┘
                                            │
                                            ▼
                                 ┌────────────────────┐
                                 │   ChromaDB         │
                                 │   Vector Store     │
                                 │                    │
                                 │   6 Record Types:  │
                                 │   • fully_enriched │
                                 │   • with_features  │
                                 │   • verdict_only   │
                                 │   • domain_only    │
                                 │   • features_only  │
                                 │   • inactive       │
                                 └────────────────────┘
```

---

## Components Breakdown

### 1. **Data Sources**

#### **CT-Watcher** (Certificate Transparency Monitor)
- **What it does**: Listens to real-time certificate transparency logs via CertStream
- **How it works**:
  - Connects to `wss://certstream.calidog.io/`
  - Uses **intelligent token matching** with 5 rules:
    1. **Exact match**: Domain exactly matches brand token (e.g., "sbi")
    2. **LD1 match**: 1 character difference for typosquatting (e.g., "rctc" → "irctc")
    3. **Word match**: Brand appears with separators (e.g., "sbi-login", "my-sbi")
    4. **Prefix match**: Brand at start with separator/digit (e.g., "sbi123")
    5. **Suffix match**: Brand at end with separator/digit (e.g., "secure-sbi")
  - Filters out generic words (mail, login, secure) to reduce false positives
  - Extracts domain names from certificates
- **Output**: Publishes matching domains to Kafka topic `raw.hosts` with CSE ID and reasons
- **Match Mode**: `seed` (only emits brand-matching domains, not all certificates)

#### **DNSTwist Runner**
- **What it does**: Generates domain permutations/typosquatting variants
- **How it works**:
  - **Startup Mode**: Processes seed domains from CSV (`cse_seeds.csv`)
    - Runs 3-pass comprehensive analysis:
      - **PASS_A**: 12 fuzzers + common TLDs (comprehensive)
      - **PASS_B**: 8 fuzzers + India TLDs (regional focus)
      - **PASS_C**: 4 fuzzers + high-risk dictionary (phishing patterns)
  - **Continuous Mode**: Listens to `raw.hosts` for user/CT submissions
    -  **NEW**: Processes **full domain** (not just registrable domain)
    -  **NEW**: Uses same 3-pass analysis as CSV seeds
    - Example: `nic.gov.in` → generates variants of `nic.gov.in` (not just `gov.in`)
  - Generates variations: homoglyphs, additions, omissions, transpositions
  - Only emits **registered domains** (DNS resolution check)
- **Output**: Publishes variants to `raw.hosts` with pass labels (PASS_A/B/C)
- **Deduplication**: Tracks processed domains to avoid re-processing
- **Performance**: 16 parallel threads, skips already-processed domains

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
  - `phish.rules.verdicts` - Risk scoring verdicts 
  - `phish.urls.failed` - Dead letter queue for failed crawls
- **Why Kafka**: Decouples services, enables replay, handles backpressure

#### **Redis**
- **Roles**:
  1. **Deduplication cache**: Stores seen domains with TTL (120 days) to prevent reprocessing
  2. **Monitoring queue** : Tracks domains requiring 90-day re-evaluation
- **Keys**:
  - `first_seen:{fqdn}` - Deduplication timestamps
  - `monitoring:queue` - Sorted set of monitored domains
  - `monitoring:meta:{domain}` - Monitoring metadata (verdict, reason, recheck_count)

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

#### **DNS Collector**
- **What it does**: Enriches domains with network intelligence
- **Data collected**:
  - **DNS Records**: A, AAAA, CNAME, MX, NS, TXT
  - **WHOIS**: Registrar, creation date, expiry, domain age
    -  **NEW**: Domain age detection (< 7 days, < 30 days flags)
    -  **NEW**: Days until expiry calculation
  - **GeoIP**: Country, city, coordinates
  - **ASN**: Autonomous System Number, organization
  - **RDAP**: Extended registry data
  - **NS Features**: Nameserver patterns, entropy analysis
- **Scaling**: 3 replicas for horizontal scaling (3x throughput)
- **Per-Instance Concurrency**:
  - 12 worker threads
  - 50 concurrent DNS queries
  - 4 WHOIS workers (rate-limited)
- **Total Capacity**: 36 workers, 150 concurrent DNS queries, 12 WHOIS workers
- **Load Balancing**: Kafka consumer group distributes work across all replicas
- **File Safety**: Async locks prevent corruption
- **Output**: Publishes enriched records to `domains.resolved`

#### **HTTP Fetcher** 
- **What it does**: Probes domains via HTTP/HTTPS with deep SSL analysis
- **Data collected**:
  - Response codes, redirects
  - Page titles, body content
  -  **NEW**: Comprehensive SSL certificate analysis
    - Self-signed detection
    - Certificate age (< 7 days, < 30 days)
    - Domain mismatch detection
    - Trusted CA validation
    - Certificate risk scoring
  - Response times
- **Output**: Publishes to `http.probed`

#### **URL Router** 
- **What it does**: Filters and routes valid HTTP URLs for feature extraction
- **Filters**: Only routes URLs that successfully responded to HTTP probe
- **Output**: Publishes to `phish.urls.crawl`

#### **Feature Crawler** 
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

#### **Rule Scorer**
- **What it does**: Brand-agnostic risk scoring engine that analyzes domains for phishing indicators
- **Scoring Categories**:
  - **WHOIS**: Domain age (<7d: +25, <30d: +12), expiry proximity
  - **URL Features**: Length, entropy, subdomains, repeated digits, IDN/punycode
  - **TLS/SSL**: Self-signed (+40), domain mismatch (+25), new certificates
  - **Forms**: Credential harvesting (+22), suspicious forms (+18), submit to IPs (+10)
  - **Content**: Phishing keywords (8+ keywords: +18), redirects crossing domains (+12)
  - **Parked Detection**: Minimal content, no forms, no external links
- **Verdict Types**:
  - `phishing` (score ≥70): High-confidence phishing
  - `suspicious` (score 40-69): Requires monitoring
  - `parked` (score <35, parked indicators): New domains with no content
  - `benign` (score <40): Legitimate/safe
- **Enhanced Features**:
  - Established domains (>1 year) exempt from parked classification
  - Detailed reason generation for all verdicts
  - Final verdict separate from monitoring status
- **Output**: Publishes to `phish.rules.verdicts` with metadata
- **Configuration**: Thresholds configurable via env vars

#### **Monitor Scheduler** 
- **What it does**: Tracks suspicious/parked domains for 90-day re-evaluation
- **Monitoring Logic**:
  - Domains flagged as `suspicious` or `parked` (if new) → added to monitoring queue
  - Stores metadata in Redis: verdict, reason, first_seen, recheck_count
  - Every 24 hours, checks for expired monitoring periods
  - Re-queues expired domains to `raw.hosts` for full re-crawl
  - Max 3 re-checks per domain
- **Redis Storage**:
  - Sorted set `monitoring:queue` (key: domain, score: monitor_until timestamp)
  - Hash `monitoring:meta:{domain}` (verdict, reason, url, recheck_count)
- **Re-Crawl Process**: Automatically re-submits domains through entire pipeline
- **Configuration**: Monitor days (default: 90), check interval (default: 24h), max rechecks (default: 3)

### 4. **Storage & Search**

#### **ChromaDB Ingestor** 
- **What it does**: Converts enriched domain + feature data into searchable vectors
- **Process**:
  1. Consumes from Kafka (`domains.resolved` AND `phish.features.page`)
  2.  **NEW**: Merges domain and feature data by registrable domain
  3. Transforms JSON records into dense text representations
  4. Generates embeddings using `sentence-transformers/all-MiniLM-L6-v2`
  5. Upserts into ChromaDB with 30+ metadata fields
- **Merging Strategy**: Uses tldextract for consistent registrable domain extraction
- **Batching**: Processes 128 documents at a time for efficiency

#### **ChromaDB Vector Database** 
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
  -  **NEW**: Advanced metadata filtering (combine multiple risk indicators)
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

## Complete Service Breakdown

### Infrastructure Services

#### **Zookeeper**
- **Image**: `confluentinc/cp-zookeeper:7.6.0`
- **Role**: Coordination service for Kafka cluster
- **Why we need it**:
  - Kafka requires Zookeeper for cluster metadata management
  - Handles leader election for Kafka partitions
  - Stores configuration and state for the Kafka broker
  - Manages consumer group offsets (legacy mode)
- **Resources**: Minimal (<100MB RAM)
- **Port**: 2181 (internal only)
- **Health Check**: Verifies TCP connection on port 2181
- **Configuration**:
  - `ZOOKEEPER_CLIENT_PORT=2181`: Client connection port
  - `ZOOKEEPER_TICK_TIME=2000`: Heartbeat interval in milliseconds

**Why Zookeeper matters**: Without Zookeeper, Kafka cannot coordinate distributed operations. It's the brain that keeps Kafka's distributed architecture in sync.

---

#### **Kafka**
- **Image**: `confluentinc/cp-kafka:7.6.0`
- **Role**: Distributed message bus / event streaming platform
- **Why we need it**:
  - **Decouples services**: Each component publishes/subscribes independently
  - **Enables replay**: Can reprocess historical messages for debugging
  - **Handles backpressure**: Buffers messages when consumers are slow
  - **Fault tolerance**: Messages persist even if consumers crash
  - **Scalability**: Supports parallel processing across multiple consumers
- **Resources**: 512MB heap, ~1GB total RAM
- **Port**: 9092 (exposed to host)
- **Topics** (8 total):
  1. `raw.hosts` - Unprocessed domain submissions
  2. `domains.candidates` - Deduplicated domains
  3. `domains.resolved` - DNS/WHOIS enriched domains
  4. `http.probed` - HTTP/SSL probe results
  5. `phish.urls.crawl` - URLs ready for crawling
  6. `phish.features.page` - Extracted features
  7. `phish.rules.verdicts` - Risk scoring results
  8. `phish.urls.failed` - Dead letter queue
- **Health Check**: Lists topics to verify broker is operational
- **Retention**: 168 hours (7 days) of message history
- **Configuration**:
  - `KAFKA_AUTO_CREATE_TOPICS_ENABLE=true`: Topics created on first publish
  - `KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1`: Single broker setup
  - `KAFKA_LOG_RETENTION_HOURS=168`: Keep messages for 7 days

**Why Kafka matters**: The entire pipeline is event-driven. Kafka makes it possible to process millions of domains without losing data, even if individual services crash or restart.

**Example message flow**:
```
CT-Watcher → [raw.hosts] → Normalizer → [domains.candidates] → DNS Collector → [domains.resolved] → ChromaDB
```

---

#### **Redis**
- **Image**: `redis:7`
- **Role**: In-memory key-value store
- **Why we need it**:
  - **Deduplication**: Prevents reprocessing the same domain within 120 days
  - **Monitoring queue**: Tracks domains requiring 90-day re-evaluation
  - **High performance**: Sub-millisecond lookups (1M+ ops/sec)
  - **Persistence**: Data survives restarts (RDB snapshots)
- **Resources**: ~50MB base, scales with data
- **Port**: 6379 (exposed to host)
- **Data structures**:
  - **Strings**: `first_seen:{fqdn}` → timestamp (TTL: 120 days)
  - **Sorted Sets**: `monitoring:queue` → {domain: expiry_timestamp}
  - **Hashes**: `monitoring:meta:{domain}` → {verdict, reason, recheck_count}
- **Health Check**: `redis-cli ping` returns PONG
- **Persistence**: RDB snapshots every 15 minutes

**Why Redis matters**: Without deduplication, the pipeline would waste resources re-crawling known domains. Redis stores 120 days of history using minimal RAM (~100MB for 1M domains).

**Example keys**:
```
first_seen:sbi.solutions → 1728567890
monitoring:queue → {suspicious-site.com: 1735689600}
monitoring:meta:suspicious-site.com → {verdict: "suspicious", recheck_count: "1"}
```

---

#### **Unbound**
- **Image**: `mvance/unbound:latest`
- **Role**: Recursive DNS resolver
- **Why we need it**:
  - **Performance**: Local caching avoids external DNS latency
  - **Rate limits**: Public DNS servers (8.8.8.8) throttle bulk queries
  - **Privacy**: Doesn't leak domain queries to third parties
  - **Reliability**: No dependency on external infrastructure
- **Resources**: ~100MB RAM
- **Port**: 5335:53 (mapped to avoid conflict with host DNS)
- **IP Address**: Fixed at 172.25.0.10 (static assignment)
- **Health Check**: Queries `google.com` to verify resolver works
- **Configuration**: Custom `unbound.conf` for caching and forwarding

**Why Unbound matters**: The DNS Collector makes 50+ concurrent DNS queries. Public resolvers would rate-limit or ban the pipeline. Unbound handles 1000s of queries/second without restrictions.

**Performance**:
- Cold cache: 50-100ms per query (forwards to upstream)
- Warm cache: <1ms per query (local RAM)
- Concurrent: 50+ queries simultaneously

---

#### **ChromaDB**
- **Image**: `ghcr.io/chroma-core/chroma:1.1.0`
- **Role**: Vector database for semantic search
- **Why we need it**:
  - **Semantic search**: Find domains by meaning, not exact keywords
  - **Similarity matching**: Detect domains similar to known phishing
  - **Metadata filtering**: Complex queries (e.g., "new + self-signed cert + credential form")
  - **Embeddings**: Converts text to 384-dim vectors for ML-based search
  - **Persistence**: Stores vectors and metadata on disk
- **Resources**: ~500MB RAM base, scales with data
- **Port**: 8000 (exposed to host)
- **Storage**: `/volumes/chroma` (persistent)
- **Index**: HNSW (Hierarchical Navigable Small World) for fast vector search
- **Collection**: `domains` (default collection name)
- **Features**:
  - Upsert support (merge new data into existing records)
  - Metadata filtering (30+ fields per record)
  - Cosine similarity search
  - Batch operations (128 docs at a time)

**Why ChromaDB matters**: Traditional databases can't answer questions like "find domains similar to this phishing pattern". ChromaDB's vector search enables AI-powered threat detection.

**Example query**:
```python
# Find domains similar to known phishing
collection.query(
    query_texts=["login credential harvesting page with self-signed certificate"],
    n_results=10,
    where={"is_newly_registered": True, "has_credential_form": True}
)
```

---

### Processing Services

#### **CT-Watcher**
- **Build**: `apps/ct-watcher`
- **Role**: Certificate Transparency log monitor
- **Why we need it**:
  - **Real-time detection**: Catches phishing domains within seconds of certificate issuance
  - **Passive monitoring**: No active scanning, uses public CT logs
  - **Brand matching**: Filters for domains matching seed patterns (e.g., "sbi", "icici")
- **Resources**: ~100MB RAM
- **Input**: CertStream WebSocket (`wss://certstream.calidog.io/`)
- **Output**: `raw.hosts` Kafka topic
- **Restart Policy**: `unless-stopped` (auto-restart on failure)
- **Dependencies**: Kafka must be healthy

**Why it matters**: 90% of phishing domains use HTTPS (for browser trust). CT logs capture every SSL certificate, making them perfect for early detection.

---

#### **DNSTwist Runner** (Enhanced)
- **Build**: `apps/dnstwist-runner`
- **Role**: Domain permutation generator with comprehensive fuzzing
- **Why we need it**:
  - **Proactive detection**: Generates typosquatting variants before they're registered
  - **Homoglyphs**: Detects look-alike characters (ο vs o, і vs i)
  - **Common typos**: Addition, omission, transposition, repetition
  - **Dictionary attacks**: Uses high-risk phishing keywords
- **Resources**: ~200MB RAM
- **Threads**: 16 parallel permutation generators
- **Input**:
  - Startup: Seed domains from `configs/cse_seeds.csv`
  - Continuous: Live domains from `raw.hosts` (CT-watcher, frontend, monitor-scheduler)
- **Output**: `raw.hosts` Kafka topic (variants)
- **Processing Modes**:
  - **Startup**: Process CSV seeds with 3-pass analysis
  - **Continuous**: Listen to `raw.hosts` and generate variants (also 3-pass)
- ** NEW Features**:
  - **Full domain processing**: Uses complete submitted domain (not just registrable)
  - **Unified 3-pass analysis**: Live/CT/frontend submissions get same treatment as CSV seeds
    - PASS_A: 12 fuzzers + common TLDs
    - PASS_B: 8 fuzzers + India TLDs
    - PASS_C: 4 fuzzers + high-risk dictionary
  - **Smart deduplication**: Tracks by full FQDN to avoid reprocessing
  - **Registered-only**: Only emits variants that resolve via DNS
- **Dependencies**: Kafka, Unbound

**Example processing for `nic.gov.in`** (user submission):
```
Input: nic.gov.in
PASS_A: nlc.gov.in, nic.gov.com, niic.gov.in (25 variants)
PASS_B: nic.gov.co.in, nic.bharat (12 variants)
PASS_C: nic-secure.gov.in, nic-verify.gov.in (8 variants)
Output: 45 registered variants emitted
```

---

#### **Normalizer**
- **Build**: `apps/normalizer`
- **Role**: Domain deduplication and normalization
- **Why we need it**:
  - **Prevents duplicates**: Avoids wasting resources on known domains
  - **Extracts registrable**: Converts `login.sbi.co.in` → `sbi.co.in`
  - **Adds metadata**: Tracks CSE ID, seed domain, reasons
- **Resources**: 512MB RAM limit
- **Input**: `raw.hosts`
- **Output**: `domains.candidates`
- **Redis TTL**: 120 days (10,368,000 seconds)
- **Dependencies**: Kafka, Redis

---

#### **DNS Collector** (Scaled)
- **Build**: `apps/dns-collector`
- **Role**: DNS/WHOIS/GeoIP enrichment with horizontal scaling
- **Why we need it**:
  - **Infrastructure mapping**: A/MX/NS records reveal hosting patterns
  - **Age detection**: WHOIS shows if domain is newly registered
  - **Location tracking**: GeoIP identifies hosting country/ASN
  - **High throughput**: Handles bursts from DNSTwist/CT-watcher
- **Resources**: 1GB RAM limit per instance
- ** NEW: Replicas**: 3 parallel instances (3x throughput)
- **Per-Instance Workers**: 12 DNS workers, 4 WHOIS workers
- **Per-Instance Concurrency**: 50 concurrent DNS queries
- **Total Capacity**:
  - 36 DNS workers (12 × 3)
  - 150 concurrent queries (50 × 3)
  - 12 WHOIS workers (4 × 3)
- **Load Balancing**: Kafka consumer group `dns-collector-group` distributes work
- **Input**: `raw.hosts`, `domains.candidates`
- **Output**: `domains.resolved`
- **Rate limiting**: 500ms delay between WHOIS queries per instance
- **GeoIP databases**: GeoLite2-City, GeoLite2-ASN
- **Dependencies**: Kafka, Unbound

**Why scaling matters**: Single instance was experiencing queue backlog (340+ pending tasks). Three replicas handle 3x volume without bottlenecks.

---

#### **HTTP Fetcher**
- **Build**: `apps/http-fetcher`
- **Role**: HTTP/HTTPS probing and SSL analysis
- **Why we need it**:
  - **Liveness check**: Verifies domain is reachable
  - **SSL analysis**: Detects self-signed certs, domain mismatches
  - **Basic metadata**: Title, status code, redirects
- **Resources**: 1GB RAM limit
- **Concurrency**: 20 parallel HTTP requests
- **Timeouts**: 4s connect, 6s read
- **Max body**: 200KB
- **Max redirects**: 5
- **Input**: `domains.resolved`
- **Output**: `http.probed`
- **Dependencies**: Kafka

---

#### **URL Router**
- **Build**: `apps/url-router`
- **Role**: Filters URLs for feature crawling
- **Why we need it**:
  - **Resource optimization**: Only crawls live, accessible URLs
  - **Dead site filtering**: Skips NXDOMAIN, connection refused
- **Input**: `http.probed`
- **Output**: `phish.urls.crawl`
- **Dependencies**: Kafka

---

#### **Feature Crawler**
- **Build**: `apps/feature-crawler`
- **Role**: Deep webpage analysis using Playwright
- **Why we need it**:
  - **Screenshots**: Visual evidence of phishing pages
  - **Form analysis**: Detects credential harvesting forms
  - **JavaScript analysis**: Identifies obfuscation, keyloggers
  - **Favicon hashing**: Brand impersonation detection
- **Resources**: 1GB RAM, 1GB shared memory
- **Browser**: Chromium (headless)
- **Replicas**: 3 parallel instances (3x throughput)
- **Timeout**: 15 seconds per page
- **Input**: `phish.urls.crawl`
- **Output**: `phish.features.page`, `phish.urls.failed`
- **Dependencies**: Kafka

---

#### **Rule Scorer**
- **Build**: `apps/rule-scorer`
- **Role**: Risk scoring and verdict assignment
- **Why we need it**:
  - **Automated triage**: Reduces manual review by 95%
  - **Combines 30+ indicators**: WHOIS age, forms, SSL, keywords
  - **Monitoring triggers**: Flags suspicious/parked for 90-day tracking
- **Input**: `domains.resolved`, `http.probed`, `phish.features.page`
- **Output**: `phish.rules.verdicts`
- **Verdicts**: phishing, suspicious, parked, benign
- **Dependencies**: Kafka

---

#### **Monitor Scheduler**
- **Build**: `apps/monitor-scheduler`
- **Role**: 90-day domain tracking and re-crawl automation
- **Why we need it**:
  - **Catches activation**: Parked domains often activate later
  - **Escalation detection**: Suspicious domains may become phishing
  - **Automated follow-up**: No manual tracking required
- **Resources**: 256MB RAM limit
- **Check interval**: Every 24 hours
- **Max rechecks**: 3 per domain
- **Input**: `phish.rules.verdicts`
- **Output**: `raw.hosts` (re-queue)
- **Dependencies**: Kafka, Redis

---

#### **ChromaDB Ingestor**
- **Build**: `apps/chroma-ingestor`
- **Role**: Converts JSON records to searchable vectors
- **Why we need it**:
  - **Text generation**: Creates searchable descriptions from metadata
  - **Embedding**: Converts text to 384-dim vectors
  - **Upsert**: Merges domain + features into single records
- **Model**: `sentence-transformers/all-MiniLM-L6-v2`
- **Batch size**: 1 (real-time processing)
- **Flush interval**: 5 seconds
- **Input**: `domains.resolved`, `phish.features.page`, `phish.rules.verdicts`
- **Output**: ChromaDB collection
- **Dependencies**: Kafka, ChromaDB

---

#### **Frontend API**
- **Build**: `apps/frontend-api`
- **Role**: Web UI and REST API for domain submission
- **Why we need it**:
  - **User interface**: Allows manual domain submission
  - **REST API**: Programmatic access for integrations
  - **Health checks**: Monitors pipeline status
- **Port**: 3000 (exposed to host)
- **Input**: HTTP POST to `/api/submit`
- **Output**: `raw.hosts` Kafka topic
- **Dependencies**: Kafka

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
- `features_page_*.jsonl`
- `rules_verdicts_*.jsonl`

These serve as:
- Backup/audit trail
- Batch reprocessing source
- Forensic analysis data

---

## Monitoring Strategy: Active vs Inactive Domains

### Two-Tier Monitoring System

#### **Active Monitoring** (Suspicious/Parked Sites)
- Domains that are live but flagged as suspicious or parked
- Check intervals: 90 days (configurable)
- Max rechecks: 3
- Redis queue: `monitoring:queue`

#### **Inactive Monitoring**
Two types of inactive domains are now monitored:

**1. Registered but Inactive** (`ok: false` from HTTP probe)
- Domain has DNS but no active web server
- Check intervals: **7d, 30d, 90d**
- Max checks: 3
- **Why**: Newly registered domains often activate later with phishing content

**2. Unregistered Variants** (DNSTwist generated, not registered)
- Typosquatting domains that don't exist yet
- Check intervals: **30d, 90d, 180d**
- Max checks: 3
- **Why**: Attackers may register them later

### What Gets Dropped vs Monitored vs Ingested

| Domain Type | Behavior | Monitored? | ChromaDB? | Reason |
|-------------|----------|-----------|-----------|--------|
| **HTTP probe failed** (`ok: false`) | ✅ Forwarded | ✅ Yes (7/30/90d) | ✅ **YES** | May activate later |
| **Unregistered variants** | ✅ Forwarded | ✅ Yes (30/90/180d) | ✅ **YES** | May be registered later |
| **Crawl failures** (3x retry) | ✅ Forwarded | ❌ No | ✅ **YES** | Valuable failure data |
| **Suspicious/Parked** (verdicts) | ✅ Forwarded | ✅ Yes (90d) | ✅ **YES** | May become phishing |
| **Duplicates** (<120d) | ❌ **DROPPED** | ❌ No | ❌ NO | Already processed |
| **Invalid URLs** | ❌ **DROPPED** | ❌ No | ❌ NO | Cannot process |
| **Denylist matches** | ❌ **DROPPED** | ❌ No | ❌ NO | Known false positives |
| **Infrastructure/Noise** | ❌ **DROPPED** | ❌ No | ❌ NO | Cpanel, webmail, etc. |

### ChromaDB Ingestion Summary

**✅ INGESTED to ChromaDB (5 topics consumed):**
1. `domains.resolved` - All DNS/WHOIS enriched domains
2. `phish.features.page` - Successfully crawled pages
3. `phish.urls.failed` - Failed crawls (3x retry)
4. `phish.rules.verdicts` - Risk scoring verdicts
5. `phish.urls.inactive` - **NEW:** Inactive/unregistered domains

**❌ NEVER REACH ChromaDB (Dropped Earlier):**
1. Redis duplicates (Normalizer)
2. Invalid/malformed URLs (URL Router)
3. Denylist matches (Normalizer)
4. Infrastructure/noise (CT-Watcher)

**Query Examples:**
```python
# Find inactive domains
inactive = collection.get(where={"is_inactive": True})

# Find unregistered variants being monitored
unregistered = collection.get(where={"inactive_status": "unregistered"})

# Find registered but inactive (no website)
no_website = collection.get(where={"inactive_status": "inactive"})

# Find all monitoring targets (inactive + suspicious + parked)
monitoring = collection.get(where={"$or": [
    {"is_inactive": True},
    {"requires_monitoring": True}
]})
```

### Redis Schema

**Active Monitoring:**
- `monitoring:queue` - Sorted set (domain → monitor_until timestamp)
- `monitoring:meta:{domain}` - Hash (verdict, reason, recheck_count)

**Inactive Monitoring:**
- `monitoring:inactive` - Sorted set (domain → next_check timestamp)
- `monitoring:meta:inactive:{domain}` - Hash (status, cse_id, check_count, first_seen)

### Monitoring Flow

```
Registered Domain (no website)
  → HTTP Fetcher: ok=false
  → URL Router: Forwards to phish.urls.inactive
  → Monitor-Scheduler: Adds to inactive queue
  → Check after 7 days: Still down? Check after 30 days
  → Check after 30 days: Still down? Check after 90 days
  → Check after 90 days: Still down? Remove from monitoring
  → IF ACTIVE at any check: Re-queue to raw.hosts for full crawl

Unregistered Variant (DNSTwist)
  → DNSTwist: Generates sbii.co.in (not registered)
  → DNSTwist: Emits to phish.urls.inactive
  → Monitor-Scheduler: Adds to inactive queue
  → Check after 30 days: DNS lookup (still unregistered?)
  → Check after 90 days: DNS lookup
  → Check after 180 days: DNS lookup
  → IF REGISTERED at any check: Re-queue to raw.hosts for full crawl
```

---
