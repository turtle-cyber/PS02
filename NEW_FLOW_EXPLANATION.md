# New Flow: User Submissions Trigger DNSTwist

## 🎯 What Changed

### Before (Old Flow)
```
Frontend → raw.hosts → Normalizer → DNS Collector → ...
DNSTwist runs once from CSV, exits
```

- DNSTwist only processed domains from `cse_seeds.csv`
- It ran once and exited
- User submissions were NOT analyzed for variants

### After (New Flow) ✨
```
Frontend submits: www.myvi.in
    ↓
raw.hosts topic
    ↓
    ├──→ DNSTwist (CONTINUOUS)
    │    - Generates variants: myvi.in, my-vi.in, myvii.in, myv1.in, etc.
    │    - Publishes variants back to raw.hosts
    │    - Stays alive, processes ALL incoming domains
    │
    └──→ Normalizer → DNS Collector → HTTP Fetcher → Feature Crawler → ChromaDB
```

**Key Changes:**
- ✅ DNSTwist now runs **continuously** (never exits)
- ✅ Listens to `raw.hosts` topic for user submissions
- ✅ Generates variants for **ANY** domain submitted
- ✅ Publishes variants back to `raw.hosts` for full pipeline processing
- ✅ Still processes CSV seeds on startup

---

## 📊 Complete Flow Diagram

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
          │   (CONTINUOUS)   │  │  (monitors   │
          │                  │  │  certstream) │
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
                         │  Normalizer  │ (dedup + extract registrable)
                         └──────┬───────┘
                                │
                                ▼
                         ┌──────────────┐
                         │ DNS Collector│ (DNS/WHOIS/GeoIP/Domain Age)
                         └──────┬───────┘
                                │
                                ▼
                         ┌──────────────┐
                         │ HTTP Fetcher │ (HTTP probe + SSL analysis)
                         └──────┬───────┘
                                │
                                ▼
                         ┌──────────────┐
                         │  URL Router  │ (filter crawlable URLs)
                         └──────┬───────┘
                                │
                                ▼
                         ┌──────────────┐
                         │Feature       │ (screenshot, forms, JS analysis)
                         │Crawler       │ (favicon, redirects, etc.)
                         └──────┬───────┘
                                │
                                ▼
                         ┌──────────────┐
                         │  ChromaDB    │ (vector database storage)
                         │  Ingestor    │
                         └──────────────┘
```

---

## 🔧 What Each Component Does

### 1. **Frontend API** (Port 3000)
- User submits: `https://www.myvi.in/`
- Publishes to `raw.hosts` with metadata
- Logs submission details

### 2. **DNSTwist (Continuous Mode)**
- **On Startup:** Processes all domains from `cse_seeds.csv` (one-time)
- **Continuously:**
  - Listens to `raw.hosts` topic
  - For each new domain:
    - Extracts registrable domain (e.g., `myvi.in`)
    - Runs dnstwist variant generation
    - Finds variants like:
      - `myvi.in` → `myv1.in`, `my-vi.in`, `myvii.in`, `myvi.com`, `myvi.org`, etc.
    - Publishes ALL variants back to `raw.hosts`
  - **Never exits** - stays alive processing domains

### 3. **CT-Watcher** (Continuous)
- Monitors certificate transparency logs from Certstream
- Matches certificates against seed patterns
- Publishes matching domains to `raw.hosts`

### 4. **Normalizer**
- Consumes from `raw.hosts`
- Deduplicates using Redis cache
- Extracts canonical FQDN and registrable domain
- Publishes to `domains.candidates`

### 5. **Rest of Pipeline**
- DNS Collector → HTTP Fetcher → URL Router → Feature Crawler → ChromaDB
- Same as before, now processes original + all variants

---

## 💡 Example: Submitting `www.myvi.in`

### Step-by-Step Execution

1. **User submits** `https://www.myvi.in/` via frontend

2. **Frontend API** receives it:
   ```log
   [info] 🎯 New submission request {"input":"https://www.myvi.in/"}
   [info] 🔍 Extracted domain {"extracted":"www.myvi.in"}
   [info] 📤 Submitting to Kafka {"topic":"raw.hosts","domain":"www.myvi.in"}
   [info] ✅ Successfully submitted to Kafka
   ```

3. **DNSTwist** picks it up:
   ```log
   [runner] 📥 Received domain: www.myvi.in (CSE: N/A)
   [dnstwist] ===== Processing: myvi.in (CSE: UNKNOWN) =====
   [dnstwist] Generating variants...
   [dnstwist] Found 47 registered variant domains
   [dnstwist] ✓ Completed myvi.in: 47 variants emitted
   ```

4. **DNSTwist publishes variants** back to `raw.hosts`:
   - `myvi.com`
   - `myvi.org`
   - `myvi.net`
   - `my-vi.in`
   - `myvii.in`
   - `myv1.in`
   - ... (40+ more)

5. **Normalizer** processes original + all 47 variants:
   ```log
   [normalizer] Processing www.myvi.in
   [normalizer] Processing myvi.com
   [normalizer] Processing myvi.org
   ... (48 total domains)
   ```

6. **DNS Collector** enriches each domain:
   - Resolves DNS records
   - Performs WHOIS lookup
   - Calculates domain age
   - Gets GeoIP location

7. **HTTP Fetcher** probes each domain:
   - Checks HTTP/HTTPS connectivity
   - Analyzes SSL certificates
   - Calculates certificate risk scores

8. **Feature Crawler** analyzes pages:
   - Takes screenshots
   - Extracts forms and fields
   - Detects JavaScript patterns
   - Hashes favicons
   - Tracks redirects

9. **ChromaDB** stores everything:
   - Original domain: `www.myvi.in`
   - 47 variants with full analysis
   - All queryable via semantic search

---

## 🐛 Bug Fixes Included

### 1. **DNS Collector Asyncio Error** ✅ FIXED
**Error:**
```
[dns] Error processing onlinesbi.io: An asyncio.Future, a coroutine or an awaitable is required
```

**Fix Applied:**
```python
# Before (line 452):
task = asyncio.create_task(handle_fqdn_with_limit(...))

# After:
coro = handle_fqdn_with_limit(fqdn, payload, loop, executor, producer, output_file)
task = asyncio.ensure_future(coro)
```

**File:** `apps/dns-collector/worker.py:452-458`

### 2. **DNSTwist Exits Immediately** ✅ FIXED
**Problem:** DNSTwist ran once and exited, never processing user submissions

**Solution:**
- Created `runner_continuous.py` - new continuous mode
- Processes CSV seeds on startup
- Then enters infinite loop consuming from `raw.hosts`
- Never exits unless stopped

**Files:**
- `apps/dnstwist-runner/runner_continuous.py` (NEW)
- `apps/dnstwist-runner/Dockerfile` (UPDATED)
- `infra/docker-compose.yml` (UPDATED)

---

## 🚀 How to Deploy

### 1. Rebuild DNSTwist Container

```bash
cd infra
docker-compose build dnstwist-runner
```

### 2. Rebuild DNS Collector (for asyncio fix)

```bash
docker-compose build dns-collector
```

### 3. Start Everything

```bash
docker-compose up -d
```

### 4. Verify DNSTwist is Running Continuously

```bash
docker logs -f dnstwist-runner
```

You should see:
```
[runner] ==================== STARTING DNSTWIST CONTINUOUS RUNNER ====================
[kafka] Producer connected successfully!
[runner] ==================== Processing 1 CSV seeds ====================
[runner] [1/1] ===== Processing: onlinesbi.sbi (CSE: SBI) =====
[runner] ✓ Completed onlinesbi.sbi: 13 variants emitted
[runner] ==================== CSV PROCESSING COMPLETE ====================
[runner] ==================== ENTERING CONTINUOUS MODE ====================
[runner] Listening to topic: raw.hosts
[runner] Ready to process user-submitted domains...
```

**Notice:** It **does NOT exit** anymore!

### 5. Test with a Submission

```bash
curl -X POST http://localhost:3000/api/submit \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.myvi.in/", "cse_id": "TEST"}'
```

### 6. Watch DNSTwist Process It

```bash
docker logs -f dnstwist-runner | grep "myvi"
```

You should see:
```
[runner] 📥 Received domain: www.myvi.in (CSE: TEST)
[dnstwist] ===== Processing: myvi.in (CSE: TEST) =====
[dnstwist] Generating variants...
[dnstwist] Found 47 registered variant domains
[dnstwist] ✓ Completed myvi.in: 47 variants emitted
```

### 7. Track Through Pipeline

```bash
# Check normalizer
docker logs -f normalizer | grep "myvi"

# Check DNS collector
docker logs -f dns-collector | grep "myvi"

# Check feature crawler
docker logs -f feature-crawler | grep "myvi"
```

### 8. Query Results (after 5-10 minutes)

```python
import chromadb

client = chromadb.HttpClient(host='localhost', port=8000)
collection = client.get_collection("domains")

# Search for myvi domains
results = collection.query(
    query_texts=["myvi"],
    n_results=50
)

print(f"Found {len(results['ids'][0])} myvi-related domains")
for domain in results['ids'][0]:
    print(f"  - {domain}")
```

---

## 📝 Configuration Options

### DNSTwist Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUNNER_MODE` | `continuous` | `continuous` or `oneshot` |
| `KAFKA_ENABLED` | `true` | Enable Kafka integration |
| `KAFKA_INPUT_TOPIC` | `raw.hosts` | Topic to consume from |
| `KAFKA_OUTPUT_TOPIC` | `raw.hosts` | Topic to publish variants to |
| `PROCESS_CSV_ON_STARTUP` | `true` | Process CSV seeds on startup |
| `THREADS` | `16` | DNSTwist thread count |
| `NAMESERVERS` | `unbound` | DNS resolver to use |

### Switch Back to One-Shot Mode (If Needed)

In `docker-compose.yml`:
```yaml
dnstwist-runner:
  environment:
    RUNNER_MODE: "oneshot"  # Change this
```

---

## 🎉 Benefits of New Flow

1. ✅ **User submissions generate variants automatically**
   - Submit 1 domain → get 50+ variants analyzed

2. ✅ **Comprehensive brand protection**
   - Every submission triggers typosquatting detection

3. ✅ **No manual configuration needed**
   - Users don't need to know about DNSTwist

4. ✅ **Continuous operation**
   - DNSTwist always ready to process new domains

5. ✅ **Full pipeline for all variants**
   - Original + variants all get complete analysis

6. ✅ **Queryable in ChromaDB**
   - Find all variants of a brand with semantic search

---

## 🐞 Troubleshooting

### DNSTwist still exits?

**Check:**
```bash
docker exec dnstwist-runner env | grep RUNNER_MODE
```

Should show: `RUNNER_MODE=continuous`

If not, rebuild:
```bash
cd infra
docker-compose up -d --build dnstwist-runner
```

### No variants appearing?

**Check DNSTwist logs:**
```bash
docker logs dnstwist-runner --tail=50
```

Look for:
- `[runner] ==================== ENTERING CONTINUOUS MODE ====================`
- `[runner] Ready to process user-submitted domains...`

If you see `[runner] Container will now exit.` → It's running in oneshot mode!

### DNS collector still shows asyncio errors?

**Rebuild:**
```bash
cd infra
docker-compose up -d --build dns-collector
```

**Verify fix:**
```bash
docker logs dns-collector --tail=50 | grep "asyncio.Future"
```

Should show **no results**.

---

## 📚 Files Modified

1. ✅ `apps/dnstwist-runner/runner_continuous.py` - NEW continuous mode runner
2. ✅ `apps/dnstwist-runner/Dockerfile` - Support both modes
3. ✅ `apps/dns-collector/worker.py` - Fixed asyncio error (line 452-458)
4. ✅ `infra/docker-compose.yml` - Updated DNSTwist config

---

## 🎯 Next Steps

1. **Test the flow** with a real domain submission
2. **Monitor logs** to verify variants are generated
3. **Query ChromaDB** after 5-10 minutes for results
4. **Adjust fuzzer settings** if too many/few variants

Enjoy your new continuous variant generation pipeline! 🚀
