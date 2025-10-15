# ChromaDB Querying Guide

## How to Query and Retrieve Data from ChromaDB

This guide shows you how to query the phishing detection pipeline's ChromaDB vector database to retrieve analyzed domain data.

## Setup

### 1. Install ChromaDB Client

```bash
pip install chromadb
```

### 2. Connect to ChromaDB

```python
import chromadb

# Connect to ChromaDB server (running in Docker)
client = chromadb.HttpClient(host='localhost', port=8000)

# Get the collection
collection = client.get_collection(name="domains")
```

### 3. Verify Connection

```python
# Check collection stats
print(f"Total records: {collection.count()}")
```

---

## Query Types

### 1. **Semantic Search** (Vector Similarity)

Search for domains using natural language queries. ChromaDB uses embeddings to find semantically similar records.

```python
# Find phishing login pages
results = collection.query(
    query_texts=["phishing login page with password form"],
    n_results=10
)

# Find domains targeting specific brands
results = collection.query(
    query_texts=["State Bank of India fake website"],
    n_results=20
)

# Find suspicious payment pages
results = collection.query(
    query_texts=["fake payment gateway credit card form"],
    n_results=15
)
```

### 2. **Filtered Search** (Metadata + Semantic)

Combine semantic search with metadata filters for precise results.

```python
# Find phishing sites with credential forms
results = collection.query(
    query_texts=["login page"],
    where={"has_credential_form": True},
    n_results=10
)

# Find newly registered domains with self-signed certificates
results = collection.query(
    query_texts=["suspicious banking website"],
    where={
        "$and": [
            {"is_newly_registered": True},
            {"is_self_signed": True}
        ]
    },
    n_results=20
)
```

### 3. **Direct Lookup** (By ID)

Retrieve specific domains directly by their registrable domain (ID).

```python
# Get a specific domain
results = collection.get(
    ids=["suspicious-sbi.com"]
)

# Get multiple domains
results = collection.get(
    ids=["domain1.com", "domain2.com", "domain3.com"]
)
```

### 4. **Filter-Only Query** (No Semantic Search)

Query based purely on metadata filters without semantic similarity.

```python
# Get all domains from a specific country
results = collection.get(
    where={"country": "CN"},
    limit=100
)

# Get all high-risk domains
results = collection.get(
    where={
        "$and": [
            {"cert_risk_score": {"$gte": 50}},
            {"js_risk_score": {"$gte": 40}}
        ]
    },
    limit=50
)
```

---

## Understanding Results

### Result Structure

```python
results = collection.query(
    query_texts=["phishing login"],
    n_results=5
)

# Results structure:
{
    "ids": [["domain1.com", "domain2.com", ...]],           # Domain IDs (registrable)
    "documents": [["text1", "text2", ...]],                 # Embedded text documents
    "metadatas": [[{...}, {...}, ...]],                     # Metadata dictionaries
    "distances": [[0.1, 0.15, 0.2, ...]]                   # Similarity scores (lower = better)
}
```

### Accessing Results

```python
# Loop through results
for i, domain_id in enumerate(results['ids'][0]):
    metadata = results['metadatas'][0][i]
    distance = results['distances'][0][i]

    print(f"\n🔍 Domain: {domain_id}")
    print(f"   Similarity: {1 - distance:.2%}")
    print(f"   URL: {metadata.get('url', 'N/A')}")
    print(f"   Risk Score: {metadata.get('cert_risk_score', 0)}")
    print(f"   Has Credential Form: {metadata.get('has_credential_form', False)}")
    print(f"   Domain Age: {metadata.get('domain_age_days', 'N/A')} days")
```

---

## Common Query Examples

### High-Risk Phishing Detection

#### 1. Find Newly Registered Domains with Credential Forms

```python
results = collection.query(
    query_texts=["login password banking"],
    where={
        "$and": [
            {"is_newly_registered": True},      # < 30 days old
            {"has_credential_form": True}       # Has password form
        ]
    },
    n_results=50
)

print(f"Found {len(results['ids'][0])} high-risk domains")
```

#### 2. Find Self-Signed Certificate Sites

```python
results = collection.query(
    query_texts=["secure login banking"],
    where={"is_self_signed": True},
    n_results=30
)
```

#### 3. Find Domains with Keyloggers

```python
results = collection.query(
    query_texts=["phishing credential harvesting"],
    where={"js_keylogger": True},
    n_results=20
)
```

#### 4. Ultimate High-Risk Query (Multiple Indicators)

```python
results = collection.query(
    query_texts=["phishing login credentials bank"],
    where={
        "$and": [
            {"is_newly_registered": True},           # New domain
            {"has_credential_form": True},           # Credential form
            {
                "$or": [
                    {"is_self_signed": True},        # Self-signed cert
                    {"cert_risk_score": {"$gte": 40}}
                ]
            },
            {
                "$or": [
                    {"js_keylogger": True},          # Keylogger
                    {"has_suspicious_forms": True},  # Suspicious forms
                    {"js_obfuscated": True}          # Obfuscated JS
                ]
            }
        ]
    },
    n_results=100
)

print(f"🚨 CRITICAL: Found {len(results['ids'][0])} extremely high-risk phishing sites")
```

### 🔍 Brand-Specific Queries

#### 5. Find All Domains Targeting SBI

```python
results = collection.query(
    query_texts=["State Bank of India online banking"],
    where={"cse_id": "SBI"},
    n_results=100
)
```

#### 6. Find SBI Lookalikes with Stolen Favicon

```python
# First, get the legitimate SBI favicon hash
legit_results = collection.get(
    ids=["sbi.co.in"]
)
legit_favicon = legit_results['metadatas'][0]['favicon_md5']

# Find all domains using the same favicon
results = collection.query(
    query_texts=["sbi banking"],
    where={
        "$and": [
            {"favicon_md5": legit_favicon},      # Same favicon
            {"cse_id": "SBI"},                   # Tagged as SBI-related
            {"is_newly_registered": True}        # But newly registered
        ]
    },
    n_results=50
)

print(f"⚠️ Found {len(results['ids'][0])} potential brand impersonation sites")
```

### 🌍 Geographic Queries

#### 7. Find Phishing Sites Hosted in Specific Countries

```python
# High-risk countries
suspicious_countries = ["CN", "RU", "NG", "ID"]

results = collection.query(
    query_texts=["phishing banking login"],
    where={
        "$and": [
            {"country": {"$in": suspicious_countries}},
            {"has_credential_form": True}
        ]
    },
    n_results=50
)
```

### 📊 Form Analysis Queries

#### 8. Find Forms Submitting to IP Addresses

```python
results = collection.query(
    query_texts=["login form payment"],
    where={"forms_to_ip": {"$gt": 0}},
    n_results=30
)
```

#### 9. Find Forms Using Suspicious TLDs

```python
results = collection.query(
    query_texts=["credential harvesting"],
    where={"forms_to_suspicious_tld": {"$gt": 0}},
    n_results=30
)
```

### 🔗 Redirect Chain Queries

#### 10. Find Domains with Multiple Redirects

```python
results = collection.query(
    query_texts=["phishing redirect chain"],
    where={"redirect_count": {"$gte": 2}},
    n_results=40
)
```

### 📈 Risk Score Queries

#### 11. Find High SSL Risk Scores

```python
results = collection.query(
    query_texts=["secure banking"],
    where={"cert_risk_score": {"$gte": 50}},
    n_results=30
)
```

#### 12. Find High JavaScript Risk Scores

```python
results = collection.query(
    query_texts=["suspicious javascript"],
    where={"js_risk_score": {"$gte": 40}},
    n_results=30
)
```

### 🕐 Time-Based Queries

#### 13. Find Very New Domains (< 7 Days)

```python
results = collection.query(
    query_texts=["phishing website"],
    where={"is_very_new": True},
    n_results=50
)
```

#### 14. Find Newly Issued Certificates (< 30 Days)

```python
results = collection.query(
    query_texts=["banking login"],
    where={"is_newly_issued": True},
    n_results=40
)
```

### 📝 Feature Presence Queries

#### 15. Find Domains Without Features (Need Crawling)

```python
results = collection.get(
    where={"record_type": "domain"},
    limit=100
)

print(f"ℹ️ Found {len(results['ids'])} domains waiting to be crawled")
```

#### 16. Find Fully Merged Records (Domain + Features)

```python
results = collection.query(
    query_texts=["phishing"],
    where={"record_type": "merged"},
    n_results=50
)
```

---

## Advanced Querying

### Pagination

```python
# Get results in batches
offset = 0
batch_size = 100

while True:
    results = collection.get(
        where={"has_credential_form": True},
        limit=batch_size,
        offset=offset
    )

    if not results['ids']:
        break  # No more results

    # Process batch
    for domain_id in results['ids']:
        print(domain_id)

    offset += batch_size
```

### Complex Boolean Logic

```python
# (A AND B) OR (C AND D)
results = collection.query(
    query_texts=["phishing"],
    where={
        "$or": [
            {
                "$and": [
                    {"is_self_signed": True},
                    {"has_credential_form": True}
                ]
            },
            {
                "$and": [
                    {"js_keylogger": True},
                    {"is_newly_registered": True}
                ]
            }
        ]
    },
    n_results=50
)
```

### Exclude Specific Values

```python
# Find domains NOT from US
results = collection.query(
    query_texts=["phishing"],
    where={"country": {"$ne": "US"}},
    n_results=50
)

# Find domains WITHOUT credential forms
results = collection.query(
    query_texts=["website"],
    where={"has_credential_form": {"$ne": True}},
    n_results=50
)
```

---


## Export Data

### Export to JSON

```python
import json

# Get all high-risk domains
results = collection.get(
    where={
        "$and": [
            {"has_credential_form": True},
            {"is_newly_registered": True}
        ]
    },
    limit=10000
)

# Export to JSON file
output = []
for i, domain_id in enumerate(results['ids']):
    output.append({
        "domain": domain_id,
        "metadata": results['metadatas'][i]
    })

with open('high_risk_domains.json', 'w') as f:
    json.dump(output, f, indent=2)

print(f"✅ Exported {len(output)} domains to high_risk_domains.json")
```

### Export to CSV

```python
import csv

results = collection.get(
    where={"has_credential_form": True},
    limit=10000
)

with open('phishing_domains.csv', 'w', newline='') as f:
    writer = csv.writer(f)

    # Header
    writer.writerow(['domain', 'url', 'country', 'domain_age_days', 'is_self_signed',
                     'has_credential_form', 'cert_risk_score', 'js_risk_score'])

    # Data
    for i, domain_id in enumerate(results['ids']):
        meta = results['metadatas'][i]
        writer.writerow([
            domain_id,
            meta.get('url', ''),
            meta.get('country', ''),
            meta.get('domain_age_days', ''),
            meta.get('is_self_signed', ''),
            meta.get('has_credential_form', ''),
            meta.get('cert_risk_score', ''),
            meta.get('js_risk_score', '')
        ])

print(f"✅ Exported to phishing_domains.csv")
```

---

## Performance Tips

1. **Use filters before semantic search**: Filters are fast, semantic search is slower
   ```python
   # Good: Filter first, then semantic search
   results = collection.query(
       query_texts=["phishing"],
       where={"is_newly_registered": True},  # Fast filter
       n_results=10
   )
   ```

2. **Limit results**: Don't fetch more than you need
   ```python
   # Get top 20, not all 10,000
   results = collection.query(query_texts=["..."], n_results=20)
   ```

3. **Use direct lookup for known IDs**: Faster than semantic search
   ```python
   # Fast: Direct ID lookup
   results = collection.get(ids=["domain.com"])

   # Slower: Semantic search
   results = collection.query(query_texts=["domain.com"], n_results=1)
   ```

---

## Troubleshooting

### Connection Error: "Connection refused"

**Solution**: Check if ChromaDB server is running:

```bash
docker ps | grep chromadb
```

If not running, start it:

```bash
docker-compose up -d chromadb
```

### Empty Results

**Possible causes**:
1. No data ingested yet → Check `docker logs chroma-ingestor`
2. Wrong collection name → Verify with `client.list_collections()`
3. Filters too restrictive → Try without `where` parameter

### Slow Queries

**Solution**: Add indexes or use more specific filters:

```python
# Slow: Broad semantic search
results = collection.query(query_texts=["phishing"], n_results=1000)

# Fast: Narrow with filters
results = collection.query(
    query_texts=["phishing"],
    where={"cse_id": "SBI"},
    n_results=50
)
```
