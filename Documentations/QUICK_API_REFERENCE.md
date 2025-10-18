# ChromaDB Query API - Quick Reference

## Base URL
```
http://localhost:3000/api/chroma
```

---

## Quick Commands

### 1. Get All Original Brands
```bash
curl "http://localhost:3000/api/chroma/originals?limit=100"
```

### 2. Get All Phishing Variants
```bash
curl "http://localhost:3000/api/chroma/variants?verdict=phishing&limit=100"
```

### 3. Find Variants of a Specific Brand
```bash
curl "http://localhost:3000/api/chroma/variants?seed_registrable=sbi.co.in"
```

### 4. Get High-Risk Domains (Score >= 70)
```bash
curl "http://localhost:3000/api/chroma/variants?risk_score_min=70&has_verdict=true"
```

### 5. Search with Natural Language
```bash
curl "http://localhost:3000/api/chroma/search?query=phishing%20sites%20with%20login%20forms&limit=10"
```

### 6. Get Domain Details (with DNSTwist Stats for Originals)
```bash
curl "http://localhost:3000/api/chroma/domain/sbi.co.in"
```
**Note**: Original seed domains include DNSTwist variant statistics showing total variants generated.

### 7. Get Collection Statistics
```bash
curl "http://localhost:3000/api/chroma/stats"
```

### 8. Get Newly Registered Suspicious Domains
```bash
curl "http://localhost:3000/api/chroma/variants?is_newly_registered=true&verdict=suspicious"
```

---

## Endpoints Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/collections` | GET | List all collections |
| `/originals` | GET | Query original seed domains (includes DNSTwist stats) |
| `/variants` | GET | Query lookalike/phishing variants |
| `/search` | GET | Semantic search (natural language) |
| `/domain/:domain` | GET | Get specific domain details (with DNSTwist stats for originals) |
| `/stats` | GET | Collection statistics |

---

## Common Filters

### For `/originals`:
- `limit` - Results count (max: 100)
- `offset` - Pagination offset
- `registrable` - Exact domain name
- `cse_id` - Brand identifier
- `verdict` - Verdict value

### For `/variants`:
- `limit` - Results count (max: 1000)
- `offset` - Pagination offset
- `seed_registrable` - Original brand
- `cse_id` - Brand identifier
- `verdict` - `phishing`, `suspicious`, `parked`
- `risk_score_min` - Minimum score (0-100)
- `risk_score_max` - Maximum score (0-100)
- `is_newly_registered` - Boolean

### For `/search`:
- `query` - Natural language query (required)
- `collection` - `both`, `originals`, `variants`
- `limit` - Results per collection (max: 50)

---

## Python Example

```python
import requests

API_BASE = "http://localhost:3000/api/chroma"

# Get original domain with DNSTwist variant stats
response = requests.get(f"{API_BASE}/domain/sbi.co.in")
data = response.json()

if data['success'] and 'dnstwist_stats' in data:
    stats = data['dnstwist_stats']
    print(f"Domain: {data['domain']}")
    print(f"Total variants: {stats['total_variants_generated']}")
    print(f"Registered: {stats['variants_registered']}")
    print(f"Unregistered: {stats['variants_unregistered']}")

# Get all SBI phishing variants
response = requests.get(f"{API_BASE}/variants", params={
    "seed_registrable": "sbi.co.in",
    "verdict": "phishing",
    "limit": 100
})

data = response.json()
if data['success']:
    for domain in data['domains']:
        print(f"{domain['metadata']['registrable']} - Score: {domain['metadata']['risk_score']}")
```

---

## JavaScript Example

```javascript
const axios = require('axios');

const API_BASE = 'http://localhost:3000/api/chroma';

// Get original domain with DNSTwist stats
async function getDomainStats(domain) {
  const response = await axios.get(`${API_BASE}/domain/${domain}`);

  if (response.data.success && response.data.dnstwist_stats) {
    const stats = response.data.dnstwist_stats;
    console.log(`${domain}: ${stats.total_variants_generated} variants (${stats.variants_registered} registered)`);
  }

  return response.data;
}

// Semantic search
async function searchPhishing() {
  const response = await axios.get(`${API_BASE}/search`, {
    params: {
      query: 'credential harvesting login forms',
      collection: 'variants',
      limit: 10
    }
  });

  return response.data.results.variants;
}
```

---

## Response Structure

All responses follow this format:

```json
{
  "success": true,
  "collection": "domains",
  "count": 10,
  "domains": [
    {
      "id": "unique-id",
      "metadata": {
        "registrable": "example.com",
        "verdict": "phishing",
        "risk_score": 85,
        ...
      },
      "document": "Full text description..."
    }
  ]
}
```

---

## Key Metadata Fields

### Core Fields
- `registrable` - Domain name
- `seed_registrable` - Original brand
- `cse_id` - Brand identifier
- `verdict` - Risk classification
- `risk_score` - Score (0-100)
- `is_original_seed` - True if original
- `domain_age_days` - Domain age
- `is_newly_registered` - < 30 days
- `has_credential_form` - Has login form
- `country` - Hosting country

### SSL/Certificate Fields
- `is_self_signed` - 🚨 Self-signed certificate
- `cert_age_days` - Certificate age
- `is_newly_issued_cert` - Cert < 30 days old
- `cert_risk_score` - SSL risk (0-100)
- `domain_mismatch` - Cert domain mismatch
- `trusted_issuer` - From trusted CA

### Form Submission Analysis
- `forms_to_ip` - 🚨 Forms to IP addresses
- `forms_to_suspicious_tld` - Forms to .tk/.ml/.ga
- `forms_to_private_ip` - Forms to localhost
- `has_suspicious_forms` - Has suspicious forms

### JavaScript Analysis
- `js_keylogger` - 🚨 Keylogger detected
- `js_obfuscated` - Uses obfuscation
- `js_form_manipulation` - Modifies forms
- `js_redirect_detected` - JS redirects
- `js_risk_score` - JS risk (0-100)

### Additional Fields
- `favicon_md5` - Favicon hash (brand detection)
- `redirect_count` - HTTP redirect count
- `had_redirects` - Has redirects

### DNSTwist Statistics (Original Seeds Only)
- `dnstwist_variants_registered` - Number of registered variants
- `dnstwist_variants_unregistered` - Number of unregistered variants
- `dnstwist_total_generated` - Total variants generated
- `dnstwist_processed_at` - Unix timestamp of processing

---

## Useful Queries

### Get Original Domain with Variant Statistics
```bash
curl "http://localhost:3000/api/chroma/domain/sbi.co.in"
```
**Example Response**:
```json
{
  "success": true,
  "domain": "sbi.co.in",
  "collection": "original_domains",
  "is_original_seed": true,
  "data": {
    "id": "sbi.co.in:a1b2c3d4e5f6g7h8",
    "metadata": {
      "registrable": "sbi.co.in",
      "cse_id": "SBI",
      "is_original_seed": true,
      "verdict": "benign"
    }
  },
  "dnstwist_stats": {
    "variants_registered": 127,
    "variants_unregistered": 453,
    "total_variants_generated": 580,
    "processed_at": 1729180521,
    "processed_date": "2025-10-17T13:15:21.000Z"
  }
}
```

### Find All High-Risk Banking Phishing Sites
```bash
curl "http://localhost:3000/api/chroma/search?query=banking%20phishing%20high%20risk&collection=variants&limit=50"
```

### Get All Original Banking Domains
```bash
curl "http://localhost:3000/api/chroma/search?query=banking%20financial%20institution&collection=originals&limit=20"
```

### Monitor New Threats (Last 7 Days)
```bash
curl "http://localhost:3000/api/chroma/variants?is_newly_registered=true&verdict=phishing&limit=100"
```

### Export All Variants for a Brand (with jq)
```bash
curl "http://localhost:3000/api/chroma/variants?seed_registrable=sbi.co.in&limit=1000" \
  | jq -r '.domains[] | "\(.metadata.registrable),\(.metadata.risk_score),\(.metadata.verdict)"'
```

### Find Domains with Self-Signed Certificates (High Risk)
```bash
# Self-signed certs are the #1 phishing indicator
curl "http://localhost:3000/api/chroma/search?query=login%20banking&limit=50" \
  | jq '.results.variants[] | select(.metadata.is_self_signed == true)'
```

### Find Domains with Keyloggers Detected
```bash
# JavaScript keyloggers capturing credentials
curl "http://localhost:3000/api/chroma/search?query=credential%20harvesting&limit=50" \
  | jq '.results.variants[] | select(.metadata.js_keylogger == true)'
```

### Find Forms Submitting to IP Addresses
```bash
# Forms sending credentials to external IPs (major red flag)
curl "http://localhost:3000/api/chroma/search?query=phishing%20forms&limit=50" \
  | jq '.results.variants[] | select(.metadata.forms_to_ip > 0)'
```

### Find Domains with Multiple Risk Indicators
```bash
# Combine SSL + keylogger + suspicious forms
curl "http://localhost:3000/api/chroma/search?query=high%20risk%20phishing&limit=50" \
  | jq '.results.variants[] | select(
      .metadata.is_self_signed == true or
      .metadata.js_keylogger == true or
      .metadata.forms_to_ip > 0
    )'
```

---

For full documentation, see [CHROMA_API_DOCUMENTATION.md](CHROMA_API_DOCUMENTATION.md)
