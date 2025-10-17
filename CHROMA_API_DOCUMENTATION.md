# ChromaDB Query API Documentation

Complete API documentation for querying original seed domains and lookalike variants from the phishing detection pipeline.

## Base URL

```
http://localhost:3000/api/chroma
```

**Note**: Replace `localhost:3000` with your actual server address.

---

## Table of Contents

1. [Collections Overview](#collections-overview)
2. [Authentication](#authentication)
3. [API Endpoints](#api-endpoints)
   - [List Collections](#1-list-collections)
   - [Query Original Domains](#2-query-original-domains)
   - [Query Variant Domains](#3-query-variant-domains)
   - [Semantic Search](#4-semantic-search)
   - [Get Domain Details](#5-get-domain-details)
   - [Collection Statistics](#6-collection-statistics)
4. [Usage Examples](#usage-examples)
5. [Error Handling](#error-handling)

---

## Collections Overview

### `original_domains` Collection
Contains legitimate brand/seed domains that are being protected:
- Original domains from CSV seeds (e.g., `sbi.co.in`, `icicibank.com`)
- User-submitted domains with `use_full_pipeline=true`
- Fully enriched with DNS, WHOIS, page features, and verdicts
- **Includes DNSTwist variant statistics** (registered/unregistered counts)

### `domains` Collection
Contains lookalike/phishing variants detected by the system:
- DNSTwist-generated variants (e.g., `sbi-login.co.in`, `icici-secure.com`)
- Certificate Transparency matches
- Fully enriched with all analysis data

**Key Difference**: Original domains include variant generation stats, variants do not.

---

## Authentication

Currently, the API does not require authentication. For production use, consider implementing API keys or OAuth2.

---

## API Endpoints

### 1. List Collections

Get a list of all available ChromaDB collections.

**Endpoint**: `GET /api/chroma/collections`

**Response**:
```json
{
  "success": true,
  "collections": [
    {
      "name": "original_domains",
      "metadata": { "hnsw:space": "cosine" }
    },
    {
      "name": "domains",
      "metadata": { "hnsw:space": "cosine" }
    }
  ],
  "count": 2
}
```

**Example**:
```bash
curl http://localhost:3000/api/chroma/collections
```

---

### 2. Query Original Domains

Get original seed domains with optional filtering.

**Endpoint**: `GET /api/chroma/originals`

**Query Parameters**:

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `limit` | integer | Number of results (max: 100) | `10` |
| `offset` | integer | Skip first N results | `0` |
| `registrable` | string | Filter by exact domain name | `sbi.co.in` |
| `cse_id` | string | Filter by brand/CSE ID | `SBI` |
| `has_verdict` | boolean | Filter by verdict presence | `true` |
| `verdict` | string | Filter by verdict value | `clean` |

**Response**:
```json
{
  "success": true,
  "collection": "original_domains",
  "count": 5,
  "limit": 10,
  "offset": 0,
  "filters": {
    "cse_id": "SBI"
  },
  "domains": [
    {
      "id": "sbi.co.in:abc123...",
      "metadata": {
        "registrable": "sbi.co.in",
        "cse_id": "SBI",
        "seed_registrable": "sbi.co.in",
        "is_original_seed": true,
        "has_verdict": true,
        "verdict": "clean",
        "risk_score": 0,
        "domain_age_days": 7300,
        "a_count": 4,
        "country": "IN"
      },
      "document": "Domain: sbi.co.in\nURL: https://sbi.co.in/\n..."
    }
  ]
}
```

**Examples**:

```bash
# Get all original domains (first 10)
curl "http://localhost:3000/api/chroma/originals?limit=10"

# Get SBI domains
curl "http://localhost:3000/api/chroma/originals?cse_id=SBI"

# Get domains with verdicts
curl "http://localhost:3000/api/chroma/originals?has_verdict=true"

# Pagination - get next 10 results
curl "http://localhost:3000/api/chroma/originals?limit=10&offset=10"
```

---

### 3. Query Variant Domains

Get lookalike/phishing variant domains with filtering.

**Endpoint**: `GET /api/chroma/variants`

**Query Parameters**:

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `limit` | integer | Number of results (max: 1000) | `50` |
| `offset` | integer | Skip first N results | `0` |
| `registrable` | string | Filter by exact domain name | `sbi-login.co.in` |
| `seed_registrable` | string | Filter by original brand | `sbi.co.in` |
| `cse_id` | string | Filter by brand/CSE ID | `SBI` |
| `has_verdict` | boolean | Filter by verdict presence | `true` |
| `verdict` | string | Filter by verdict value | `phishing`, `suspicious`, `parked` |
| `risk_score_min` | integer | Minimum risk score (0-100) | `70` |
| `risk_score_max` | integer | Maximum risk score (0-100) | `100` |
| `is_newly_registered` | boolean | Newly registered domains | `true` |

**Response**:
```json
{
  "success": true,
  "collection": "domains",
  "count": 15,
  "limit": 50,
  "offset": 0,
  "filters": {
    "seed_registrable": "sbi.co.in",
    "verdict": "phishing"
  },
  "domains": [
    {
      "id": "sbi-login.co.in:def456...",
      "metadata": {
        "registrable": "sbi-login.co.in",
        "seed_registrable": "sbi.co.in",
        "cse_id": "SBI",
        "has_verdict": true,
        "verdict": "phishing",
        "risk_score": 85,
        "is_newly_registered": true,
        "domain_age_days": 3,
        "form_count": 1,
        "password_fields": 1,
        "has_credential_form": true,
        "country": "US"
      },
      "document": "🚨 VERDICT: PHISHING (Risk Score: 85/100)..."
    }
  ]
}
```

**Examples**:

```bash
# Get all phishing variants
curl "http://localhost:3000/api/chroma/variants?verdict=phishing&limit=100"

# Get variants of SBI
curl "http://localhost:3000/api/chroma/variants?seed_registrable=sbi.co.in"

# Get high-risk domains (score >= 70)
curl "http://localhost:3000/api/chroma/variants?risk_score_min=70&has_verdict=true"

# Get newly registered suspicious domains
curl "http://localhost:3000/api/chroma/variants?is_newly_registered=true&verdict=suspicious"

# Get all variants for a specific CSE/brand
curl "http://localhost:3000/api/chroma/variants?cse_id=ICICI&limit=200"
```

---

### 4. Semantic Search

Perform natural language semantic search across collections.

**Endpoint**: `GET /api/chroma/search`

**Query Parameters**:

| Parameter | Type | Required | Description | Example |
|-----------|------|----------|-------------|---------|
| `query` | string | ✅ Yes | Natural language search query | `phishing sites with login forms` |
| `collection` | string | No | Which collection(s) to search | `both` (default), `originals`, `variants` |
| `limit` | integer | No | Results per collection (max: 50) | `5` |

**Response**:
```json
{
  "success": true,
  "query": "phishing sites with login forms",
  "collection_type": "both",
  "limit": 5,
  "results": {
    "originals": [],
    "variants": [
      {
        "id": "sbi-secure-login.co.in:xyz789...",
        "metadata": {
          "registrable": "sbi-secure-login.co.in",
          "verdict": "phishing",
          "risk_score": 92,
          "has_credential_form": true,
          "password_fields": 2
        },
        "document": "🚨 VERDICT: PHISHING (Risk Score: 92/100)...",
        "distance": 0.15,
        "similarity": "0.8500"
      }
    ]
  }
}
```

**Similarity Score**:
- Range: 0.0 to 1.0
- Higher = more similar to query
- `similarity = 1 - distance`

**Examples**:

```bash
# Search for credential harvesting sites
curl "http://localhost:3000/api/chroma/search?query=credential%20harvesting%20forms&collection=variants&limit=10"

# Search for banking domains
curl "http://localhost:3000/api/chroma/search?query=banking%20financial%20institutions&collection=originals"

# Search for newly registered suspicious domains
curl "http://localhost:3000/api/chroma/search?query=new%20domain%20parked%20suspicious&collection=variants"

# Search for SSL certificate issues
curl "http://localhost:3000/api/chroma/search?query=self-signed%20certificate%20mismatch"
```

---

### 5. Get Domain Details

Retrieve full details for a specific domain (searches both collections).

**Endpoint**: `GET /api/chroma/domain/:domain`

**Path Parameters**:
- `:domain` - The full domain name (e.g., `sbi.bank.in`)

**Response for Original Seed**:
```json
{
  "success": true,
  "domain": "sbi.bank.in",
  "collection": "original_domains",
  "is_original_seed": true,
  "data": {
    "id": "sbi.bank.in:2f3f481c22e4a12c",
    "metadata": {
      "registrable": "bank.in",
      "cse_id": "SBI",
      "is_original_seed": true,
      "has_verdict": true,
      "verdict": "benign",
      "domain_age_days": 7547,
      "country": "IN",
      "dnstwist_variants_registered": 127,
      "dnstwist_variants_unregistered": 453,
      "dnstwist_total_generated": 580,
      "dnstwist_processed_at": 1697654321
    },
    "document": "Domain: sbi.bank.in\nURL: https://sbi.bank.in/\n📡 DNS Records:\n..."
  },
  "dnstwist_stats": {
    "variants_registered": 127,
    "variants_unregistered": 453,
    "total_variants_generated": 580,
    "processed_at": 1697654321,
    "processed_date": "2025-10-17T13:15:21.000Z"
  }
}
```

**Response for Variant Domain**:
```json
{
  "success": true,
  "domain": "sbi-login.bank.in",
  "collection": "domains",
  "is_original_seed": false,
  "data": {
    "id": "sbi-login.bank.in:abc456def789",
    "metadata": {
      "registrable": "bank.in",
      "seed_registrable": "sbi.bank.in",
      "cse_id": "SBI",
      "verdict": "phishing",
      "risk_score": 85
    },
    "document": "🚨 VERDICT: PHISHING (Risk Score: 85/100)..."
  }
}
```

**Note**: `dnstwist_stats` section only appears for original seed domains.

**Examples**:

```bash
# Get details for an original domain
curl "http://localhost:3000/api/chroma/domain/sbi.co.in"

# Get details for a variant
curl "http://localhost:3000/api/chroma/domain/sbi-login.co.in"

# Check if domain exists
curl "http://localhost:3000/api/chroma/domain/example.com"
# Returns 404 if not found
```

---

### 6. Collection Statistics

Get statistics about the collections.

**Endpoint**: `GET /api/chroma/stats`

**Response**:
```json
{
  "success": true,
  "chroma_host": "localhost:8000",
  "collections": {
    "originals": {
      "name": "original_domains",
      "count": 28
    },
    "variants": {
      "name": "domains",
      "count": 3547
    }
  },
  "timestamp": "2025-10-17T10:30:00.000Z"
}
```

**Example**:
```bash
curl "http://localhost:3000/api/chroma/stats"
```

---

## Usage Examples

### Example 1: Monitor All SBI Phishing Variants

```bash
# Get all phishing variants targeting SBI
curl "http://localhost:3000/api/chroma/variants?seed_registrable=sbi.co.in&verdict=phishing&limit=100" \
  | jq '.domains[] | {domain: .metadata.registrable, score: .metadata.risk_score, age: .metadata.domain_age_days}'
```

**Output**:
```json
{
  "domain": "sbi-secure-login.co.in",
  "score": 92,
  "age": 2
}
{
  "domain": "sbi-netbanking-verify.com",
  "score": 88,
  "age": 5
}
```

### Example 2: Find Credential Harvesting Sites

```bash
# Semantic search for credential harvesting
curl "http://localhost:3000/api/chroma/search?query=credential%20harvesting%20login%20password&collection=variants&limit=20" \
  | jq '.results.variants[] | select(.metadata.has_credential_form == true) | {domain: .metadata.registrable, score: .metadata.risk_score}'
```

### Example 3: Export All Original Brands

```bash
# Get all original domains with pagination
for i in {0..2..1}; do
  curl "http://localhost:3000/api/chroma/originals?limit=10&offset=$((i*10))" \
    | jq -r '.domains[] | .metadata.registrable'
done
```

### Example 4: Monitor New Registrations

```bash
# Get newly registered domains (< 30 days) with high risk
curl "http://localhost:3000/api/chroma/variants?is_newly_registered=true&risk_score_min=60&limit=50" \
  | jq '.domains[] | {domain: .metadata.registrable, age_days: .metadata.domain_age_days, score: .metadata.risk_score, verdict: .metadata.verdict}'
```

### Example 5: JavaScript/Python Integration

**JavaScript (Node.js)**:
```javascript
const axios = require('axios');

async function getPhishingVariants(brand) {
  try {
    const response = await axios.get('http://localhost:3000/api/chroma/variants', {
      params: {
        seed_registrable: brand,
        verdict: 'phishing',
        limit: 100
      }
    });

    return response.data.domains.map(d => ({
      domain: d.metadata.registrable,
      score: d.metadata.risk_score,
      age: d.metadata.domain_age_days
    }));
  } catch (error) {
    console.error('Error:', error.message);
  }
}

// Usage
getPhishingVariants('sbi.co.in').then(variants => {
  console.log('Phishing variants:', variants);
});
```

**Python**:
```python
import requests

def get_phishing_variants(brand, min_score=70):
    url = "http://localhost:3000/api/chroma/variants"
    params = {
        "seed_registrable": brand,
        "verdict": "phishing",
        "risk_score_min": min_score,
        "limit": 100
    }

    response = requests.get(url, params=params)
    data = response.json()

    if data['success']:
        return [
            {
                'domain': d['metadata']['registrable'],
                'score': d['metadata']['risk_score'],
                'age': d['metadata'].get('domain_age_days', 'N/A')
            }
            for d in data['domains']
        ]
    return []

# Usage
variants = get_phishing_variants('sbi.co.in', min_score=80)
for v in variants:
    print(f"{v['domain']} - Score: {v['score']}, Age: {v['age']} days")
```

---

## Error Handling

### Common Error Responses

**400 Bad Request**:
```json
{
  "success": false,
  "error": "Missing required parameter: query"
}
```

**404 Not Found**:
```json
{
  "success": false,
  "error": "Domain not found",
  "domain": "nonexistent.com"
}
```

**500 Internal Server Error**:
```json
{
  "success": false,
  "error": "Failed to query variant domains",
  "details": "Connection refused to ChromaDB"
}
```

**503 Service Unavailable**:
```json
{
  "success": false,
  "error": "ChromaDB client not initialized"
}
```

---

## Metadata Fields Reference

### Common Fields (All Records)

| Field | Type | Description |
|-------|------|-------------|
| `registrable` | string | Registrable domain (eTLD+1) |
| `cse_id` | string | Brand/CSE identifier |
| `seed_registrable` | string | Original brand domain |
| `is_original_seed` | boolean | True if original, false if variant |
| `has_verdict` | boolean | Whether domain has been scored |

### Verdict Fields

| Field | Type | Description |
|-------|------|-------------|
| `verdict` | string | `clean`, `suspicious`, `phishing`, `parked` |
| `risk_score` | integer | Risk score (0-100) |
| `confidence` | float | Confidence level (0.0-1.0) |

### Domain Fields

| Field | Type | Description |
|-------|------|-------------|
| `domain_age_days` | integer | Domain age in days |
| `is_newly_registered` | boolean | < 30 days old |
| `is_very_new` | boolean | < 7 days old |
| `country` | string | Hosting country code |
| `a_count` | integer | Number of A records |
| `mx_count` | integer | Number of MX records |

### Page Analysis Fields

| Field | Type | Description |
|-------|------|-------------|
| `form_count` | integer | Number of forms |
| `password_fields` | integer | Password input fields |
| `email_fields` | integer | Email input fields |
| `has_credential_form` | boolean | Has login form |
| `html_size` | integer | HTML size in bytes |
| `external_links` | integer | External link count |
| `iframe_count` | integer | Number of iframes |

### SSL/Certificate Fields

| Field | Type | Description |
|-------|------|-------------|
| `uses_https` | boolean | Has SSL certificate |
| `is_self_signed` | boolean | Self-signed cert |
| `domain_mismatch` | boolean | Cert domain mismatch |
| `cert_age_days` | integer | Certificate age |

### File Paths (for artifacts)

| Field | Type | Description |
|-------|------|-------------|
| `html_path` | string | Path to HTML file |
| `pdf_path` | string | Path to PDF snapshot |
| `screenshot_path` | string | Path to screenshot |

---

## Rate Limiting

The API uses rate limiting to prevent abuse:
- **Limit**: 100 requests per 15 minutes per IP
- **Response Header**: `X-RateLimit-Remaining`

If you exceed the limit:
```json
{
  "success": false,
  "error": "Too many requests from this IP, please try again later."
}
```

---

## Best Practices

1. **Pagination**: Always use `limit` and `offset` for large result sets
2. **Filtering**: Apply filters to reduce result size and improve performance
3. **Caching**: Cache results when possible (e.g., original domains rarely change)
4. **Error Handling**: Always check `success` field before processing results
5. **Semantic Search**: Use natural language queries for exploration; use filters for precision

---

## Support

For issues or questions:
- Check ChromaDB connection: `GET /api/chroma/stats`
- View server logs for detailed error messages
- Ensure ChromaDB service is running: `docker ps | grep chroma`

---

## Changelog

**Version 1.0 (2025-10-17)**:
- Initial release
- Support for two collections: `original_domains` and `domains`
- 6 query endpoints with comprehensive filtering
- Semantic search with natural language
- Full metadata extraction and enrichment
