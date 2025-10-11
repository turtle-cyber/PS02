# ChromaDB Schema Documentation

## Overview

The ChromaDB ingestor uses a **unified schema** where domain data and feature data are merged into **single records** keyed by the **registrable domain**.

## Primary Key Strategy

**ID = Registrable Domain (lowercase)**

Examples:
- `sbi.solutions` → ID: `"sbi.solutions"`
- `onlinesbi.co.in` → ID: `"onlinesbi.co.in"`
- `phishing-site.com` → ID: `"phishing-site.com"`

### Why Registrable Domain?

- **Unique per site**: Each registrable domain represents one organization/site
- **Merges naturally**: Domain data (DNS, WHOIS) + Feature data (crawled webpage) share the same key
- **Supports updates**: When features are crawled later, they automatically merge with existing domain records via upsert

## Record Types

Records in ChromaDB can have three types (indicated by `record_type` metadata):

### 1. `"domain"` - Domain-only records
Contains DNS, WHOIS, GeoIP data but **no webpage features** (not yet crawled)

```json
{
  "id": "onlinesbi.co.in",
  "metadata": {
    "record_type": "domain",
    "registrable": "onlinesbi.co.in",
    "cse_id": "SBI",
    "has_features": false,
    "a_count": 1,
    "mx_count": 2,
    "country": "IN",
    "registrar": "GoDaddy"
  },
  "document": "Domain: onlinesbi.co.in\nRegistrable: onlinesbi.co.in\n..."
}
```

### 2. `"features"` - Feature-only records
Contains webpage features but **no domain data** (domain not in DNS resolver output)

```json
{
  "id": "sbi.solutions",
  "metadata": {
    "record_type": "features",
    "registrable": "sbi.solutions",
    "url": "https://sbi.solutions/",
    "has_features": true,
    "form_count": 1,
    "password_fields": 1,
    "has_credential_form": true
  },
  "document": "URL: https://sbi.solutions/\nForms -> Count: 1, Password Fields: 1\n..."
}
```

### 3. `"merged"` - Complete records ⭐
Contains **both** domain data AND webpage features (the ideal state)

```json
{
  "id": "sbi.solutions",
  "metadata": {
    "record_type": "merged",
    "registrable": "sbi.solutions",
    "url": "https://sbi.solutions/",
    "has_features": true,
    "cse_id": "SBI",
    "a_count": 1,
    "mx_count": 0,
    "country": "US",
    "form_count": 1,
    "password_fields": 1,
    "has_credential_form": true,
    "phishing_keywords": "login,verify"
  },
  "document": "Domain: sbi.solutions\nDNS -> A: 1.2.3.4\n...\n--- Page Features ---\nURL: https://sbi.solutions/\nForms -> Count: 1..."
}
```

## Data Flow

### Timeline of a Record

1. **Stage 1: Domain discovered** (from ct-watcher or dnstwist)
   ```
   ID: "sbi.solutions"
   Type: "domain"
   Data: DNS, WHOIS, GeoIP
   ```

2. **Stage 2: Features extracted** (from feature-crawler)
   ```
   ID: "sbi.solutions" (same ID!)
   Type: "merged" (upserted with features)
   Data: DNS, WHOIS, GeoIP + URL features, forms, HTML analysis
   ```

### ChromaDB Upsert Behavior

When the ingestor processes a feature record for `sbi.solutions`:

1. **Check if record exists**: Look for ID `"sbi.solutions"`
2. **If exists**: Update the record with new feature data (merge)
3. **If not exists**: Create new record with feature data

This means:
- If domain data arrived first, features are **added** to it
- If features arrive first, they create a new record (domain data can be added later)
- The **text embedding is regenerated** on each upsert to reflect all available data

## Metadata Fields

### Common Fields (all records)
| Field | Type | Description |
|-------|------|-------------|
| `record_type` | string | "domain", "features", or "merged" |
| `registrable` | string | Registrable domain (eTLD+1) |
| `cse_id` | string | Brand/CSE identifier (e.g., "SBI", "ICICI") |
| `seed_registrable` | string | Original seed domain from config |

### Domain-only Fields
| Field | Type | Description |
|-------|------|-------------|
| `a_count` | int | Number of A (IPv4) records |
| `mx_count` | int | Number of MX records |
| `ns_count` | int | Number of NS records |
| `country` | string | GeoIP country code |
| `registrar` | string | Domain registrar name |

#### Domain Age (WHOIS) ✨
| Field | Type | Description |
|-------|------|-------------|
| `domain_age_days` | int | Age of domain in days since creation |
| `is_newly_registered` | bool | ⚠️ Domain registered < 30 days ago |
| `is_very_new` | bool | 🚨 Domain registered < 7 days ago |
| `days_until_expiry` | int | Days until domain registration expires |

**Why it matters**: 90% of phishing domains are less than 30 days old. Newly registered domains mimicking established brands are highly suspicious.

### Feature-only Fields
| Field | Type | Description |
|-------|------|-------------|
| `url` | string | Full URL that was crawled |
| `has_features` | bool | Always true for feature records |
| `url_length` | int | Character count of URL |
| `url_entropy` | float | Shannon entropy of URL |
| `num_subdomains` | int | Number of subdomain labels |
| `has_repeated_digits` | bool | URL contains repeated digits |
| `is_idn` | bool | Uses internationalized domain names |
| `mixed_script` | bool | Mixes different Unicode scripts |
| `form_count` | int | Number of HTML forms on page |
| `password_fields` | int | Number of password input fields |
| `email_fields` | int | Number of email input fields |
| `has_credential_form` | bool | ⚠️ Has both password + email fields |
| `phishing_keywords` | string | Comma-separated keywords found |
| `keyword_count` | int | Count of phishing keywords |
| `html_size` | int | HTML document size in bytes |
| `external_links` | int | Number of outbound links |
| `iframe_count` | int | Number of iframes (potential embedding) |

#### SSL Certificate Analysis ✨
| Field | Type | Description |
|-------|------|-------------|
| `is_self_signed` | bool | 🚨 Certificate is self-signed (not from trusted CA) |
| `cert_age_days` | int | Days since certificate was issued |
| `is_newly_issued` | bool | ⚠️ Certificate issued < 30 days ago |
| `cert_is_very_new` | bool | 🚨 Certificate issued < 7 days ago |
| `has_domain_mismatch` | bool | Certificate CN doesn't match hostname |
| `trusted_issuer` | string | Issuer CommonName (e.g., "Let's Encrypt") |
| `cert_risk_score` | int | 0-100 risk score (higher = more suspicious) |

**Why it matters**: Self-signed certificates are the #1 phishing indicator. Legitimate sites use trusted CAs. Newly issued certificates on new domains indicate fresh phishing campaigns.

#### Enhanced Form Analysis ✨
| Field | Type | Description |
|-------|------|-------------|
| `suspicious_form_count` | int | Number of forms with suspicious attributes |
| `has_suspicious_forms` | bool | ⚠️ Page contains forms submitting to IPs/suspicious TLDs |
| `forms_to_ip` | int | Forms submitting to IP addresses |
| `forms_to_suspicious_tld` | int | Forms submitting to .tk/.ml/.ga/.xyz/etc |
| `forms_to_private_ip` | int | Forms submitting to localhost/private IPs |

**Why it matters**: Phishing forms often submit credentials to external IP addresses, free TLDs (.tk, .ml), or localhost (for local data harvesting). Legitimate sites submit to their own domain.

**Suspicious TLDs**: `.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.xyz`, `.top`, `.club`, `.info`, `.online`, `.site`, `.website`, `.space`, `.tech`

#### JavaScript Analysis ✨
| Field | Type | Description |
|-------|------|-------------|
| `js_obfuscated` | bool | ⚠️ JavaScript uses obfuscation techniques |
| `js_eval_count` | int | Number of eval() calls (code execution) |
| `js_encoding_count` | int | atob/fromCharCode usage (encoded strings) |
| `js_keylogger` | bool | 🚨 Keylogger patterns detected |
| `js_form_manipulation` | bool | ⚠️ Forms dynamically modified via JS |
| `js_redirect_detected` | bool | JavaScript-based redirects detected |
| `js_risk_score` | int | 0-100 risk score for JavaScript behavior |

**Why it matters**: Phishing sites heavily obfuscate JavaScript to hide malicious behavior. Keyloggers capture credentials before submission. Form manipulation bypasses browser security warnings.

**Detection patterns**:
- **Obfuscation**: `eval()`, `atob()`, `String.fromCharCode()`
- **Keyloggers**: Multiple `addEventListener("keypress")` or `addEventListener("keydown")`
- **Form manipulation**: `document.createElement("form")`, `form.action = ...`
- **Redirects**: `window.location.href`, `document.location.replace()`

#### Favicon Analysis ✨
| Field | Type | Description |
|-------|------|-------------|
| `favicon_md5` | string | MD5 hash of favicon image |
| `favicon_sha256` | string | SHA256 hash of favicon image |

**Why it matters**: Phishing sites steal favicons from legitimate brands. By hashing favicons, we can detect when multiple suspicious domains use the exact same icon as a trusted site (e.g., all fake SBI sites use the real SBI favicon).

**Use case**: Build database of legitimate brand favicons, then flag any new suspicious domain using the same hash.

#### Redirect Tracking ✨
| Field | Type | Description |
|-------|------|-------------|
| `redirect_count` | int | Number of redirects before reaching final page |
| `had_redirects` | bool | Page performed HTTP or JS redirects |
| `initial_url` | string | Original URL requested |
| `final_url` | string | Final destination URL after all redirects |

**Why it matters**: Phishing campaigns often use redirect chains to evade detection (e.g., compromised site → URL shortener → phishing page). Tracking the full chain reveals infrastructure.

**Note**: Feature extraction occurs **only on the final destination page**, but the full redirect chain is logged for forensic analysis.

## Important Guarantees

### ✅ URL-to-Domain Mapping
- **Every feature record has a `url` field** pointing to the exact URL crawled
- **Every feature record has a `registrable` field** linking it to the domain
- Example: `{"url": "https://sbi.solutions/login", "registrable": "sbi.solutions"}`

### ✅ No Cross-Domain Pollution
- Features for `sbi.solutions` will **only** be stored under ID `"sbi.solutions"`
- Features for `onlinesbi.co.in` will **only** be stored under ID `"onlinesbi.co.in"`
- No mixing between different domains

### ✅ Empty Features = No Data
- If a domain has **not been crawled**, it will have `record_type: "domain"` and no feature fields
- You can filter for domains without features: `where={"has_features": {"$ne": True}}`

### ⚠️ One URL per Domain
- Current limitation: Only **one URL per registrable domain** is stored
- If you crawl both `/` and `/login` for the same domain, the **last one wins**
- This is because we use registrable domain as the primary key

## Query Examples

### Find domains with features
```python
collection.query(
    query_texts=["phishing login page"],
    where={"has_features": True},
    n_results=10
)
```

### Find domains WITHOUT features (need to crawl)
```python
collection.query(
    query_texts=["suspicious bank domain"],
    where={"record_type": "domain"},  # Only domain data, no features yet
    n_results=10
)
```

### Find high-risk credential harvesting pages
```python
collection.query(
    query_texts=["fake login page"],
    where={
        "has_credential_form": True,
        "keyword_count": {"$gte": 2}
    },
    n_results=10
)
```

### Find all records for a specific brand
```python
collection.query(
    query_texts=["state bank india"],
    where={"cse_id": "SBI"},
    n_results=50
)
```

### Get merged records only
```python
collection.query(
    query_texts=["phishing website"],
    where={"record_type": "merged"},  # Only records with both domain + features
    n_results=10
)
```

### 🚨 Find newly registered domains with self-signed certificates ✨
```python
collection.query(
    query_texts=["login banking credentials"],
    where={
        "$and": [
            {"is_very_new": True},           # Domain < 7 days old
            {"is_self_signed": True}         # Self-signed certificate
        ]
    },
    n_results=20
)
```

### 🚨 Find domains with keyloggers and credential forms ✨
```python
collection.query(
    query_texts=["phishing page"],
    where={
        "$and": [
            {"js_keylogger": True},          # Keylogger detected
            {"has_credential_form": True}    # Has password + email form
        ]
    },
    n_results=10
)
```

### ⚠️ Find pages with suspicious form submissions ✨
```python
collection.query(
    query_texts=["fake payment page"],
    where={
        "$or": [
            {"forms_to_ip": {"$gt": 0}},           # Forms submit to IP address
            {"forms_to_suspicious_tld": {"$gt": 0}} # Forms submit to .tk/.ml/etc
        ]
    },
    n_results=15
)
```

### 🔍 Find domains with high SSL risk scores ✨
```python
collection.query(
    query_texts=["secure login"],
    where={
        "cert_risk_score": {"$gte": 50}    # Risk score >= 50
    },
    n_results=10
)
```

### 🔍 Find domains using specific favicon (brand impersonation) ✨
```python
# First, get the legitimate brand favicon hash
legit_hash = "a1b2c3d4e5f6..."  # SBI's real favicon MD5

# Find all domains using the same favicon
collection.query(
    query_texts=["online banking"],
    where={
        "$and": [
            {"favicon_md5": legit_hash},     # Same favicon as SBI
            {"cse_id": "SBI"},               # Tagged as SBI-related
            {"is_newly_registered": True}    # But newly registered
        ]
    },
    n_results=20
)
```

### 🔍 Find domains with obfuscated JavaScript ✨
```python
collection.query(
    query_texts=["phishing site"],
    where={
        "$and": [
            {"js_obfuscated": True},         # Uses eval/atob/etc
            {"js_risk_score": {"$gte": 40}}  # High JS risk score
        ]
    },
    n_results=10
)
```

### 🔍 Find domains with redirect chains ✨
```python
collection.query(
    query_texts=["redirect phishing"],
    where={
        "redirect_count": {"$gte": 2}  # 2+ redirects before landing
    },
    n_results=10
)
```

### 🚨 ULTIMATE HIGH-RISK QUERY - Combine all indicators ✨
```python
collection.query(
    query_texts=["phishing login credentials"],
    where={
        "$and": [
            {"is_newly_registered": True},      # New domain
            {"has_credential_form": True},      # Asks for credentials
            {"$or": [
                {"is_self_signed": True},       # Self-signed cert
                {"cert_risk_score": {"$gte": 40}}  # OR high cert risk
            ]},
            {"$or": [
                {"js_keylogger": True},         # Keylogger detected
                {"has_suspicious_forms": True}, # OR suspicious form submission
                {"js_obfuscated": True}         # OR obfuscated JS
            ]}
        ]
    },
    n_results=50
)
```

## Configuration

In `docker-compose.yml`:

```yaml
chroma-ingestor:
  environment:
    - KAFKA_TOPIC=domains.resolved          # Domain data
    - KAFKA_FEATURES_TOPIC=phish.features.page  # Feature data
    - CHROMA_COLLECTION=domains             # Single unified collection
```

Both topics feed into the **same collection** using the **same ID strategy** (registrable domain), ensuring automatic merging.
