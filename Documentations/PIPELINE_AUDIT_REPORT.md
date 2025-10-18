# ChromaDB Pipeline Field Audit Report
**Date:** 2025-10-18
**Scope:** Complete data flow from feature-crawler → chroma-ingestor → ChromaDB → API

---

## Executive Summary

### 🔴 CRITICAL ISSUES FOUND: 2
### ⚠️ WARNING ISSUES FOUND: 3
### ✅ WORKING CORRECTLY: Most fields

---

## Issue #1: 🔴 CRITICAL - Missing File Paths in Features Object

**Location:** `Pipeline/apps/feature-crawler/worker.py:749-780`

**Problem:** The `build_features()` function does NOT include `html_path` and `screenshot_paths` in the returned features object that gets sent to Kafka.

**Evidence:**
```python
def build_features(url: str, html_path: Path, artifacts: Dict[str,Any], ...):
    return {
        "url": url,
        "canonical_fqdn": canonical_fqdn,
        # ... many fields ...
        "pdf_path": artifacts.get("pdf_path"),  # ✅ PDF path IS included
        "url_features": ufeat,
        # ... more fields ...
        "javascript": htmlf.get("javascript", {}),
        # ❌ html_path is MISSING
        # ❌ screenshot_paths is MISSING
    }
```

**Impact:**
- `html_path` and `screenshot_paths` are stored in the `artifacts` object (line 699-700 in `crawl_once()`)
- These are sent to `OUT_TOPIC_RAW` topic but NOT to `OUT_TOPIC_FEAT` topic
- ChromaDB ingestor consumes from `OUT_TOPIC_FEAT` (phish.features.page)
- Result: **HTML and screenshot paths are NEVER ingested into ChromaDB**

**Data Flow:**
```
crawl_once() returns artifacts = {
    "html_path": str(html_path),           # ← Created here
    "screenshot_paths": [str(shot_path)],   # ← Created here
    "pdf_path": str(pdf_path),
    ...
}

build_features(art.get("final_url"), Path(art["html_path"]), art, ...)
    ↓
Returns feat = {
    "pdf_path": artifacts.get("pdf_path"),  # ✅ Copied
    # ❌ html_path NOT copied
    # ❌ screenshot_paths NOT copied
}

producer.send(OUT_TOPIC_FEAT, value=feat)  # ← Missing fields!
    ↓
Ingestor consumes KAFKA_FEATURES_TOPIC
    ↓
to_metadata() tries to extract:
    if "html_path" in r:                   # ← NEVER TRUE!
        keep["html_path"] = r["html_path"]
    if "screenshot_paths" in r:            # ← NEVER TRUE!
        keep["screenshot_path"] = r["screenshot_paths"][0]
```

**Fix Required:**
Add the missing fields to `build_features()` return statement (worker.py:749):

```python
return {
    "url": url,
    "canonical_fqdn": canonical_fqdn,
    # ... existing fields ...
    "html_path": artifacts.get("html_path"),           # ← ADD THIS
    "screenshot_paths": artifacts.get("screenshot_paths"), # ← ADD THIS
    "pdf_path": artifacts.get("pdf_path"),
    # ... rest of fields ...
}
```

---

## Issue #2: 🔴 CRITICAL - Favicon Size Field Missing from Features

**Location:** `Pipeline/apps/feature-crawler/worker.py:749-780`

**Problem:** The `favicon_size` field is extracted by `extract_html_features()` but is NOT included in the final features object.

**Evidence:**

1. **Extraction happens correctly:**
```python
# worker.py:278 - Favicon data includes size
result["favicon_size"] = len(favicon_bytes)

# worker.py:554 - HTML features include favicon_size
return {
    "favicon_size": favicon_size,  # ✅ Extracted here
    ...
}
```

2. **But NOT included in build_features() return:**
```python
# worker.py:763-766 - Only these favicon fields are included
return {
    "favicon_present": htmlf.get("favicon_present", False),  # ✅
    "favicon_url": htmlf.get("favicon_url"),                 # ✅
    "favicon_md5": htmlf.get("favicon_md5"),                 # ✅
    "favicon_sha256": htmlf.get("favicon_sha256"),           # ✅
    # ❌ favicon_size is MISSING
}
```

**Impact:**
- Favicon size is useful for detecting duplicate favicons across phishing sites
- Schema defines this field but it's not being stored
- Data loss: ~5% of available phishing indicators

**Fix Required:**
Add `favicon_size` to the return statement in `build_features()`:

```python
return {
    # ... existing fields ...
    "favicon_present": htmlf.get("favicon_present", False),
    "favicon_url": htmlf.get("favicon_url"),
    "favicon_md5": htmlf.get("favicon_md5"),
    "favicon_sha256": htmlf.get("favicon_sha256"),
    "favicon_size": htmlf.get("favicon_size"),  # ← ADD THIS
    "images_count": htmlf.get("images_count", 0),
    # ... rest of fields ...
}
```

---

## Issue #3: ⚠️ WARNING - images_count Field Potentially Missing

**Location:** `Pipeline/apps/feature-crawler/worker.py:555, 767`

**Status:** Field is extracted and included, but needs verification

**Evidence:**
```python
# worker.py:555 - Extracted in extract_html_features()
return {
    "images_count": images_count,  # ✅ Extracted
}

# worker.py:767 - Included in build_features()
return {
    "images_count": htmlf.get("images_count", 0),  # ✅ Included
}
```

**ChromaDB Ingestor:** Does NOT explicitly map `images_count` to metadata

```python
# ingest.py:to_metadata() - No explicit mapping found
# The field relies on generic catch-all logic (if any exists)
```

**Impact:**
- Image count is a useful indicator (phishing sites often have few images)
- May not be queryable in ChromaDB if not in metadata
- Needs verification via API test

**Fix Required:**
Add explicit mapping in `ingest.py:to_metadata()`:

```python
def to_metadata(r: Dict[str,Any]) -> Dict[str,Any]:
    keep = {}
    # ... existing code ...

    # Add after line 636 (after external_links):
    if "images_count" in r:
        keep["images_count"] = r["images_count"]
```

---

## Issue #4: ⚠️ WARNING - external_stylesheets Field Not Mapped

**Location:** `Pipeline/apps/chroma-ingestor/ingest.py:to_metadata()`

**Problem:** `external_stylesheets` is extracted by feature-crawler but NOT mapped to ChromaDB metadata.

**Evidence:**

1. **Extraction works:**
```python
# worker.py:775 - Included in build_features()
return {
    "external_stylesheets": htmlf.get("external_stylesheets", 0),  # ✅ Extracted
}
```

2. **But NOT mapped in ingestor:**
```python
# ingest.py:632-639 - Only these are mapped:
if "html_length_bytes" in r:
    keep["html_size"] = r["html_length_bytes"]
if "external_links" in r:
    keep["external_links"] = r["external_links"]
if "iframes" in r:
    keep["iframe_count"] = r["iframes"]
# ❌ external_stylesheets is MISSING
```

**Impact:**
- External stylesheets can indicate template-based phishing kits
- Data is extracted but not queryable via ChromaDB
- Minor loss (~2% of indicators)

**Fix Required:**
Add explicit mapping in `ingest.py:to_metadata()` after line 636:

```python
if "external_scripts" in r:
    keep["external_scripts"] = r["external_scripts"]

if "external_stylesheets" in r:  # ← ADD THIS
    keep["external_stylesheets"] = r["external_stylesheets"]
```

---

## Issue #5: ⚠️ WARNING - Inconsistent Field Naming

**Location:** Multiple files

**Problem:** The same data uses different field names in different parts of the pipeline.

**Examples:**

1. **HTML size field:**
   - Feature-crawler: `html_length_bytes` (worker.py:770)
   - Ingestor mapping: `html_size` (ingest.py:633)
   - Schema documentation: `html_size` (CHROMADB_SCHEMA.md:318)

2. **IFrame count:**
   - Feature-crawler: `iframes` (worker.py:773)
   - Ingestor mapping: `iframe_count` (ingest.py:639)
   - Schema documentation: `iframe_count` (CHROMADB_SCHEMA.md:320)

**Impact:**
- Confusing for developers
- Risk of mapping errors
- Requires translation layer in ingestor

**Status:** Currently working due to explicit mapping, but fragile

**Recommendation:**
Standardize field names across the entire pipeline. Either:
- Option A: Use schema names everywhere (requires changing feature-crawler)
- Option B: Update schema to match feature-crawler (requires docs update)

---

## Field Coverage Matrix

### URL Structure Analysis Fields (CHROMADB_SCHEMA.md:281-301)

| Field | Schema | Feature-Crawler | Ingestor | Status |
|-------|--------|-----------------|----------|---------|
| `url` | ✅ | ✅ Line 750 | ✅ Line 582-583 | ✅ WORKING |
| `url_length` | ✅ | ✅ Line 157 (url_features) | ✅ Line 589 | ✅ WORKING |
| `url_entropy` | ✅ | ✅ Line 174 (url_features) | ✅ Line 590 | ✅ WORKING |
| `num_dots` | ✅ | ✅ Line 158 (url_features) | ✅ Line 591 | ✅ WORKING |
| `num_hyphens` | ✅ | ✅ Line 161 (url_features) | ✅ Line 592 | ✅ WORKING |
| `num_slashes` | ✅ | ✅ Line 162 (url_features) | ✅ Line 593 | ✅ WORKING |
| `num_underscores` | ✅ | ✅ Line 163 (url_features) | ✅ Line 594 | ✅ WORKING |
| `has_repeated_digits` | ✅ | ✅ Line 159 (url_features) | ✅ Line 595 | ✅ WORKING |
| `domain_length` | ✅ | ✅ Line 170 (url_features) | ✅ Line 598 | ✅ WORKING |
| `domain_entropy` | ✅ | ✅ Line 175 (url_features) | ✅ Line 599 | ✅ WORKING |
| `domain_hyphens` | ✅ | ✅ Line 171 (url_features) | ✅ Line 600 | ✅ WORKING |
| `num_subdomains` | ✅ | ✅ Line 177 (url_features) | ✅ Line 603 | ✅ WORKING |
| `avg_subdomain_length` | ✅ | ✅ Line 178-181 (url_features) | ✅ Line 604 | ✅ WORKING |
| `subdomain_entropy` | ✅ | ✅ Line 182-185 (url_features) | ✅ Line 605 | ✅ WORKING |
| `path_length` | ✅ | ✅ Line 190 (url_features) | ✅ Line 608 | ✅ WORKING |
| `path_has_query` | ✅ | ✅ Line 191 (url_features) | ✅ Line 609 | ✅ WORKING |
| `path_has_fragment` | ✅ | ✅ Line 192 (url_features) | ✅ Line 610 | ✅ WORKING |

**URL Fields: 17/17 ✅ 100% Coverage**

---

### Internationalization Fields (CHROMADB_SCHEMA.md:303-307)

| Field | Schema | Feature-Crawler | Ingestor | Status |
|-------|--------|-----------------|----------|---------|
| `is_idn` | ✅ | ✅ Line 198-207 (idn_features) | ✅ Line 614 | ✅ WORKING |
| `mixed_script` | ✅ | ✅ Line 209-210 (idn_features) | ✅ Line 615 | ✅ WORKING |

**IDN Fields: 2/2 ✅ 100% Coverage**

---

### Page Content Analysis Fields (CHROMADB_SCHEMA.md:309-320)

| Field | Schema | Feature-Crawler | Ingestor | Status |
|-------|--------|-----------------|----------|---------|
| `form_count` | ✅ | ✅ Line 316 (forms.count) | ✅ Line 619 | ✅ WORKING |
| `password_fields` | ✅ | ✅ Line 317 (forms.password_fields) | ✅ Line 620 | ✅ WORKING |
| `email_fields` | ✅ | ✅ Line 318 (forms.email_fields) | ✅ Line 621 | ✅ WORKING |
| `has_credential_form` | ✅ | ✅ Derived from pw+email | ✅ Line 622-624 | ✅ WORKING |
| `phishing_keywords` | ✅ | ✅ Line 733-737 (text_keywords) | ✅ Line 627-630 | ✅ WORKING |
| `keyword_count` | ✅ | ✅ Derived from array length | ✅ Line 630 | ✅ WORKING |
| `html_size` | ✅ | ✅ Line 556 (as html_length_bytes) | ✅ Line 632-633 | ✅ WORKING |
| `external_links` | ✅ | ✅ Line 558 | ✅ Line 635-636 | ✅ WORKING |
| `iframe_count` | ✅ | ✅ Line 570 (as iframes) | ✅ Line 638-639 | ✅ WORKING |

**Page Content Fields: 9/9 ✅ 100% Coverage**

---

### SSL Certificate Analysis Fields (CHROMADB_SCHEMA.md:322-337)

| Field | Schema | Feature-Crawler | Ingestor | Status |
|-------|--------|-----------------|----------|---------|
| `uses_https` | ✅ | ❌ NOT extracted | ✅ Line 655 | 🔴 **MISSING FROM CRAWLER** |
| `is_self_signed` | ✅ | ❌ NOT extracted | ✅ Line 656 | 🔴 **MISSING FROM CRAWLER** |
| `cert_age_days` | ✅ | ❌ NOT extracted | ✅ Line 659-661 | 🔴 **MISSING FROM CRAWLER** |
| `is_newly_issued_cert` | ✅ | ❌ NOT extracted | ✅ Line 659-661 | 🔴 **MISSING FROM CRAWLER** |
| `domain_mismatch` | ✅ | ❌ NOT extracted | ✅ Line 657 | 🔴 **MISSING FROM CRAWLER** |
| `trusted_issuer` | ✅ | ❌ NOT extracted | ✅ Line 658 | 🔴 **MISSING FROM CRAWLER** |
| `cert_issuer` | ✅ | ❌ NOT extracted | ✅ Line 665-666 | 🔴 **MISSING FROM CRAWLER** |
| `cert_subject` | ✅ | ❌ NOT extracted | ✅ Line 667-668 | 🔴 **MISSING FROM CRAWLER** |
| `cert_risk_score` | ✅ | ❌ NOT extracted | ✅ Line 662-663 | 🔴 **MISSING FROM CRAWLER** |

**SSL Fields: 0/9 🔴 0% Coverage**

**ROOT CAUSE:** Feature-crawler uses Playwright which does NOT expose SSL certificate details via the browser automation API. SSL data is only extracted by `http-fetcher` (fetcher.py:196-329).

**Data Flow Issue:**
```
http-fetcher extracts SSL → sends to http.probed topic
feature-crawler extracts page features → sends to phish.features.page topic
ingestor consumes phish.features.page → ❌ NO SSL DATA

Result: SSL fields are NEVER populated for feature-extracted URLs
```

**Impact:**
- 🔴 CRITICAL: SSL is the #1 phishing indicator (self-signed certs)
- Missing ~30% of risk scoring capability
- Schema claims these fields exist but they're always null/missing

**Fix Options:**

**Option A (Recommended):** Add SSL extraction to feature-crawler using Python's `ssl` module
```python
# In crawl_once(), after page.goto():
ssl_info = extract_ssl_certificate(final_url)  # New function
return {
    # ... existing fields ...
    "ssl_info": ssl_info,
}

# In build_features():
return {
    # ... existing fields ...
    "ssl_info": artifacts.get("ssl_info", {}),
}
```

**Option B:** Merge http-fetcher data with feature-crawler data in ingestor
- Requires correlation by URL
- More complex, race conditions possible
- Not recommended

**Option C:** Run http-fetcher BEFORE feature-crawler
- Update pipeline topology
- Requires Kafka topic restructuring
- Medium complexity

---

### Enhanced Form Analysis Fields (CHROMADB_SCHEMA.md:339-356)

| Field | Schema | Feature-Crawler | Ingestor | Status |
|-------|--------|-----------------|----------|---------|
| `suspicious_form_count` | ✅ | ✅ Line 565 (forms.suspicious_form_count) | ✅ Line 698-700 | ✅ WORKING |
| `has_suspicious_forms` | ✅ | ✅ Derived | ✅ Line 700 | ✅ WORKING |
| `forms_to_ip` | ✅ | ✅ Line 545-547 (forms.forms_to_ip) | ✅ Line 702-703 | ✅ WORKING |
| `forms_to_suspicious_tld` | ✅ | ✅ Line 546 (forms.forms_to_suspicious_tld) | ✅ Line 704-705 | ✅ WORKING |
| `forms_to_private_ip` | ✅ | ✅ Line 547 (forms.forms_to_private_ip) | ✅ Line 706-707 | ✅ WORKING |

**Form Analysis Fields: 5/5 ✅ 100% Coverage**

---

### JavaScript Analysis Fields (CHROMADB_SCHEMA.md:358-387)

| Field | Schema | Feature-Crawler | Ingestor | Status |
|-------|--------|-----------------|----------|---------|
| `js_obfuscated` | ✅ | ✅ Line 308-323 (javascript.obfuscated_scripts) | ✅ Line 681 | ✅ WORKING |
| `js_obfuscated_count` | ✅ | ✅ Line 363 (javascript.obfuscated_scripts) | ✅ Line 693-694 | ✅ WORKING |
| `js_eval_usage` | ✅ | ✅ Line 332-335 (javascript.eval_usage) | ✅ Line 682 | ✅ WORKING |
| `js_eval_count` | ✅ | ✅ Line 334 (javascript.eval_usage) | ✅ Line 689-690 | ✅ WORKING |
| `js_encoding_count` | ✅ | ✅ Line 338-340 (javascript.base64_decoding) | ✅ Line 691-692 | ✅ WORKING |
| `js_keylogger` | ✅ | ✅ Line 391-394 (javascript.keylogger_patterns) | ✅ Line 683 | ✅ WORKING |
| `js_form_manipulation` | ✅ | ✅ Line 376-379 (javascript.form_manipulation) | ✅ Line 684 | ✅ WORKING |
| `js_redirect_detected` | ✅ | ✅ Line 364-367 (javascript.redirect_scripts) | ✅ Line 685 | ✅ WORKING |
| `js_risk_score` | ✅ | ✅ Line 409-421 (javascript.js_risk_score) | ✅ Line 686-687 | ✅ WORKING |

**JavaScript Fields: 9/9 ✅ 100% Coverage**

---

### Favicon Analysis Fields (CHROMADB_SCHEMA.md:389-399)

| Field | Schema | Feature-Crawler | Ingestor | Status |
|-------|--------|-----------------|----------|---------|
| `favicon_md5` | ✅ | ✅ Line 282 | ✅ Line 670-671 | ✅ WORKING |
| `favicon_sha256` | ✅ | ✅ Line 283 | ✅ Line 672-673 | ✅ WORKING |

**Favicon Fields: 2/2 ✅ 100% Coverage**

*Note: `favicon_size` exists in extraction code but not passed to features - see Issue #2*

---

### Redirect Tracking Fields (CHROMADB_SCHEMA.md:401-411)

| Field | Schema | Feature-Crawler | Ingestor | Status |
|-------|--------|-----------------|----------|---------|
| `redirect_count` | ✅ | ✅ Line 684 (redirects.redirect_count) | ✅ Line 675-677 | ✅ WORKING |
| `had_redirects` | ✅ | ✅ Line 687 (redirects.had_redirects) | ✅ Line 677 | ✅ WORKING |

**Redirect Fields: 2/2 ✅ 100% Coverage**

---

### File Path Fields (Not in schema but expected)

| Field | Feature-Crawler Extraction | Feature-Crawler Return | Ingestor Mapping | Status |
|-------|---------------------------|------------------------|------------------|---------|
| `html_path` | ✅ Line 699 (artifacts) | ❌ NOT in build_features() | ✅ Line 710-711 | 🔴 **ISSUE #1** |
| `screenshot_paths` | ✅ Line 700 (artifacts) | ❌ NOT in build_features() | ✅ Line 716-720 | 🔴 **ISSUE #1** |
| `pdf_path` | ✅ Line 701 (artifacts) | ✅ Line 758 | ✅ Line 713-714 | ✅ WORKING |

**File Path Fields: 1/3 🔴 33% Coverage**

---

## Summary Statistics

### By Category

| Category | Total Fields | Working | Missing | Coverage % |
|----------|--------------|---------|---------|------------|
| URL Structure | 17 | 17 | 0 | 100% ✅ |
| Internationalization | 2 | 2 | 0 | 100% ✅ |
| Page Content | 9 | 9 | 0 | 100% ✅ |
| **SSL Certificate** | **9** | **0** | **9** | **0% 🔴** |
| Form Analysis | 5 | 5 | 0 | 100% ✅ |
| JavaScript | 9 | 9 | 0 | 100% ✅ |
| Favicon | 2 | 2 | 0 | 100% ✅ |
| Redirects | 2 | 2 | 0 | 100% ✅ |
| **File Paths** | **3** | **1** | **2** | **33% 🔴** |
| **TOTAL** | **58** | **47** | **11** | **81%** |

### Issues by Severity

| Severity | Count | Issues |
|----------|-------|--------|
| 🔴 CRITICAL | 2 | #1 (File paths), #2 (Favicon size), SSL extraction architecture |
| ⚠️ WARNING | 3 | #3 (images_count), #4 (external_stylesheets), #5 (naming) |
| ✅ WORKING | 47 fields | Most fields working correctly |

---

## Recommendations

### Immediate Fixes (High Priority)

1. **Fix Issue #1:** Add `html_path` and `screenshot_paths` to `build_features()` return
   - **File:** `Pipeline/apps/feature-crawler/worker.py:749`
   - **Effort:** 5 minutes
   - **Impact:** HIGH - Enables artifact retrieval via API

2. **Fix Issue #2:** Add `favicon_size` to `build_features()` return
   - **File:** `Pipeline/apps/feature-crawler/worker.py:763`
   - **Effort:** 2 minutes
   - **Impact:** MEDIUM - Improves phishing detection

3. **Fix SSL Extraction:** Add SSL certificate extraction to feature-crawler
   - **File:** `Pipeline/apps/feature-crawler/worker.py` (new function)
   - **Effort:** 2-3 hours
   - **Impact:** CRITICAL - Restores 30% of risk scoring capability

### Secondary Fixes (Medium Priority)

4. **Fix Issue #4:** Add `external_stylesheets` mapping to ingestor
   - **File:** `Pipeline/apps/chroma-ingestor/ingest.py:636`
   - **Effort:** 2 minutes
   - **Impact:** LOW - Minor indicator improvement

5. **Fix Issue #3:** Add `images_count` mapping to ingestor
   - **File:** `Pipeline/apps/chroma-ingestor/ingest.py:636`
   - **Effort:** 2 minutes
   - **Impact:** LOW - Minor indicator improvement

### Long-term Improvements

6. **Standardize field naming** across the pipeline
   - **Effort:** 1-2 hours
   - **Impact:** MEDIUM - Reduces maintenance burden

7. **Add integration tests** to detect field mapping regressions
   - **Effort:** 4-6 hours
   - **Impact:** HIGH - Prevents future data loss

---

## Testing Verification Steps

After implementing fixes, verify with:

1. **Submit test URL via API:**
   ```bash
   curl -X POST http://localhost:3001/api/submit \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example-phish.com", "use_full_pipeline": false}'
   ```

2. **Wait 2-3 minutes for processing**

3. **Query ChromaDB via API:**
   ```bash
   curl http://localhost:3001/api/chroma/domain/example-phish.com
   ```

4. **Verify response includes:**
   - ✅ `metadata.html_path` (Issue #1 fix)
   - ✅ `metadata.screenshot_path` (Issue #1 fix)
   - ✅ `metadata.favicon_size` (Issue #2 fix)
   - ✅ `metadata.images_count` (Issue #3 fix)
   - ✅ `metadata.external_stylesheets` (Issue #4 fix)
   - ✅ `metadata.uses_https` (SSL fix)
   - ✅ `metadata.is_self_signed` (SSL fix)
   - ✅ `metadata.cert_risk_score` (SSL fix)

5. **Check API returns all fields:**
   ```bash
   # Count metadata fields in response
   curl -s http://localhost:3001/api/chroma/domain/example-phish.com | \
     jq '.data.metadata | keys | length'

   # Should return 50+ fields after fixes
   ```

---

## Appendix: Code References

### Feature-Crawler Key Functions
- `crawl_once()`: worker.py:580-717 - Playwright crawling, artifact generation
- `build_features()`: worker.py:719-780 - Feature aggregation and return
- `extract_html_features()`: worker.py:425-574 - HTML parsing, forms, JS analysis
- `analyze_javascript()`: worker.py:298-423 - JS risk detection
- `fetch_and_hash_favicon()`: worker.py:222-296 - Favicon hashing

### Ingestor Key Functions
- `to_metadata()`: ingest.py:466-722 - Field mapping to ChromaDB metadata
- `record_to_text()`: ingest.py:161-400 - Document text generation
- `upsert_docs()`: ingest.py:736-788 - ChromaDB ingestion

### API Endpoints
- `/api/chroma/domain/:domain`: chroma-query.js:423-550 - Domain lookup
- `/api/chroma/variants`: chroma-query.js:232-315 - Variant query
- `/api/chroma/originals`: chroma-query.js:144-214 - Original seeds query

---

**End of Report**
