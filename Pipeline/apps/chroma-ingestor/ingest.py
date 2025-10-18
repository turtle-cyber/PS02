import os, glob, time, hashlib, ujson as json, redis
from typing import Dict, Any, Iterable, List

# --- Chroma client (HTTP, server mode) ---
import chromadb
from chromadb import HttpClient
from chromadb.config import DEFAULT_TENANT, DEFAULT_DATABASE, Settings
from chromadb.utils import embedding_functions
# --- Embeddings ---
from sentence_transformers import SentenceTransformer

# --- Optional Kafka ---
from kafka import KafkaConsumer

# --- Registrable domain extraction ---
import tldextract
_tld_extract = tldextract.TLDExtract(suffix_list_urls=None)

CHROMA_HOST = os.getenv("CHROMA_HOST", "chroma")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))
COLLECTION  = os.getenv("CHROMA_COLLECTION", "domains")
ORIGINAL_COLLECTION = os.getenv("CHROMA_ORIGINAL_COLLECTION", "original_domains")  # NEW: Collection for original seeds
MODEL_NAME  = os.getenv("EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
BATCH_SIZE  = int(os.getenv("BATCH_SIZE", "128"))
CHROMA_TENANT = os.getenv("CHROMA_TENANT", DEFAULT_TENANT)
CHROMA_DATABASE = os.getenv("CHROMA_DATABASE", DEFAULT_DATABASE)

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP")
KAFKA_TOPIC     = os.getenv("KAFKA_TOPIC")
KAFKA_FEATURES_TOPIC = os.getenv("KAFKA_FEATURES_TOPIC")

# Redis connection for fetching DNSTwist stats
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

def get_redis_client():
    """Create Redis client for DNSTwist stats lookup"""
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_connect_timeout=2)
        r.ping()
        print(f"[ingestor] ✓ Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
        return r
    except Exception as e:
        print(f"[ingestor] ⚠️  Redis connection failed: {e}. DNSTwist stats will not be available.")
        return None

redis_client = get_redis_client()

def fetch_dnstwist_stats(domain):
    """Fetch DNSTwist variant statistics from Redis for a domain"""
    if not redis_client:
        return None

    try:
        variants = redis_client.get(f"dnstwist:variants:{domain}")
        unregistered = redis_client.get(f"dnstwist:unregistered:{domain}")
        timestamp = redis_client.get(f"dnstwist:timestamp:{domain}")

        if not variants and not timestamp:
            return None  # Not processed by DNSTwist

        return {
            "variants_registered": int(variants) if variants else 0,
            "variants_unregistered": int(unregistered) if unregistered else 0,
            "total_generated": (int(variants) if variants else 0) + (int(unregistered) if unregistered else 0),
            "processed_at": int(timestamp) if timestamp else 0
        }
    except Exception as e:
        print(f"[ingestor] ⚠️  Failed to fetch DNSTwist stats for {domain}: {e}")
        return None

KAFKA_FAILED_TOPIC = os.getenv("KAFKA_FAILED_TOPIC")
KAFKA_VERDICTS_TOPIC = os.getenv("KAFKA_VERDICTS_TOPIC", "phish.rules.verdicts")  # Verdicts from rule-scorer
KAFKA_INACTIVE_TOPIC = os.getenv("KAFKA_INACTIVE_TOPIC", "phish.urls.inactive")  # NEW: Inactive/unregistered domains
KAFKA_GROUP     = os.getenv("KAFKA_GROUP", "chroma-ingestor")
JSONL_DIR       = os.getenv("JSONL_DIR")
FEATURES_JSONL  = os.getenv("FEATURES_JSONL")

# ---------------- helpers ----------------

def get_collections():
    """Create/get both ChromaDB collections with proper settings"""
    print(f"[ingestor] Connecting to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}")
    client: HttpClient = chromadb.HttpClient(
        host=CHROMA_HOST,
        port=CHROMA_PORT,
        settings=Settings(),
        tenant=CHROMA_TENANT,
        database=CHROMA_DATABASE,
    )
    print(f"[ingestor] Getting/creating collections: {COLLECTION} (variants) and {ORIGINAL_COLLECTION} (original seeds)")

    # Create embedding function
    sentence_transformer_ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=MODEL_NAME
    )

    # Collection for variants/lookalikes
    variants_col = client.get_or_create_collection(
        name=COLLECTION,
        metadata={"hnsw:space": "cosine"},
        embedding_function=sentence_transformer_ef
    )

    # Collection for original seeds
    originals_col = client.get_or_create_collection(
        name=ORIGINAL_COLLECTION,
        metadata={"hnsw:space": "cosine"},
        embedding_function=sentence_transformer_ef
    )

    return variants_col, originals_col

def embedder():
    """Load embedding model"""
    print(f"[ingestor] Loading embedding model: {MODEL_NAME}")
    return SentenceTransformer(MODEL_NAME, device="cpu")

def features_to_text(r: Dict[str, Any]) -> str:
    """Convert feature-crawler output into queryable text for embedding."""
    url = r.get("url", "")
    registrable = r.get("registrable", "")
    cse_id = r.get("cse_id", "")

    url_feats = r.get("url_features", {})
    url_len = url_feats.get("url_length", 0)
    url_entropy = url_feats.get("url_entropy", 0)
    domain_len = url_feats.get("domain_length", 0)
    num_subdomains = url_feats.get("num_subdomains", 0)
    num_hyphens = url_feats.get("num_hyphens", 0)
    num_special = url_feats.get("num_special_chars", 0)

    idn = r.get("idn", {})
    is_idn = idn.get("is_idn", False)
    mixed_script = idn.get("mixed_script", False)
    confusable = idn.get("confusable_count", 0)

    forms = r.get("forms", {})
    form_count = forms.get("count", 0)
    pw_fields = forms.get("password_fields", 0)
    email_fields = forms.get("email_fields", 0)
    submit_texts = ", ".join(forms.get("submit_texts", [])[:5])

    html_len = r.get("html_length_bytes", 0)
    ext_links = r.get("external_links", 0)
    int_links = r.get("internal_links", 0)
    images = r.get("images_count", 0)
    iframes = r.get("iframes", 0)
    ext_scripts = r.get("external_scripts", 0)
    favicon = "Yes" if r.get("favicon_present") else "No"

    # Favicon color scheme
    favicon_color_info = ""
    fav_color_scheme = r.get("favicon_color_scheme")
    if fav_color_scheme:
        color_count = fav_color_scheme.get("color_count", 0)
        avg_brightness = fav_color_scheme.get("avg_brightness", 0)
        favicon_color_info = f", Colors: {color_count}, Brightness: {avg_brightness}"

    keywords = ", ".join(r.get("text_keywords", []))

    # OCR data
    ocr = r.get("ocr", {})
    ocr_text_len = ocr.get("length", 0)
    ocr_excerpt = ocr.get("text_excerpt", "")[:100] if ocr else ""

    # Image OCR data
    img_ocr = r.get("image_ocr", {})
    images_with_text = img_ocr.get("images_with_text", 0)
    ocr_keywords = ", ".join(img_ocr.get("extracted_keywords", [])[:10])

    # Image quality metadata
    img_meta = r.get("image_metadata", {})
    img_quality = img_meta.get("overall_quality", "unknown")
    avg_sharpness = img_meta.get("avg_sharpness", 0)

    parts = [
        f"URL: {url}",
        f"Registrable Domain: {registrable}",
        f"Brand/CSE: {cse_id}" if cse_id else "",
        f"URL Structure -> Length: {url_len}, Entropy: {url_entropy}, Domain Length: {domain_len}",
        f"URL Characteristics -> Subdomains: {num_subdomains}, Hyphens: {num_hyphens}, Special Chars: {num_special}",
        f"IDN -> Is IDN: {is_idn}, Mixed Script: {mixed_script}, Confusables: {confusable}" if is_idn or mixed_script else "",
        f"Forms -> Count: {form_count}, Password Fields: {pw_fields}, Email Fields: {email_fields}",
        f"Form Buttons: {submit_texts}" if submit_texts else "",
        f"HTML Content -> Size: {html_len} bytes, Images: {images}, Favicon: {favicon}{favicon_color_info}",
        f"Image Quality -> Overall: {img_quality}, Avg Sharpness: {avg_sharpness}" if img_quality != "unknown" else "",
        f"Links -> Internal: {int_links}, External: {ext_links}, IFrames: {iframes}, External Scripts: {ext_scripts}",
        f"Phishing Keywords: {keywords}" if keywords else "",
        f"OCR Text Length: {ocr_text_len}, Excerpt: {ocr_excerpt}" if ocr_text_len > 0 else "",
        f"Images with Text: {images_with_text}, OCR Keywords: {ocr_keywords}" if images_with_text > 0 else "",
    ]
    return "\n".join([p for p in parts if p])

def record_to_text(r: Dict[str, Any]) -> str:
    """
    Turn enriched JSON into dense, queryable text.
    Handles progressive enrichment: domain → features → verdict
    All data types are merged into a single coherent document.
    """
    # Identify what data is present
    has_domain = bool(r.get("dns") or r.get("whois"))
    has_features = bool(r.get("url_features") or r.get("forms"))
    has_verdict = bool(r.get("verdict") or r.get("score") is not None)
    is_failed = bool("error" in r or r.get("status") == "failed")

    # Extract core identifiers
    fqdn = r.get("canonical_fqdn") or r.get("fqdn") or r.get("host") or ""
    url = r.get("url") or r.get("final_url") or ""
    if not fqdn and url:
        from urllib.parse import urlparse
        try:
            fqdn = urlparse(url).hostname or url
        except:
            fqdn = url

    registrable = r.get("registrable", "")
    cse_id = r.get("cse_id", "")
    seed = r.get("seed_registrable", "")
    
    # Start building the document
    parts = []
    
    # === VERDICT SECTION (if present) ===
    if has_verdict:
        verdict = r.get("verdict", "unknown")
        score = r.get("score", 0)
        confidence = r.get("confidence", 0)
        reasons = ", ".join(r.get("reasons", []))
        categories = r.get("categories", {})
        cat_breakdown = ", ".join([f"{k}:{v}" for k, v in categories.items()]) if categories else ""
        
        parts.append(f"🚨 VERDICT: {verdict.upper()} (Risk Score: {score}/100, Confidence: {confidence:.2f})")
        if reasons:
            parts.append(f"   Risk Indicators: {reasons}")
        if cat_breakdown:
            parts.append(f"   Category Breakdown: {cat_breakdown}")
        parts.append("")  # Blank line for readability

    # === BASIC IDENTITY ===
    parts.append(f"Domain: {fqdn}")
    if url:
        parts.append(f"URL: {url}")
    parts.append(f"Registrable Domain: {registrable}")
    if cse_id or seed:
        parts.append(f"Brand/CSE: {cse_id} (seed: {seed})" if cse_id else f"Seed: {seed}")
    parts.append("")

    # === DOMAIN DATA (DNS/WHOIS/Network) ===
    if has_domain:
        dns = r.get("dns", {})
        if dns:
            A = ", ".join(dns.get("A", []) or [])
            AAAA = ", ".join(dns.get("AAAA", []) or [])
            CNAME = ", ".join(dns.get("CNAME", []) or [])
            
            mx_records = dns.get("MX", []) or []
            if isinstance(mx_records, list) and mx_records:
                if isinstance(mx_records[0], dict):
                    MX = ", ".join([m.get("exchange", "") for m in mx_records])
                else:
                    MX = ", ".join([str(m) for m in mx_records])
            else:
                MX = ""
            
            NS = ", ".join(dns.get("NS", []) or [])
            
            parts.append("📡 DNS Records:")
            if A: parts.append(f"   A (IPv4): {A}")
            if AAAA: parts.append(f"   AAAA (IPv6): {AAAA}")
            if CNAME: parts.append(f"   CNAME: {CNAME}")
            if MX: parts.append(f"   MX (Mail): {MX}")
            if NS: parts.append(f"   NS (Nameservers): {NS}")
            parts.append("")

        whois = r.get("whois", {})
        if whois:
            registrar = whois.get("registrar", "")
            created = whois.get("created", "")
            expires = whois.get("expires", "")
            age_days = whois.get("domain_age_days")
            is_new = whois.get("is_newly_registered", False)
            is_very_new = whois.get("is_very_new", False)
            days_to_exp = whois.get("days_until_expiry")
            
            parts.append("📋 WHOIS Information:")
            if registrar: parts.append(f"   Registrar: {registrar}")
            if created: parts.append(f"   Created: {created}")
            if expires: parts.append(f"   Expires: {expires}")
            if age_days is not None:
                age_status = " ⚠️ VERY NEW (<7d)" if is_very_new else " ⚠️ NEW (<30d)" if is_new else ""
                parts.append(f"   Domain Age: {age_days} days{age_status}")
            if days_to_exp is not None:
                parts.append(f"   Days Until Expiry: {days_to_exp}")
            parts.append("")

        # Network/GeoIP
        asn = r.get("asn") or r.get("rdap", {}).get("asn") or ""
        as_org = r.get("asn_org") or r.get("rdap", {}).get("asn_org") or ""
        geo = r.get("geoip", {})
        country = geo.get("country", "")
        city = geo.get("city", "")
        
        if asn or country:
            parts.append("🌍 Network & Location:")
            if asn: parts.append(f"   ASN: {asn} ({as_org})" if as_org else f"   ASN: {asn}")
            if country: parts.append(f"   Country: {country}" + (f", {city}" if city else ""))
            parts.append("")

    # === FEATURE DATA (Page Analysis) ===
    if has_features:
        parts.append("🔍 Page Features & Analysis:")
        parts.append("")
        
        # URL structure
        url_feats = r.get("url_features", {})
        if url_feats:
            url_len = url_feats.get("url_length", 0)
            url_ent = url_feats.get("url_entropy", 0)
            num_subdom = url_feats.get("num_subdomains", 0)
            num_hyphens = url_feats.get("num_hyphens", 0)
            num_special = url_feats.get("num_special_chars", 0)
            has_repdig = url_feats.get("has_repeated_digits", False)
            
            parts.append("   URL Structure:")
            parts.append(f"      Length: {url_len} chars, Entropy: {url_ent:.2f}")
            parts.append(f"      Subdomains: {num_subdom}, Hyphens: {num_hyphens}, Special Chars: {num_special}")
            if has_repdig:
                parts.append(f"      ⚠️ Contains repeated digits")
            parts.append("")

        # IDN analysis
        idn = r.get("idn", {})
        if idn.get("is_idn") or idn.get("mixed_script"):
            parts.append("   ⚠️ Internationalized Domain:")
            parts.append(f"      Uses IDN: {idn.get('is_idn', False)}")
            parts.append(f"      Mixed Scripts: {idn.get('mixed_script', False)}")
            parts.append(f"      Confusable Characters: {idn.get('confusable_count', 0)}")
            parts.append("")

        # Forms analysis (critical for phishing)
        forms = r.get("forms", {})
        if forms:
            form_count = forms.get("count", 0)
            pw_fields = forms.get("password_fields", 0)
            email_fields = forms.get("email_fields", 0)
            susp_forms = forms.get("suspicious_form_count", 0)
            submit_texts = forms.get("submit_texts", [])
            
            if form_count > 0:
                parts.append("   📝 Forms Detected:")
                parts.append(f"      Total Forms: {form_count}")
                parts.append(f"      Password Fields: {pw_fields}")
                parts.append(f"      Email Fields: {email_fields}")
                if susp_forms > 0:
                    parts.append(f"      ⚠️ Suspicious Forms: {susp_forms}")
                if pw_fields > 0 and email_fields > 0:
                    parts.append(f"      🚨 CREDENTIAL HARVESTING FORM DETECTED")
                if submit_texts:
                    parts.append(f"      Submit Buttons: {', '.join(submit_texts[:5])}")
                parts.append("")

        # Content analysis
        html_size = r.get("html_length_bytes") or r.get("html_size")
        ext_links = r.get("external_links")
        int_links = r.get("internal_links")
        images = r.get("images_count")
        iframes = r.get("iframes") or r.get("iframe_count")
        ext_scripts = r.get("external_scripts")
        favicon = r.get("favicon_present") or r.get("favicon_md5")
        
        if html_size or ext_links or iframes:
            parts.append("   📄 Page Content:")
            if html_size: parts.append(f"      HTML Size: {html_size:,} bytes")
            if int_links is not None: parts.append(f"      Internal Links: {int_links}")
            if ext_links is not None: parts.append(f"      External Links: {ext_links}")
            if images is not None: parts.append(f"      Images: {images}")
            if iframes: parts.append(f"      ⚠️ IFrames: {iframes}")
            if ext_scripts is not None: parts.append(f"      External Scripts: {ext_scripts}")
            if favicon: parts.append(f"      Favicon: Present")
            parts.append("")

        # Phishing keywords
        keywords = r.get("text_keywords", [])
        if keywords:
            parts.append(f"   🚩 Phishing Keywords Detected: {', '.join(keywords)}")
            parts.append("")

        # SSL/TLS analysis
        tls = r.get("tls") or r.get("ssl")
        if tls:
            parts.append("   🔒 SSL/TLS Certificate:")
            parts.append(f"      Uses HTTPS: {tls.get('uses_https', False)}")
            if tls.get("is_self_signed"):
                parts.append(f"      🚨 SELF-SIGNED CERTIFICATE")
            if tls.get("has_domain_mismatch") or tls.get("domain_mismatch"):
                parts.append(f"      🚨 DOMAIN MISMATCH")
            if tls.get("trusted_issuer"):
                parts.append(f"      Issuer: {tls.get('trusted_issuer')}")
            if tls.get("cert_age_days") is not None:
                cert_age = tls.get("cert_age_days")
                age_flag = " ⚠️ VERY NEW" if tls.get("cert_is_very_new") else " ⚠️ NEW" if tls.get("is_newly_issued") else ""
                parts.append(f"      Certificate Age: {cert_age} days{age_flag}")
            if tls.get("cert_risk_score"):
                parts.append(f"      Certificate Risk Score: {tls.get('cert_risk_score')}/100")
            parts.append("")

        # JavaScript analysis
        js = r.get("javascript", {})
        if js and any(js.values()):
            parts.append("   ⚠️ JavaScript Behavior:")
            if js.get("obfuscated_scripts"): parts.append(f"      🚨 Obfuscated Code Detected")
            if js.get("eval_usage"): parts.append(f"      ⚠️ Uses eval() for code execution")
            if js.get("keylogger_patterns"): parts.append(f"      🚨 KEYLOGGER PATTERNS DETECTED")
            if js.get("form_manipulation"): parts.append(f"      ⚠️ Form Manipulation Detected")
            if js.get("js_risk_score"): parts.append(f"      JS Risk Score: {js['js_risk_score']}/100")
            parts.append("")

    # === FAILURE INFO ===
    if is_failed:
        parts.append("❌ CRAWL FAILED:")
        parts.append(f"   Reason: {r.get('error', 'Unknown error')}")
        parts.append(f"   Status: {r.get('status', 'failed')}")
        parts.append("")

    # === METADATA ===
    first_seen = r.get("first_seen") or r.get("ts") or r.get("timestamp") or ""
    stage = r.get("stage") or r.get("_stage") or ""
    if first_seen or stage:
        parts.append("📊 Metadata:")
        if first_seen: parts.append(f"   First Seen: {first_seen}")
        if stage: parts.append(f"   Processing Stage: {stage}")

    return "\n".join(parts)

def extract_registrable(domain_or_url: str) -> str:
    """Extract registrable domain (eTLD+1) using tldextract."""
    if not domain_or_url:
        return ""

    if "://" in domain_or_url:
        from urllib.parse import urlparse
        try:
            domain_or_url = urlparse(domain_or_url).hostname or domain_or_url
        except:
            pass

    try:
        ext = _tld_extract(domain_or_url)
        if ext.suffix:
            registrable = f"{ext.domain}.{ext.suffix}"
        else:
            registrable = ext.domain
        return registrable.lower() if registrable else ""
    except:
        parts = domain_or_url.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain_or_url.lower()

def stable_id(r: Dict[str,Any]) -> str:
    """
    Upsert key: Use FULL domain name (FQDN) for merging all records for same domain.
    This ensures subdomains like pnb.bank.in, sbi.bank.in get unique IDs.
    Previously used registrable domain, but tldextract incorrectly treats .bank.in as public suffix.

    Special handling:
    - Normalizes 'www.' prefix: www.example.com -> example.com (for merging)
    - Keeps other subdomains: mail.example.com, pnb.bank.in remain separate
    """
    full_domain = None

    # Priority 1: Extract full hostname from URL
    url = r.get("url") or r.get("final_url")
    if url:
        from urllib.parse import urlparse
        try:
            hostname = urlparse(url).hostname
            if hostname:
                full_domain = hostname.lower()
        except:
            pass

    # Priority 2: Extract from FQDN fields
    if not full_domain:
        fqdn = r.get("canonical_fqdn") or r.get("fqdn") or r.get("host")
        if fqdn:
            full_domain = fqdn.lower()

    # Priority 3: Use provided registrable as fallback
    if not full_domain:
        provided = r.get("registrable")
        if provided:
            full_domain = provided.lower()

    # Normalize 'www.' subdomain to merge www.example.com with example.com
    # BUT preserve other important subdomains like pnb.bank.in, mail.example.com
    if full_domain and full_domain.startswith("www."):
        normalized = full_domain[4:]  # Strip 'www.'
        # Only normalize if the result has at least one dot (avoid stripping from www.com)
        if "." in normalized:
            full_domain = normalized

    # Generate stable ID using full domain name
    if full_domain:
        domain_hash = hashlib.sha1(full_domain.encode()).hexdigest()[:16]
        return f"{full_domain}:{domain_hash}"

    # Fallback: content hash
    h = hashlib.sha1(json.dumps(r, sort_keys=True).encode()).hexdigest()
    return f"rec-{h[:24]}"

def to_metadata(r: Dict[str,Any]) -> Dict[str,Any]:
    keep = {}

    # Common metadata fields
    for k in ("cse_id","seed_registrable","registrable","reasons","first_seen","stage","is_original_seed"):
        if k in r:
            val = r[k]
            if isinstance(val, list):
                keep[k] = ",".join(str(v) for v in val)
            else:
                keep[k] = val

    # DNSTwist stats (for original seeds only)
    for k in ("dnstwist_variants_registered", "dnstwist_variants_unregistered", "dnstwist_total_generated", "dnstwist_processed_at"):
        if k in r:
            keep[k] = r[k]

    # OPTION 1: Store full nested objects as JSON strings
    # This preserves all enrichment data while remaining ChromaDB-compatible

    # Store full DNS record (includes A, AAAA, MX, NS, CNAME, TXT, etc.)
    if "dns" in r and isinstance(r["dns"], dict):
        keep["dns"] = json.dumps(r["dns"])
        # Also keep summary counts for easy filtering
        keep["a_count"] = len(r["dns"].get("A",[]) or [])
        keep["mx_count"] = len(r["dns"].get("MX",[]) or [])
        keep["ns_count"] = len(r["dns"].get("NS",[]) or [])

    # Store full WHOIS record
    if "whois" in r and isinstance(r["whois"], dict):
        keep["whois"] = json.dumps(r["whois"])
        # Also keep key fields for filtering
        whois = r["whois"]
        keep["registrar"] = whois.get("registrar")
        if "domain_age_days" in whois:
            keep["domain_age_days"] = whois["domain_age_days"]
            keep["is_newly_registered"] = bool(whois.get("is_newly_registered", False))
            keep["is_very_new"] = bool(whois.get("is_very_new", False))
        if "days_until_expiry" in whois:
            keep["days_until_expiry"] = whois["days_until_expiry"]

    # Store full GeoIP record
    if "geoip" in r and isinstance(r["geoip"], dict):
        keep["geoip"] = json.dumps(r["geoip"])
        # Also keep country for filtering
        keep["country"] = r["geoip"].get("country")

    # Store full RDAP record
    if "rdap" in r and isinstance(r["rdap"], dict):
        keep["rdap"] = json.dumps(r["rdap"])

    # Determine enrichment level (what data is present)
    # Check for domain data in both nested (dns-collector) and flattened (rule-scorer) formats
    has_domain = bool(
        r.get("dns") or
        r.get("whois") or
        r.get("a_count") is not None or
        r.get("mx_count") is not None or
        r.get("ns_count") is not None or
        r.get("domain_age_days") is not None or
        r.get("country")
    )
    has_features = bool(r.get("url_features") or r.get("forms"))
    has_verdict = bool(r.get("verdict") or r.get("score") is not None)
    is_failed = bool("error" in r or r.get("status") == "failed")
    is_inactive = bool(r.get("status") in ("inactive", "unregistered"))  # NEW: Check inactive status

    # Set enrichment level
    if has_verdict and has_features and has_domain:
        keep["record_type"] = "fully_enriched"  # Complete: domain + features + verdict
        keep["enrichment_level"] = 3
    elif has_verdict and has_domain:
        keep["record_type"] = "verdict_only"  # domain + verdict (no features)
        keep["enrichment_level"] = 2
    elif has_features and has_domain:
        keep["record_type"] = "with_features"  # domain + features (not scored yet)
        keep["enrichment_level"] = 2
    elif has_domain:
        keep["record_type"] = "domain_only"  # Just DNS/WHOIS
        keep["enrichment_level"] = 1
    elif has_features:
        keep["record_type"] = "features_only"  # Just page features (unusual)
        keep["enrichment_level"] = 1
    elif is_inactive:
        keep["record_type"] = "inactive"  # NEW: Inactive/unregistered domain
        keep["enrichment_level"] = 0
    else:
        keep["record_type"] = "partial"
        keep["enrichment_level"] = 0

    # Crawl status
    keep["crawl_failed"] = is_failed
    if is_failed:
        if "error" in r:
            keep["failure_reason"] = str(r["error"])[:500]
        if "status" in r:
            keep["failure_status"] = str(r["status"])

    # NEW: Inactive/monitoring status
    if is_inactive:
        keep["is_inactive"] = True
        keep["inactive_status"] = r.get("status", "unknown")  # "inactive" or "unregistered"
        if "failure_type" in r:
            keep["inactive_reason"] = str(r["failure_type"])
        if "reasons" in r:
            keep["monitoring_reasons"] = ",".join(r["reasons"]) if isinstance(r["reasons"], list) else str(r["reasons"])

    # Store verdict information if present
    if has_verdict:
        keep["has_verdict"] = True
        if "verdict" in r:
            keep["verdict"] = str(r["verdict"])
        if "final_verdict" in r:
            keep["final_verdict"] = str(r["final_verdict"])
        if "score" in r:
            keep["risk_score"] = int(r["score"])
        if "confidence" in r:
            keep["confidence"] = float(r["confidence"])
        # Store category breakdown
        if "categories" in r and isinstance(r["categories"], dict):
            for cat, val in r["categories"].items():
                keep[f"cat_{cat}"] = int(val)
        # Store monitoring metadata
        if "monitor_until" in r:
            keep["monitor_until"] = int(r["monitor_until"])
        if "monitor_reason" in r:
            keep["monitor_reason"] = str(r["monitor_reason"])
        if "requires_monitoring" in r:
            keep["requires_monitoring"] = bool(r["requires_monitoring"])
    else:
        keep["has_verdict"] = False

    # Feature-specific metadata
    if "url" in r:
        keep["url"] = r["url"]

    # Set has_features flag based on actual feature data presence
    keep["has_features"] = has_features

    # Store full URL features as JSON
    if "url_features" in r and isinstance(r["url_features"], dict):
        keep["url_features"] = json.dumps(r["url_features"])
        # Also keep key metrics for filtering
        url_f = r["url_features"]
        keep["url_length"] = url_f.get("url_length", 0)
        keep["url_entropy"] = float(url_f.get("url_entropy", 0))
        keep["num_dots"] = url_f.get("num_dots", 0)
        keep["num_hyphens"] = url_f.get("num_hyphens", 0)
        keep["num_slashes"] = url_f.get("num_slashes", 0)
        keep["num_underscores"] = url_f.get("num_underscores", 0)
        keep["has_repeated_digits"] = bool(url_f.get("has_repeated_digits", False))
        keep["domain_length"] = url_f.get("domain_length", 0)
        keep["domain_entropy"] = float(url_f.get("domain_entropy", 0))
        keep["domain_hyphens"] = url_f.get("domain_hyphens", 0)
        keep["num_subdomains"] = url_f.get("num_subdomains", 0)
        keep["avg_subdomain_length"] = url_f.get("avg_subdomain_length", 0)
        keep["subdomain_entropy"] = float(url_f.get("subdomain_entropy", 0))
        keep["path_length"] = url_f.get("path_length", 0)
        keep["path_has_query"] = bool(url_f.get("path_has_query", False))
        keep["path_has_fragment"] = bool(url_f.get("path_has_fragment", False))

    # Store full IDN analysis as JSON
    if "idn" in r and isinstance(r["idn"], dict):
        keep["idn"] = json.dumps(r["idn"])
        # Also keep key flags for filtering
        idn = r["idn"]
        keep["is_idn"] = bool(idn.get("is_idn", False))
        keep["mixed_script"] = bool(idn.get("mixed_script", False))

    # Store full forms analysis as JSON
    if "forms" in r and isinstance(r["forms"], dict):
        keep["forms"] = json.dumps(r["forms"])
        # Also keep key metrics for filtering
        forms = r["forms"]
        keep["form_count"] = forms.get("count", 0)
        keep["password_fields"] = forms.get("password_fields", 0)
        keep["email_fields"] = forms.get("email_fields", 0)
        keep["has_credential_form"] = bool(
            forms.get("password_fields", 0) > 0 and forms.get("email_fields", 0) > 0
        )

    # Store text keywords as JSON array
    if "text_keywords" in r:
        keywords = r.get("text_keywords", [])
        if keywords:
            keep["text_keywords"] = json.dumps(keywords)
            keep["phishing_keywords"] = ",".join(keywords)  # Also keep comma-separated for backward compat
            keep["keyword_count"] = len(keywords)

    if "html_length_bytes" in r:
        keep["html_size"] = r["html_length_bytes"]

    if "external_links" in r:
        keep["external_links"] = r["external_links"]

    if "iframes" in r:
        keep["iframe_count"] = r["iframes"]

    # FIX: Add missing field mappings
    if "images_count" in r:
        keep["images_count"] = r["images_count"]

    if "external_scripts" in r:
        keep["external_scripts"] = r["external_scripts"]

    if "external_stylesheets" in r:
        keep["external_stylesheets"] = r["external_stylesheets"]

    if "favicon_size" in r:
        keep["favicon_size"] = r["favicon_size"]

    # Store full favicon color scheme as JSON
    if "favicon_color_scheme" in r and isinstance(r["favicon_color_scheme"], dict):
        keep["favicon_color_scheme"] = json.dumps(r["favicon_color_scheme"])
        # Also keep key metrics for filtering
        fav_color = r["favicon_color_scheme"]
        keep["favicon_color_count"] = fav_color.get("color_count", 0)
        keep["favicon_color_variance"] = float(fav_color.get("color_variance", 0))
        keep["favicon_color_entropy"] = float(fav_color.get("color_entropy", 0))
        keep["favicon_has_transparency"] = bool(fav_color.get("has_transparency", False))
        keep["favicon_avg_brightness"] = float(fav_color.get("avg_brightness", 0))
        # Store dominant colors as JSON string
        dominant = fav_color.get("dominant_colors", [])
        if dominant:
            keep["favicon_dominant_color"] = dominant[0].get("hex", "") if len(dominant) > 0 else ""

    # Store full OCR data as JSON
    if "ocr" in r and isinstance(r["ocr"], dict):
        keep["ocr"] = json.dumps(r["ocr"])
        # Also keep key fields for filtering
        ocr = r["ocr"]
        keep["ocr_text_length"] = ocr.get("length", 0)
        keep["ocr_text_excerpt"] = (ocr.get("text_excerpt", "") or "")[:500]

    # Store full image OCR data as JSON
    if "image_ocr" in r and isinstance(r["image_ocr"], dict):
        keep["image_ocr"] = json.dumps(r["image_ocr"])
        # Also keep key metrics for filtering
        img_ocr = r["image_ocr"]
        keep["images_with_ocr_text"] = img_ocr.get("images_with_text", 0)
        keep["images_with_brand_keywords"] = img_ocr.get("images_with_brand_keywords", 0)
        keep["images_with_suspicious_keywords"] = img_ocr.get("images_with_suspicious_keywords", 0)
        keep["ocr_total_text_length"] = img_ocr.get("total_text_length", 0)
        # Store extracted keywords
        keywords = img_ocr.get("extracted_keywords", [])
        if keywords:
            keep["ocr_extracted_keywords"] = ",".join(keywords[:20])

    # Store full image metadata as JSON
    if "image_metadata" in r and isinstance(r["image_metadata"], dict):
        keep["image_metadata"] = json.dumps(r["image_metadata"])
        # Also keep key metrics for filtering
        img_meta = r["image_metadata"]
        keep["avg_image_sharpness"] = float(img_meta.get("avg_sharpness", 0))
        keep["avg_image_resolution"] = float(img_meta.get("avg_resolution", 0))
        keep["image_overall_quality"] = img_meta.get("overall_quality", "unknown")
        keep["high_quality_images"] = img_meta.get("high_quality_images", 0)
        keep["medium_quality_images"] = img_meta.get("medium_quality_images", 0)
        keep["low_quality_images"] = img_meta.get("low_quality_images", 0)

    # SSL certificate analysis
    # Check multiple possible locations for SSL data
    ssl = None
    if "ssl_info" in r:
        ssl = r["ssl_info"]
    elif "ssl" in r:
        ssl = r["ssl"]
    elif "tls" in r:
        ssl = r["tls"]
    elif "final" in r and isinstance(r["final"], dict) and "ssl_info" in r["final"]:
        # SSL data might be nested inside 'final' object from http-fetcher
        ssl = r["final"]["ssl_info"]

    # Store full TLS/SSL record as JSON
    if ssl and isinstance(ssl, dict):
        keep["tls"] = json.dumps(ssl)
        # Also keep key fields for filtering
        keep["uses_https"] = bool(ssl.get("uses_https", False))
        keep["is_self_signed"] = bool(ssl.get("is_self_signed", False))
        keep["domain_mismatch"] = bool(ssl.get("domain_mismatch") or ssl.get("has_domain_mismatch", False))
        keep["trusted_issuer"] = bool(ssl.get("trusted_issuer", False))
        if "cert_age_days" in ssl:
            keep["cert_age_days"] = ssl["cert_age_days"]
            keep["is_newly_issued_cert"] = bool(ssl.get("is_newly_issued") or ssl.get("is_very_new_cert", False))
        if "cert_risk_score" in ssl:
            keep["cert_risk_score"] = ssl["cert_risk_score"]
        # Additional SSL fields from http-fetcher
        if "issuer" in ssl:
            keep["cert_issuer"] = ssl["issuer"]
        if "subject" in ssl:
            keep["cert_subject"] = ssl["subject"]

    if "favicon_md5" in r:
        keep["favicon_md5"] = r["favicon_md5"]
    if "favicon_sha256" in r:
        keep["favicon_sha256"] = r["favicon_sha256"]

    if "redirect_count" in r:
        keep["redirect_count"] = r["redirect_count"]
        keep["had_redirects"] = bool(r.get("had_redirects", False))

    # Store full JavaScript analysis as JSON
    if "javascript" in r and isinstance(r["javascript"], dict):
        keep["javascript"] = json.dumps(r["javascript"])
        # Also keep key flags for filtering
        js = r["javascript"]
        keep["js_obfuscated"] = js.get("obfuscated_scripts", 0) > 0
        keep["js_eval_usage"] = js.get("eval_usage", 0) > 0
        keep["js_keylogger"] = js.get("keylogger_patterns", 0) > 0
        keep["js_form_manipulation"] = js.get("form_manipulation", 0) > 0
        keep["js_redirect_detected"] = js.get("redirect_scripts", 0) > 0
        if "js_risk_score" in js:
            keep["js_risk_score"] = js["js_risk_score"]
        # Additional JS analysis fields
        if "eval_usage" in js:
            keep["js_eval_count"] = js["eval_usage"]
        if "base64_decoding" in js:
            keep["js_encoding_count"] = js["base64_decoding"]
        if "obfuscated_scripts" in js:
            keep["js_obfuscated_count"] = js["obfuscated_scripts"]

    # Note: forms already stored as JSON above, but keep additional fields
    if "forms" in r and isinstance(r["forms"], dict):
        forms = r["forms"]
        if "suspicious_form_count" in forms:
            keep["suspicious_form_count"] = forms["suspicious_form_count"]
            keep["has_suspicious_forms"] = forms["suspicious_form_count"] > 0
        # Form submission analysis
        if "forms_to_ip" in forms:
            keep["forms_to_ip"] = forms["forms_to_ip"]
        if "forms_to_suspicious_tld" in forms:
            keep["forms_to_suspicious_tld"] = forms["forms_to_suspicious_tld"]
        if "forms_to_private_ip" in forms:
            keep["forms_to_private_ip"] = forms["forms_to_private_ip"]

    # CRITICAL: Store file paths for HTML/PDF/screenshots from feature-crawler
    if "html_path" in r:
        keep["html_path"] = r["html_path"]

    if "pdf_path" in r:
        keep["pdf_path"] = r["pdf_path"]

    if "screenshot_paths" in r and isinstance(r["screenshot_paths"], list) and len(r["screenshot_paths"]) > 0:
        # ChromaDB metadata only supports strings, not lists - store as comma-separated
        keep["screenshot_path"] = r["screenshot_paths"][0]  # Store first screenshot path
        if len(r["screenshot_paths"]) > 1:
            keep["screenshot_paths_all"] = ",".join(r["screenshot_paths"])

    return keep

def batched(iterable: Iterable, n: int):
    batch = []
    for x in iterable:
        batch.append(x)
        if len(batch) >= n:
            yield batch
            batch = []
    if batch:
        yield batch

# --------------- ingestion functions ---------------

def upsert_docs(variants_col, originals_col, model, rows: List[Dict[str,Any]]):
    """Embed and upsert documents into ChromaDB (routing to correct collection)"""
    # Separate rows into originals and variants
    original_rows = [r for r in rows if r.get("is_original_seed") is True]
    variant_rows = [r for r in rows if r.get("is_original_seed") is not True]

    # Process originals
    if original_rows:
        docs, metas, ids = [], [], []
        for r in original_rows:
            # Fetch and add DNSTwist stats for original seeds
            domain = r.get("canonical_fqdn") or r.get("fqdn") or r.get("registrable")
            if domain:
                stats = fetch_dnstwist_stats(domain)
                if stats:
                    r["dnstwist_variants_registered"] = stats["variants_registered"]
                    r["dnstwist_variants_unregistered"] = stats["variants_unregistered"]
                    r["dnstwist_total_generated"] = stats["total_generated"]
                    r["dnstwist_processed_at"] = stats["processed_at"]

            ids.append(stable_id(r))
            metas.append(to_metadata(r))
            docs.append(record_to_text(r))

        print(f"[ingestor] Encoding {len(docs)} original seed documents...")
        vecs = model.encode(docs, batch_size=min(64, len(docs)), show_progress_bar=False, normalize_embeddings=True).tolist()

        try:
            originals_col.upsert(ids=ids, documents=docs, embeddings=vecs, metadatas=metas)
            print(f"[ingestor] ✓ Upserted {len(docs)} documents to '{ORIGINAL_COLLECTION}' collection")
        except Exception as e:
            print(f"[ingestor] Upsert failed, trying add: {e}")
            originals_col.add(ids=ids, documents=docs, embeddings=vecs, metadatas=metas)
            print(f"[ingestor] ✓ Added {len(docs)} documents to '{ORIGINAL_COLLECTION}' collection")

    # Process variants
    if variant_rows:
        docs, metas, ids = [], [], []
        for r in variant_rows:
            ids.append(stable_id(r))
            metas.append(to_metadata(r))
            docs.append(record_to_text(r))

        print(f"[ingestor] Encoding {len(docs)} variant documents...")
        vecs = model.encode(docs, batch_size=min(64, len(docs)), show_progress_bar=False, normalize_embeddings=True).tolist()

        try:
            variants_col.upsert(ids=ids, documents=docs, embeddings=vecs, metadatas=metas)
            print(f"[ingestor] ✓ Upserted {len(docs)} documents to '{COLLECTION}' collection")
        except Exception as e:
            print(f"[ingestor] Upsert failed, trying add: {e}")
            variants_col.add(ids=ids, documents=docs, embeddings=vecs, metadatas=metas)
            print(f"[ingestor] ✓ Added {len(docs)} documents to '{COLLECTION}' collection")

def from_kafka(variants_col, originals_col, model):
    """Stream from Kafka and continuously ingest from multiple topics"""
    topics = []
    if KAFKA_TOPIC:
        topics.append(KAFKA_TOPIC)
    if KAFKA_FEATURES_TOPIC:
        topics.append(KAFKA_FEATURES_TOPIC)
    if KAFKA_FAILED_TOPIC:
        topics.append(KAFKA_FAILED_TOPIC)
    if KAFKA_VERDICTS_TOPIC:
        topics.append(KAFKA_VERDICTS_TOPIC)
    if KAFKA_INACTIVE_TOPIC:
        topics.append(KAFKA_INACTIVE_TOPIC)  # NEW: Inactive domains

    if not topics:
        raise ValueError("[ingestor] No Kafka topics configured!")

    print(f"[ingestor] Creating Kafka consumer for topics: {', '.join(topics)}")
    consumer = KafkaConsumer(
        *topics,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=KAFKA_GROUP,
        enable_auto_commit=True,
        auto_offset_reset="earliest",
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        consumer_timeout_ms=-1
    )
    print(f"[ingestor] Kafka consumer ready, waiting for messages...")

    buffer = []
    msg_count = 0
    enrichment_stats = {
        "domain": 0,
        "features": 0,
        "verdict": 0,
        "failed": 0,
        "inactive": 0  # NEW: Track inactive domains
    }

    for msg in consumer:
        val = msg.value
        if isinstance(val, dict):
            buffer.append(val)
            msg_count += 1

            # Track message types for statistics
            has_features = bool(val.get("url_features") or val.get("forms"))
            has_verdict = bool(val.get("verdict") or val.get("score") is not None)
            is_failed = bool("error" in val or val.get("status") == "failed")
            is_inactive = bool(val.get("status") in ("inactive", "unregistered"))  # NEW: Check for inactive status

            if is_inactive:
                enrichment_stats["inactive"] += 1
                msg_type = "inactive"
            elif is_failed:
                enrichment_stats["failed"] += 1
                msg_type = "failed"
            elif has_verdict:
                enrichment_stats["verdict"] += 1
                msg_type = "verdict"
            elif has_features:
                enrichment_stats["features"] += 1
                msg_type = "features"
            else:
                enrichment_stats["domain"] += 1
                msg_type = "domain"

            # Log first few messages and important verdicts
            if msg_count <= 5 or (has_verdict and val.get("verdict") in ("parked", "suspicious", "phishing")):
                identifier = val.get("url") or val.get("canonical_fqdn") or val.get("fqdn") or val.get("host", "unknown")
                verdict_info = f" [{val.get('verdict')}:{val.get('score')}]" if has_verdict else ""
                monitor_info = f" monitoring={val.get('requires_monitoring', False)}" if has_verdict else ""
                print(f"[ingestor] Received message {msg_count} ({msg_type}): {identifier}{verdict_info}{monitor_info}")

            if len(buffer) >= BATCH_SIZE:
                print(f"[ingestor] Buffer full ({len(buffer)} docs), upserting...")
                upsert_docs(variants_col, originals_col, model, buffer)
                buffer.clear()

        # Periodic status update
        if msg_count % 100 == 0:
            print(f"[ingestor] Processed {msg_count} messages | Stats: {enrichment_stats} | Buffered: {len(buffer)}")

    if buffer:
        print(f"[ingestor] Flushing remaining {len(buffer)} documents...")
        upsert_docs(variants_col, originals_col, model, buffer)
    
    print(f"[ingestor] Final statistics: {enrichment_stats}")

def from_jsonl(variants_col, originals_col, model):
    """Batch ingest from JSONL files"""
    all_paths = []

    if JSONL_DIR:
        domain_paths = sorted(glob.glob(os.path.join(JSONL_DIR, "**/*.jsonl"), recursive=True))
        all_paths.extend(domain_paths)
        print(f"[ingestor] Found {len(domain_paths)} domain JSONL files in {JSONL_DIR}")

    if FEATURES_JSONL:
        if os.path.isfile(FEATURES_JSONL):
            all_paths.append(FEATURES_JSONL)
            print(f"[ingestor] Adding features JSONL: {FEATURES_JSONL}")
        else:
            print(f"[ingestor] WARNING: Features JSONL not found: {FEATURES_JSONL}")

    if not all_paths:
        print(f"[ingestor] No JSONL files to process")
        return

    total_records = 0
    domain_records = 0
    feature_records = 0
    verdict_records = 0

    for p in all_paths:
        print(f"[ingestor] Ingesting {p}")
        with open(p, "r", encoding="utf-8") as fh:
            buffer = []
            line_count = 0
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    line_count += 1

                    # Track record type
                    if "verdict" in obj or "score" in obj:
                        verdict_records += 1
                    elif "url_features" in obj or "forms" in obj:
                        feature_records += 1
                    else:
                        domain_records += 1

                    buffer.append(obj)
                    if len(buffer) >= BATCH_SIZE:
                        upsert_docs(variants_col, originals_col, model, buffer)
                        total_records += len(buffer)
                        buffer.clear()
                except Exception as e:
                    print(f"[ingestor] Failed to parse line {line_count} in {p}: {e}")
                    continue

            if buffer:
                upsert_docs(variants_col, originals_col, model, buffer)
                total_records += len(buffer)

        print(f"[ingestor] Completed {p}: processed {line_count} lines")

    print(f"[ingestor] JSONL ingestion complete: {total_records} total records (domains: {domain_records}, features: {feature_records}, verdicts: {verdict_records})")

# --------------- main ---------------

if __name__ == "__main__":
    print("[ingestor] Starting ChromaDB ingestor...")

    try:
        variants_col, originals_col = get_collections()
        model = embedder()

        # Determine ingestion mode
        has_kafka = KAFKA_BOOTSTRAP and (KAFKA_TOPIC or KAFKA_FEATURES_TOPIC or KAFKA_VERDICTS_TOPIC or KAFKA_INACTIVE_TOPIC)
        has_jsonl = JSONL_DIR or FEATURES_JSONL

        if has_kafka:
            topics = []
            if KAFKA_TOPIC:
                topics.append(f"{KAFKA_TOPIC} (domains)")
            if KAFKA_FEATURES_TOPIC:
                topics.append(f"{KAFKA_FEATURES_TOPIC} (features)")
            if KAFKA_FAILED_TOPIC:
                topics.append(f"{KAFKA_FAILED_TOPIC} (failed)")
            if KAFKA_VERDICTS_TOPIC:
                topics.append(f"{KAFKA_VERDICTS_TOPIC} (verdicts)")
            if KAFKA_INACTIVE_TOPIC:
                topics.append(f"{KAFKA_INACTIVE_TOPIC} (inactive)")  # NEW
            print(f"[ingestor] Streaming mode: consuming from Kafka topics: {', '.join(topics)}")
            from_kafka(variants_col, originals_col, model)
        elif has_jsonl:
            sources = []
            if JSONL_DIR:
                sources.append(f"directory: {JSONL_DIR}")
            if FEATURES_JSONL:
                sources.append(f"features: {FEATURES_JSONL}")
            print(f"[ingestor] Batch mode: ingesting from {', '.join(sources)}")
            from_jsonl(variants_col, originals_col, model)
        else:
            raise SystemExit("[ingestor] ERROR: Set KAFKA_* or JSONL_DIR/FEATURES_JSONL for ingestion.")
    except Exception as e:
        print(f"[ingestor] FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        raise