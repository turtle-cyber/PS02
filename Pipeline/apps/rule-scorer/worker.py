#!/usr/bin/env python3
# apps/rule-scorer/worker.py - Enhanced Version
import os, asyncio, ujson as json, time, math, re
from collections import OrderedDict, defaultdict
from urllib.parse import urlparse
from datetime import datetime, timezone
from typing import Dict, Tuple, List, Optional

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

# ------------ Config ------------
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
INPUT_TOPICS = [t.strip() for t in os.getenv(
    "INPUT_TOPICS", "domains.resolved,http.probed,phish.features.page"
).split(",") if t.strip()]
OUTPUT_TOPIC = os.getenv("OUTPUT_TOPIC", "phish.rules.verdicts")
GROUP_ID = os.getenv("GROUP_ID", "rule-scorer")

# Optional JSONL mirror (batch ingest)
WRITE_JSONL = os.getenv("WRITE_JSONL", "true").lower() == "true"
OUT_DIR = os.getenv("OUT_DIR", "/out")

# Thresholds (brand-agnostic)
THRESH_PHISHING   = int(os.getenv("THRESH_PHISHING", "70"))
THRESH_SUSPICIOUS = int(os.getenv("THRESH_SUSPICIOUS", "40"))
THRESH_PARKED     = int(os.getenv("THRESH_PARKED", "28"))

# Monitoring config
MONITOR_SUSPICIOUS = os.getenv("MONITOR_SUSPICIOUS", "true").lower() == "true"
MONITOR_PARKED = os.getenv("MONITOR_PARKED", "true").lower() == "true"
MONITOR_DAYS = int(os.getenv("MONITOR_DAYS", "90"))

RISKY_TLDS = set(os.getenv(
    "RISKY_TLDS", "tk,ml,ga,cf,gq,xyz,top,club,info,online,site,website,space,tech,zip,click,download"
).replace(" ", "").split(","))

# Protected TLDs that should not appear in subdomains (impersonation detection)
PROTECTED_TLDS = set(os.getenv(
    "PROTECTED_TLDS", "gov,edu,mil,ac,org,gov.in,gov.uk,gov.au,gov.ca,gov.sg,ac.uk,edu.au,mil.uk"
).replace(" ", "").split(","))

# Country-code TLDs for detection
CCTLDS = set(os.getenv(
    "CCTLDS", "in,uk,au,de,fr,cn,ru,br,jp,kr,sg,nz,za,nl,se,no,dk,fi,es,it,pl,ch,at,be,gr,ie,pt,cz"
).replace(" ", "").split(","))

# Sensitive TLDs requiring geographic validation (country code -> expected countries)
GEO_SENSITIVE_TLDS = {
    "gov.in": ["IN"],
    "gov.uk": ["GB", "UK"],
    "gov.au": ["AU"],
    "gov.ca": ["CA"],
    "gov.sg": ["SG"],
    "gov": ["US"],
    "mil": ["US"],
    "ac.uk": ["GB", "UK"],
    "edu.au": ["AU"],
    "mil.uk": ["GB", "UK"],
}

# Suspicious nameserver providers (bullet-proof hosting, etc.)
SUSPICIOUS_NAMESERVERS = set(os.getenv(
    "SUSPICIOUS_NAMESERVERS", "freenom,njalla,1984hosting,shinjiru,flokinet,cyberbunker,ecatel"
).replace(" ", "").split(","))

# DNS anomaly thresholds
MIN_TTL_THRESHOLD = int(os.getenv("MIN_TTL_THRESHOLD", "60"))  # Flag TTLs below this (fast-flux)

# High-risk hosting providers with risk scores
HIGH_RISK_HOSTING = {
    "namecheap": 8,
    "hostinger": 10,
    "bluehost": 6,
    "godaddy": 5,
    "ovh": 7,
    "digitalocean": 5,
    "contabo": 12,
    "shinjiru": 15,
    "flokinet": 18,
    "njalla": 20,
    "1984hosting": 15,
    "cyberbunker": 25,
    "ecatel": 20,
    "bulletproof": 30,
    "offshore": 25
}

# Country risk scores for phishing
COUNTRY_RISK_SCORES = {
    # Very High Risk
    "NG": 20, "RU": 18, "CN": 15, "KP": 25,
    # High Risk
    "RO": 12, "UA": 12, "VN": 10, "ID": 10, "TR": 10,
    "PK": 10, "BD": 10, "KZ": 10, "BY": 12,
    # Medium Risk
    "IN": 5, "BR": 5, "MX": 5, "PH": 5, "TH": 5,
    # Low Risk (negative scores = safer)
    "US": -5, "GB": -5, "CA": -5, "AU": -5, "JP": -5,
    "DE": -5, "FR": -5, "NL": -5, "CH": -5, "SE": -5
}

# Phishing kit path indicators
PHISHING_KIT_PATHS = {
    "/admin/": 10,
    "/panel/": 10,
    "/verify/": 12,
    "/validation/": 12,
    "/secure/": 8,
    "/update/": 10,
    "/confirm/": 10,
    "/suspended/": 15,
    "/locked/": 15,
    "/webscr": 15,  # PayPal phishing
    "/.well-known/": 8,
    "/includes/": 8,
    "/assets/": 5,
    "/process/": 10,
    "/submit/": 8,
    "/redirect/": 10,
    "/gateway/": 10,
    "/authentication/": 12,
    "/2fa/": 12,
    "/otp/": 12
}

# Phishing kit filenames
PHISHING_KIT_FILES = {
    "index.php": 5,
    "login.php": 8,
    "verify.php": 12,
    "process.php": 10,
    "submit.php": 10,
    "confirm.php": 10,
    "update.php": 10,
    "secure.php": 10,
    "validation.php": 12,
    "authenticate.php": 12,
    "signin.php": 8,
    "account.php": 8,
    "webscr.php": 15
}

# Parking page content markers (weighted)
PARKING_CONTENT_MARKERS = {
    "domain for sale": 15,
    "buy this domain": 15,
    "this domain is parked": 20,
    "is for sale": 15,
    "buy now": 12,
    "purchase domain": 12,
    "acquire this domain": 12,
    "make an offer": 12,
    "inquire about this domain": 12,
    "sponsored listings": 10,
    "related searches": 8,
    "domain may be for sale": 12,
    "get this domain": 12,
    "premium domain": 10,
    "backorder this domain": 10,
    "register your domain": 8,
    "this page is parked": 15,
    "under construction": 8,
    "coming soon": 6,
    "website coming soon": 8,
    "stay tuned": 5
}

# Known parking providers (DNS nameservers) - Enhanced
PARKING_NAMESERVERS = {
    # DNS-based parking
    "sedoparking.com", "parkingcrew.net", "bodis.com", "dns-parking.com",
    "cashparking.com", "dan.com", "undeveloped.com", "afternic.com",
    "hugedomains.com", "sav.com", "epik.com", "dynadot.com",
    "uniregistrymarket.link", "parklogic.com", "above.com", "voodoo.com",
    "parkweb.com", "domainnameshop.com", "domainmarket.com",
    # Registrar parking
    "registrar-servers.com", "domaincontrol.com", "plesk.com",
    "register.com", "name.com", "fastpark.net", "domain-parking.net"
}

# Parking provider markers in HTTP/HTML
PARKING_MARKERS = [
    "domain for sale", "buy this domain", "this domain is parked",
    "make an offer", "inquire about this domain", "sponsored listings",
    "related searches", "sedoparking", "parkingcrew", "bodis",
    "cashparking", "afternic", "dan.com", "hugedomains",
    "is for sale", "buy now", "purchase domain", "atom.com"
]

MAX_KEYS = int(os.getenv("MAX_KEYS", "12000"))
GC_AFTER = int(os.getenv("GC_AFTER", "300"))  # seconds

# ------------ Utils ------------
def _now(): return time.time()
def _puny(s): return "xn--" in (s or "")
def _tld(h):
    if not h or "." not in h: return ""
    return h.rsplit(".",1)[-1].lower()
def _safe_int(x, d=0):
    try: return int(x)
    except Exception: return d
def _safe_float(x, d=0.0):
    try: return float(x)
    except Exception: return d
def _drop_heavy(d: dict):
    for k in ("html","raw_html","pdf","screenshot","screenshots","page_html","image_bytes"):
        d.pop(k, None)

def _is_cross_registrable(orig_host, final_url):
    if not orig_host or not final_url: return False
    try:
        fhost = urlparse(final_url).hostname
        if not fhost or "." not in fhost or "." not in orig_host: return False
        return orig_host.split(".",1)[-1].lower() != fhost.split(".",1)[-1].lower()
    except Exception:
        return False

def _extract_subdomain_labels(fqdn):
    """Extract all subdomain labels from FQDN as a list.
    Example: 'dc.crsorgi.gov.in.web.index.dc-verify.info' -> ['dc', 'crsorgi', 'gov', 'in', 'web', 'index', 'dc-verify']
    """
    if not fqdn or "." not in fqdn:
        return []
    parts = fqdn.lower().split(".")
    # Return all parts except the last 2 (assuming last 2 are TLD or registrable)
    # But for multi-part TLDs like .co.uk, this is approximate
    return parts[:-2] if len(parts) > 2 else []

def _detect_tld_impersonation(fqdn, actual_tld):
    """Detect if protected TLDs (gov, edu, mil, ccTLDs) appear in subdomain labels.
    Returns (is_impersonating, impersonated_tld)
    """
    if not fqdn:
        return False, None

    subdomain_labels = _extract_subdomain_labels(fqdn)

    # Check for multi-part protected TLDs first (e.g., gov.in, gov.uk)
    for i in range(len(subdomain_labels) - 1):
        combined = f"{subdomain_labels[i]}.{subdomain_labels[i+1]}"
        if combined in PROTECTED_TLDS and combined != actual_tld:
            return True, combined

    # Check for single-part protected TLDs or ccTLDs
    for label in subdomain_labels:
        if label in PROTECTED_TLDS and label != actual_tld:
            return True, label
        # Also flag if ccTLD appears in subdomain (e.g., paypal.in.scam.com)
        if label in CCTLDS and label != actual_tld:
            return True, label

    return False, None

def _count_subdomain_depth(fqdn):
    """Count the number of subdomain levels.
    Example: 'a.b.c.d.example.com' -> 4 subdomains
    """
    if not fqdn or "." not in fqdn:
        return 0
    parts = fqdn.split(".")
    # Subdomains = total parts - 2 (for domain.tld)
    # This is approximate for multi-part TLDs but good enough for scoring
    return max(0, len(parts) - 2)

def _check_self_referential_mx(fqdn, mx_records):
    """Check if MX records point to the same domain (suspicious)."""
    if not fqdn or not mx_records:
        return False
    fqdn_lower = fqdn.lower().rstrip(".")
    for mx in mx_records:
        mx_lower = (mx or "").lower().rstrip(".")
        if mx_lower == fqdn_lower:
            return True
    return False

def _check_low_ttl(ttls_dict):
    """Check if any TTL values are suspiciously low (fast-flux indicator)."""
    if not ttls_dict:
        return False
    for record_type, ttl in ttls_dict.items():
        if isinstance(ttl, int) and 0 <= ttl < MIN_TTL_THRESHOLD:
            return True
    return False

def _check_geographic_mismatch(fqdn, geoip_data):
    """Check if claimed geographic identity (TLD) mismatches hosting location."""
    if not fqdn or not geoip_data:
        return False, None

    # Extract country from geoip
    actual_country = geoip_data.get("country")
    if not actual_country:
        return False, None

    # Check if domain claims to be from a sensitive TLD
    for sensitive_tld, expected_countries in GEO_SENSITIVE_TLDS.items():
        # Check if this sensitive TLD appears in the FQDN
        if f".{sensitive_tld}." in f".{fqdn.lower()}." or fqdn.lower().endswith(f".{sensitive_tld}"):
            # If actual TLD matches, this is legitimate
            if fqdn.lower().endswith(f".{sensitive_tld}"):
                continue
            # TLD is in subdomain - check if hosting country matches
            if actual_country.upper() not in expected_countries:
                return True, sensitive_tld

    return False, None

# ------------ Fusion state ------------
class LRUState:
    def __init__(self, cap=MAX_KEYS):
        self.cap = cap
        self.data = OrderedDict()  # (fqdn,url) -> {updated, parts{domain,http,features}}
    def upsert(self, key, part, payload):
        v = self.data.get(key, {"updated": _now(), "parts": {}})
        v["parts"][part] = payload
        v["updated"] = _now()
        self.data[key] = v
        self.data.move_to_end(key)
        if len(self.data) > self.cap:
            self.data.popitem(last=False)
        return v
    def gc(self):
        cut = _now() - GC_AFTER
        stale = [k for k,v in self.data.items() if v["updated"] < cut]
        for k in stale: self.data.pop(k, None)

state = LRUState()

# ------------ Enhanced Temporal Correlation ------------
def score_temporal_correlation(domain: Dict, http: Dict) -> Tuple[int, List[str]]:
    """
    Detect suspicious temporal patterns between domain registration and SSL certificate.
    Phishing sites often register domain and get SSL cert on same day.
    """
    score = 0
    reasons = []

    try:
        whois = (domain or {}).get("whois", {})
        tls = (http or {}).get("tls", {})

        domain_age = whois.get("domain_age_days")
        cert_age = tls.get("cert_age_days")

        # Both must exist for correlation
        if not (isinstance(domain_age, (int, float)) and isinstance(cert_age, (int, float))):
            return score, reasons

        # Calculate the gap between domain registration and cert issuance
        cert_gap = abs(domain_age - cert_age)

        # CRITICAL: Same-day registration and cert (highest phishing signal)
        if cert_gap <= 1:
            score += 35
            reasons.append("Domain and SSL cert created same day (automation)")
        # SUSPICIOUS: Same week
        elif cert_gap <= 7:
            score += 20
            reasons.append(f"Domain and cert created within {int(cert_gap)} days")
        # WARNING: Same month
        elif cert_gap <= 30:
            score += 10
            reasons.append("Domain and cert both new (<30 days)")

        # Check for Let's Encrypt on brand new domain (common in phishing)
        cert_issuer = tls.get("cert_issuer", "").lower()
        if domain_age and domain_age < 7 and "let's encrypt" in cert_issuer:
            score += 15
            reasons.append("Let's Encrypt cert on very new domain")

        # Check for very short validity periods (suspicious)
        cert_validity_days = tls.get("cert_validity_days")
        if cert_validity_days and cert_validity_days < 90:
            score += 8
            reasons.append(f"Short cert validity ({cert_validity_days} days)")

    except Exception as e:
        # Silent fail - don't break scoring on error
        pass

    return score, reasons

# ------------ Advanced Behavioral Fingerprinting ------------
def score_behavioral_fingerprints(feat: Dict, http: Dict) -> Tuple[int, List[str]]:
    """
    Detect patterns indicating automated phishing kit deployment.
    Phishing kits have recognizable URL structures and behaviors.
    """
    score = 0
    reasons = []

    try:
        # Extract URL components
        url = (feat or {}).get("url") or (http or {}).get("final_url") or ""
        if not url:
            return score, reasons

        parsed = urlparse(url.lower())
        path = parsed.path
        query = parsed.query

        # Check for phishing kit paths
        for kit_path, risk_score in PHISHING_KIT_PATHS.items():
            if kit_path in path:
                score += risk_score
                reasons.append(f"Suspicious path pattern: {kit_path}")
                break  # Only count one path match

        # Check for phishing kit filenames
        filename = path.split("/")[-1] if "/" in path else path
        if filename in PHISHING_KIT_FILES:
            score += PHISHING_KIT_FILES[filename]
            reasons.append(f"Suspicious file: {filename}")

        # Check for base64 in URL (obfuscation)
        if "base64" in url or re.search(r"[?&][a-z]=[A-Za-z0-9+/]{20,}={0,2}", url):
            score += 18
            reasons.append("Possible base64 encoded payload in URL")

        # Check for multiple suspicious parameters
        suspicious_params = ["id", "token", "session", "key", "auth", "verify", "confirm"]
        param_count = sum(1 for param in suspicious_params if param in query.lower())
        if param_count >= 3:
            score += 15
            reasons.append(f"Multiple suspicious parameters ({param_count})")
        elif param_count >= 2:
            score += 8
            reasons.append("Suspicious URL parameters")

        # Check for double extensions (e.g., document.pdf.exe)
        if re.search(r"\.\w{2,4}\.\w{2,4}$", path):
            score += 20
            reasons.append("Double file extension (masquerading)")

        # Check for URL shortener patterns in path
        if re.search(r"/[a-zA-Z0-9]{5,8}$", path) and len(path) < 15:
            score += 10
            reasons.append("URL shortener pattern detected")

        # Check for credential harvesting patterns
        cred_patterns = [
            "/signin/", "/login/", "/account/", "/myaccount/",
            "/banking/", "/secure/", "/auth/", "/portal/"
        ]
        cred_count = sum(1 for pattern in cred_patterns if pattern in path)
        if cred_count >= 2:
            score += 15
            reasons.append("Multiple credential-related paths")

        # Check for fake security badges in path
        security_fake = ["ssl", "secure", "verified", "trusted", "safe"]
        if any(f"/{word}/" in path or f"-{word}-" in path for word in security_fake):
            score += 12
            reasons.append("Fake security indicator in URL")

    except Exception as e:
        # Silent fail
        pass

    return score, reasons

# ------------ Infrastructure Risk Scoring ------------
def score_infrastructure_risk(domain: Dict, http: Dict) -> Tuple[int, List[str]]:
    """
    Advanced infrastructure analysis considering hosting provider reputation,
    geographic anomalies, and network characteristics.
    """
    score = 0
    reasons = []

    try:
        geoip = (domain or {}).get("geoip", {})
        dns = (domain or {}).get("dns", {})
        whois = (domain or {}).get("whois", {})

        # Extract infrastructure data
        country = (geoip.get("country") or "").upper()
        asn_org = (geoip.get("asn_organization") or "").lower()
        registrar = (whois.get("registrar") or "").lower()
        ns_records = dns.get("NS", [])

        # Score based on hosting provider
        for provider, risk in HIGH_RISK_HOSTING.items():
            if provider in asn_org:
                score += risk
                reasons.append(f"High-risk hosting: {provider}")
                break

        # Score based on country risk
        if country in COUNTRY_RISK_SCORES:
            country_score = COUNTRY_RISK_SCORES[country]

            if country_score > 0:
                reasons.append(f"Hosted in suspicious country: {country}")
            elif country_score < 0:
                # Legitimate country - reduce score slightly
                score += country_score

            score += max(0, country_score)  # Don't let it go too negative

        # Check for suspicious nameserver patterns
        suspicious_ns_patterns = [
            "afraid.org", "no-ip.com", "dyndns.org",  # Dynamic DNS
            "cloudflare",  # Often used to hide real host
            "freenom", "dot.tk",  # Free domain providers
        ]

        for ns in ns_records:
            ns_lower = (ns or "").lower()
            for pattern in suspicious_ns_patterns:
                if pattern in ns_lower:
                    score += 8
                    reasons.append(f"Suspicious nameserver: {pattern}")
                    break

        # Check for bulletproof hosting indicators
        bulletproof_indicators = [
            "offshore", "anonymous", "bulletproof", "dmca ignore",
            "abuse resistant", "complaint resistant"
        ]

        asn_desc = (geoip.get("asn_description") or "").lower()
        for indicator in bulletproof_indicators:
            if indicator in asn_org or indicator in asn_desc:
                score += 25
                reasons.append("Bulletproof hosting detected")
                break

        # Check for residential IP (suspicious for commercial sites)
        if any(term in asn_org for term in ["residential", "broadband", "dsl", "cable", "telecom"]):
            score += 15
            reasons.append("Hosted on residential IP")

        # Check for free/cheap registrars (higher fraud risk)
        risky_registrars = [
            "namecheap", "godaddy", "namesilo", "porkbun",
            "freenom", "dot.tk", "hostinger", "name.com"
        ]

        for risky_reg in risky_registrars:
            if risky_reg in registrar:
                score += 5
                reasons.append(f"Budget registrar: {risky_reg}")
                break

        # Check for IP-only hosting (no reverse DNS)
        a_records = dns.get("A", [])
        ptr_records = dns.get("PTR", [])
        if a_records and not ptr_records:
            score += 8
            reasons.append("No reverse DNS configured")

        # Multi-country infrastructure (CDN or suspicious)
        if isinstance(a_records, list) and len(a_records) > 1:
            # Would need GeoIP for each IP, but multiple IPs can be suspicious
            if len(a_records) > 5:
                score += 10
                reasons.append(f"Unusual number of IPs ({len(a_records)})")

    except Exception as e:
        # Silent fail
        pass

    return score, reasons

# ------------ Improved Parked Domain Detection ------------
def detect_parked_domain(domain: Dict, http: Dict, feat: Dict) -> Tuple[bool, List[str], int]:
    """
    Multi-signal parked domain detection with confidence scoring.
    Returns: (is_parked, reasons, confidence_score)
    """
    signals = []
    confidence = 0

    try:
        # Signal 1: DNS nameserver analysis (highest confidence)
        dns = (domain or {}).get("dns", {})
        ns_records = dns.get("NS", [])

        for ns in ns_records:
            ns_lower = (ns or "").lower()
            for parking_provider in PARKING_NAMESERVERS:
                if parking_provider in ns_lower:
                    signals.append(f"NS points to parking: {parking_provider}")
                    confidence += 40
                    break

        # Signal 2: HTTP redirect to parking service
        final_url = (http or {}).get("final_url") or ""
        if final_url:
            url_lower = final_url.lower()
            parking_urls = [
                "sedo.com", "dan.com", "afternic.com", "hugedomains.com",
                "godaddy.com/domainfind", "uniregistry.com", "flippa.com",
                "brandbucket.com", "brandroot.com", "atom.com", "domains.atom.com"
            ]

            for parking_url in parking_urls:
                if parking_url in url_lower:
                    signals.append(f"Redirects to parking: {parking_url}")
                    confidence += 35
                    break

        # Signal 3: Page content analysis
        if feat:
            title = (feat.get("title") or "").lower()
            page_text = (feat.get("page_text") or "")[:5000].lower()  # First 5KB
            # Include OCR text when available (sale pages often render text in images)
            ocr_text = ""
            ocr = feat.get("ocr")
            if isinstance(ocr, dict):
                ocr_text = (ocr.get("text_excerpt") or "")[:5000]
            elif isinstance(ocr, str):
                try:
                    ocr_obj = json.loads(ocr)
                    ocr_text = (ocr_obj.get("text_excerpt") or "")[:5000]
                except Exception:
                    pass
            combined = (title + " " + page_text + " " + ocr_text).lower()

            # Check weighted content markers
            content_score = 0
            found_markers = []
            for marker, weight in PARKING_CONTENT_MARKERS.items():
                if marker in combined:
                    content_score += weight
                    found_markers.append(marker)

            if content_score >= 25:
                signals.append(f"Parking content detected ({len(found_markers)} markers)")
                confidence += min(30, content_score)

        # Signal 4: Infrastructure indicators
        mx_count = (domain or {}).get("mx_count") or dns.get("MX_count", 0)
        a_count = (domain or {}).get("a_count") or len(dns.get("A", []))

        # No email configured
        if mx_count == 0:
            signals.append("No MX records")
            confidence += 10

        # Minimal DNS (just A record)
        if a_count == 1 and mx_count == 0:
            signals.append("Minimal DNS configuration")
            confidence += 10

        # Signal 5: Page characteristics
        if feat:
            form_count = feat.get("form_count", 0)
            external_links = feat.get("external_links", 0)
            html_size = feat.get("html_size", 0)

            # No forms (no functionality)
            if form_count == 0:
                signals.append("No forms on page")
                confidence += 8

            # Very small page
            if 0 < html_size < 5000:
                signals.append(f"Minimal content ({html_size} bytes)")
                confidence += 12

            # Only external links (ads/affiliates)
            if external_links > 5 and form_count == 0:
                signals.append("Multiple external links, no forms")
                confidence += 15

        # Signal 6: Domain age and registration patterns
        whois = (domain or {}).get("whois", {})
        is_newly = whois.get("is_newly_registered", False)
        days_until_expiry = whois.get("days_until_expiry")

        if is_newly:
            signals.append("Recently registered")
            confidence += 5

        # Auto-renew not set (temporary registration)
        if isinstance(days_until_expiry, int) and days_until_expiry < 60:
            signals.append(f"Expires soon ({days_until_expiry} days)")
            confidence += 8

        # Signal 7: HTTP response analysis
        if http:
            status = http.get("status_code") or http.get("status")
            server = (http.get("server") or "").lower()

            # Specific parking server signatures
            parking_servers = ["parkingcrew", "sedoparking", "bodis", "dan.com"]
            for park_server in parking_servers:
                if park_server in server:
                    signals.append(f"Parking server: {park_server}")
                    confidence += 30
                    break

        # Determine if parked based on confidence
        is_parked = confidence >= 50

        # But not if it's an established domain (>1 year old)
        domain_age = whois.get("domain_age_days", 0)
        if is_parked and domain_age > 365:
            is_parked = False
            signals.append("(Established domain, not parked)")
            confidence = max(0, confidence - 40)

    except Exception as e:
        # Silent fail
        pass

    return is_parked, signals, confidence

# ------------ Scoring (brand-agnostic) ------------
def score_bundle(domain: dict, http: dict, feat: dict):
    reasons, cats = [], defaultdict(int)
    score = 0

    # Keys
    fqdn = (domain.get("canonical_fqdn") if domain else None) or (http or {}).get("canonical_fqdn") or (feat or {}).get("canonical_fqdn") or ""
    registrable = (domain.get("registrable") if domain else None) or (http or {}).get("registrable") or (feat or {}).get("registrable") or ""
    url = (http or {}).get("final_url") or (http or {}).get("url") or (feat or {}).get("url")
    host = fqdn or (urlparse(url).hostname if url else registrable)
    tld = _tld(host)

    # Domain WHOIS/age
    whois = (domain or {}).get("whois") or {}
    is_very_new = bool(whois.get("is_very_new"))
    is_newly = bool(whois.get("is_newly_registered"))
    days_to_exp = whois.get("days_until_expiry")
    if is_very_new: reasons.append("Domain <7d"); cats["whois"]+=25; score+=25
    elif is_newly:  reasons.append("Domain <30d"); cats["whois"]+=12; score+=12
    if isinstance(days_to_exp,int) and days_to_exp < 30:
        reasons.append("Registration expires soon"); cats["whois"]+=5; score+=5

    # URL/features (support both flattened & nested as per your crawler)
    url_len    = _safe_int((feat or {}).get("url_length") or (feat or {}).get("url_features",{}).get("url_length"))
    url_ent    = _safe_float((feat or {}).get("url_entropy") or (feat or {}).get("url_features",{}).get("url_entropy"))
    num_subdom = _safe_int((feat or {}).get("num_subdomains") or (feat or {}).get("url_features",{}).get("num_subdomains"))
    has_repdig = bool((feat or {}).get("has_repeated_digits") or (feat or {}).get("url_features",{}).get("has_repeated_digits"))
    idn = (feat or {}).get("idn") or {}
    is_idn  = bool((feat or {}).get("is_idn") or idn.get("is_idn"))
    mixed   = bool((feat or {}).get("mixed_script") or idn.get("mixed_script"))

    if _puny(host): reasons.append("IDN/punycode"); cats["url"]+=15; score+=15
    if is_idn:      reasons.append("IDN (Unicode)"); cats["url"]+=10; score+=10
    if mixed:       reasons.append("Mixed scripts");  cats["url"]+=10; score+=10
    if url_len >= 130: reasons.append("Very long URL"); cats["url"]+=10; score+=10
    elif url_len >= 80: reasons.append("Long URL");     cats["url"]+=5;  score+=5
    if url_ent and url_ent > 4.5: reasons.append("High URL entropy"); cats["url"]+=15; score+=15
    elif url_ent and url_ent > 4.0: reasons.append("Elevated URL entropy"); cats["url"]+=10; score+=10
    # Enhanced subdomain depth scoring
    actual_subdom_depth = _count_subdomain_depth(fqdn) if fqdn else num_subdom
    if actual_subdom_depth >= 8:
        reasons.append("Extreme subdomain depth (≥8)"); cats["url"]+=20; score+=20
    elif actual_subdom_depth >= 6:
        reasons.append("Very deep subdomains (≥6)"); cats["url"]+=15; score+=15
    elif actual_subdom_depth >= 5:
        reasons.append("Many subdomains (≥5)"); cats["url"]+=12; score+=12
    elif actual_subdom_depth >= 3:
        reasons.append("Multiple subdomains (≥3)"); cats["url"]+=8; score+=8

    if has_repdig: reasons.append("Repeated digits"); cats["url"]+=6; score+=6
    if tld in RISKY_TLDS: reasons.append(f"Risky TLD .{tld}"); cats["domain"]+=6; score+=6

    # TLD impersonation detection (CRITICAL for phishing)
    is_impersonating, impersonated_tld = _detect_tld_impersonation(fqdn, tld)
    if is_impersonating:
        if impersonated_tld in PROTECTED_TLDS:
            reasons.append(f"TLD impersonation: {impersonated_tld} in subdomain")
            cats["impersonation"]+=40; score+=40
        else:
            reasons.append(f"ccTLD in subdomain: {impersonated_tld}")
            cats["impersonation"]+=30; score+=30

    # Forms/keywords
    forms = (feat or {}).get("forms") or {}
    form_count = _safe_int((feat or {}).get("form_count") or forms.get("count"))
    pw = _safe_int((feat or {}).get("password_fields") or forms.get("password_fields"))
    em = _safe_int((feat or {}).get("email_fields") or forms.get("email_fields"))
    has_cred = bool((feat or {}).get("has_credential_form") or (pw>0 and em>0))
    kw_count = _safe_int((feat or {}).get("keyword_count") or (feat or {}).get("text_keywords_count"))

    if has_cred: reasons.append("Credential form"); cats["forms"]+=22; score+=22
    if _safe_int((feat or {}).get("suspicious_form_count") or forms.get("suspicious_form_count"))>0:
        reasons.append("Suspicious forms"); cats["forms"]+=18; score+=18
    if _safe_int((feat or {}).get("forms_to_ip") or forms.get("forms_to_ip"))>0:
        reasons.append("Forms submit to IP"); cats["forms"]+=10; score+=10
    if _safe_int((feat or {}).get("forms_to_suspicious_tld") or forms.get("forms_to_suspicious_tld"))>0:
        reasons.append("Forms submit to suspicious TLD"); cats["forms"]+=10; score+=10
    if _safe_int((feat or {}).get("forms_to_private_ip") or forms.get("forms_to_private_ip"))>0:
        reasons.append("Forms submit to private IP"); cats["forms"]+=10; score+=10
    if kw_count >= 8: reasons.append("Many phishing keywords"); cats["content"]+=18; score+=18
    elif kw_count >= 3: reasons.append("Phishing keywords present"); cats["content"]+=12; score+=12
    elif kw_count >= 1: reasons.append("Keyword hint"); cats["content"]+=8; score+=8

    # JavaScript obfuscation / suspicious behavior
    js_obfuscated = bool((feat or {}).get("js_obfuscated"))
    js_obfuscated_count = _safe_int((feat or {}).get("js_obfuscated_count"))
    if js_obfuscated or js_obfuscated_count > 0:
        reasons.append("Obfuscated JavaScript detected"); cats["javascript"]+=15; score+=15

    # TLS (from http.probed)
    tls = (http or {}).get("tls") or {}
    if tls.get("is_self_signed"):      reasons.append("TLS self-signed"); cats["ssl"]+=40; score+=40
    if tls.get("has_domain_mismatch"): reasons.append("TLS CN mismatch"); cats["ssl"]+=25; score+=25
    if tls.get("cert_is_very_new"):    reasons.append("Cert very new (<7d)"); cats["ssl"]+=12; score+=12
    elif tls.get("is_newly_issued"):   reasons.append("Cert new (<30d)");     cats["ssl"]+=8;  score+=8
    if _safe_int(tls.get("cert_risk_score")): 
        inc = min(20, int(_safe_int(tls.get("cert_risk_score")) * 0.2))
        cats["ssl"] += inc; score += inc

    # Redirect cross-registrable
    if _is_cross_registrable((http or {}).get("original_host") or (http or {}).get("host"),
                             (http or {}).get("final_url") or (http or {}).get("url")):
        reasons.append("Redirect crosses registrable"); cats["http"]+=12; score+=12

    # DNS anomaly detection
    dns = (domain or {}).get("dns") or {}
    mx_records = dns.get("MX") or []
    ttls = dns.get("ttls") or {}
    ns_records = dns.get("NS") or []

    # Self-referential MX (email configuration pointing to itself - suspicious)
    if _check_self_referential_mx(fqdn, mx_records):
        reasons.append("Self-referential MX record"); cats["dns"]+=10; score+=10

    # Low/zero TTL values (fast-flux DNS indicator)
    if _check_low_ttl(ttls):
        reasons.append("Suspiciously low TTL (fast-flux)"); cats["dns"]+=8; score+=8

    # Missing WHOIS data (domain registration hidden)
    whois_error = whois.get("error")
    if whois_error and "no output" in str(whois_error).lower():
        reasons.append("WHOIS data unavailable"); cats["dns"]+=5; score+=5

    # Suspicious nameserver providers
    for ns in ns_records:
        ns_lower = (ns or "").lower()
        for suspicious_provider in SUSPICIOUS_NAMESERVERS:
            if suspicious_provider in ns_lower:
                reasons.append(f"Suspicious nameserver ({suspicious_provider})"); cats["dns"]+=12; score+=12
                break

    # Geographic mismatch detection
    geoip = (domain or {}).get("geoip") or {}
    has_geo_mismatch, claimed_tld = _check_geographic_mismatch(fqdn, geoip)
    if has_geo_mismatch:
        actual_country = geoip.get("country", "unknown")
        reasons.append(f"Geographic mismatch: claims {claimed_tld}, hosted in {actual_country}")
        cats["geo"]+=15; score+=15

    # Typosquatting / Lookalike detection
    # Check if domain is flagged as a lookalike of seed domain
    seed_registrable = (domain or {}).get("seed_registrable") or (http or {}).get("seed_registrable") or (feat or {}).get("seed_registrable")
    is_original_seed = (domain or {}).get("is_original_seed") or (http or {}).get("is_original_seed") or (feat or {}).get("is_original_seed")

    # If domain has a seed but is NOT the original seed, it's a potential typosquat
    if seed_registrable and not is_original_seed and seed_registrable != registrable:
        # Basic lookalike detection - domain differs from seed
        reasons.append(f"Potential typosquat of {seed_registrable}")
        cats["typosquat"]+=25; score+=25

        # TODO: Integrate DNSTwist similarity score from Redis for more precise scoring
        # Redis keys: dnstwist:variants:{domain}, dnstwist:similarity:{domain}
        # Higher similarity (closer to seed) = higher score

    # Accurate parked domain detection
    is_parked = False
    parked_reasons = []

    # 1. DNS-based parking detection (highest signal)
    dns = (domain or {}).get("dns") or {}
    ns_records = dns.get("NS") or []
    for ns in ns_records:
        ns_lower = (ns or "").lower()
        for parker in PARKING_NAMESERVERS:
            if parker in ns_lower:
                is_parked = True
                parked_reasons.append(f"NS points to parking provider ({parker})")
                break
        if is_parked:
            break

    # 2. HTTP redirect to parking marketplace
    http_url = (http or {}).get("final_url") or (http or {}).get("url") or ""
    if http_url and not is_parked:
        http_lower = http_url.lower()
        for parker in ["sedo.com", "dan.com", "afternic.com", "hugedomains.com", "godaddy.com/domainfind", "sav.com/auction", "atom.com", "domains.atom.com"]:
            if parker in http_lower:
                is_parked = True
                parked_reasons.append(f"Redirects to parking marketplace ({parker})")
                break

    # 3. HTML content markers (if no DNS/redirect signal)
    if not is_parked and feat:
        title = (feat or {}).get("title") or ""
        page_text = (feat or {}).get("page_text") or ""
        # Include OCR text if present (parking sale banners are often image-based)
        ocr_text = ""
        ocr = (feat or {}).get("ocr")
        if isinstance(ocr, dict):
            ocr_text = (ocr.get("text_excerpt") or "")
        elif isinstance(ocr, str):
            try:
                ocr_obj = json.loads(ocr)
                ocr_text = (ocr_obj.get("text_excerpt") or "")
            except Exception:
                pass
        combined = (title + " " + page_text + " " + ocr_text).lower()
        marker_count = sum(1 for marker in PARKING_MARKERS if marker in combined)
        if marker_count >= 2:  # At least 2 parking phrases
            is_parked = True
            parked_reasons.append(f"Parking page content detected ({marker_count} markers)")

    # 4. No MX + parking NS (supporting signal)
    mx_count = _safe_int((domain or {}).get("mx_count") or dns.get("MX_count", 0))
    if is_parked and mx_count == 0:
        parked_reasons.append("No MX records")

    # Verdict with monitoring support
    monitor_until = None
    monitor_reason = None
    requires_monitoring = False

    if is_parked:
        verdict, conf, final_score = "parked", 0.95, 0
        reasons = [f"Parked domain: {'; '.join(parked_reasons)}"]
        cats = {"parked": 100}
        if MONITOR_PARKED:
            monitor_until = int(time.time() + (MONITOR_DAYS * 86400))
            monitor_reason = "parked"
            requires_monitoring = True
    else:
        final_score = score
        if score >= THRESH_PHISHING:
            verdict, conf = "phishing", min(0.99, 0.9 + (score-THRESH_PHISHING)/100.0)
        elif score >= THRESH_SUSPICIOUS:
            verdict, conf = "suspicious", 0.65 + (score-THRESH_SUSPICIOUS)/200.0
            if MONITOR_SUSPICIOUS:
                monitor_until = int(time.time() + (MONITOR_DAYS * 86400))
                monitor_reason = "suspicious"
                requires_monitoring = True
        else:
            verdict, conf = "benign", 0.5
            # Benign domains don't require monitoring
            requires_monitoring = False

    result = {
        "verdict": verdict,
        "final_verdict": verdict,  # Separate field for final classification
        "confidence": round(conf, 3),
        "score": final_score,
        "reasons": reasons[:20],
        "categories": dict(cats),
        "canonical_fqdn": fqdn,
        "registrable": registrable,
        "url": url,
        "requires_monitoring": requires_monitoring,
    }

    if monitor_until:
        result["monitor_until"] = monitor_until
        result["monitor_reason"] = monitor_reason

    return result

# ------------ Enhanced Scoring Function ------------
def enhanced_score_bundle(domain: dict, http: dict, feat: dict):
    """Enhanced scoring with all new detection modules"""
    reasons, cats = [], defaultdict(int)
    score = 0

    # Get basic identifiers
    fqdn = (domain.get("canonical_fqdn") if domain else None) or \
           (http or {}).get("canonical_fqdn") or \
           (feat or {}).get("canonical_fqdn") or ""
    registrable = (domain.get("registrable") if domain else None) or \
                  (http or {}).get("registrable") or \
                  (feat or {}).get("registrable") or ""
    url = (http or {}).get("final_url") or \
          (http or {}).get("url") or \
          (feat or {}).get("url")
    host = fqdn or (urlparse(url).hostname if url else registrable)
    tld = _tld(host)

    # === ORIGINAL SCORING (from score_bundle) ===
    # Domain WHOIS/age
    whois = (domain or {}).get("whois") or {}
    is_very_new = bool(whois.get("is_very_new"))
    is_newly = bool(whois.get("is_newly_registered"))
    days_to_exp = whois.get("days_until_expiry")
    if is_very_new: reasons.append("Domain <7d"); cats["whois"]+=25; score+=25
    elif is_newly:  reasons.append("Domain <30d"); cats["whois"]+=12; score+=12
    if isinstance(days_to_exp,int) and days_to_exp < 30:
        reasons.append("Registration expires soon"); cats["whois"]+=5; score+=5

    # URL/features
    url_len    = _safe_int((feat or {}).get("url_length") or (feat or {}).get("url_features",{}).get("url_length"))
    url_ent    = _safe_float((feat or {}).get("url_entropy") or (feat or {}).get("url_features",{}).get("url_entropy"))
    num_subdom = _safe_int((feat or {}).get("num_subdomains") or (feat or {}).get("url_features",{}).get("num_subdomains"))
    has_repdig = bool((feat or {}).get("has_repeated_digits") or (feat or {}).get("url_features",{}).get("has_repeated_digits"))
    idn = (feat or {}).get("idn") or {}
    is_idn  = bool((feat or {}).get("is_idn") or idn.get("is_idn"))
    mixed   = bool((feat or {}).get("mixed_script") or idn.get("mixed_script"))

    if _puny(host): reasons.append("IDN/punycode"); cats["url"]+=15; score+=15
    if is_idn:      reasons.append("IDN (Unicode)"); cats["url"]+=10; score+=10
    if mixed:       reasons.append("Mixed scripts");  cats["url"]+=10; score+=10
    if url_len >= 130: reasons.append("Very long URL"); cats["url"]+=10; score+=10
    elif url_len >= 80: reasons.append("Long URL");     cats["url"]+=5;  score+=5
    if url_ent and url_ent > 4.5: reasons.append("High URL entropy"); cats["url"]+=15; score+=15
    elif url_ent and url_ent > 4.0: reasons.append("Elevated URL entropy"); cats["url"]+=10; score+=10

    # Enhanced subdomain depth scoring
    actual_subdom_depth = _count_subdomain_depth(fqdn) if fqdn else num_subdom
    if actual_subdom_depth >= 8:
        reasons.append("Extreme subdomain depth (≥8)"); cats["url"]+=20; score+=20
    elif actual_subdom_depth >= 6:
        reasons.append("Very deep subdomains (≥6)"); cats["url"]+=15; score+=15
    elif actual_subdom_depth >= 5:
        reasons.append("Many subdomains (≥5)"); cats["url"]+=12; score+=12
    elif actual_subdom_depth >= 3:
        reasons.append("Multiple subdomains (≥3)"); cats["url"]+=8; score+=8

    if has_repdig: reasons.append("Repeated digits"); cats["url"]+=6; score+=6
    if tld in RISKY_TLDS: reasons.append(f"Risky TLD .{tld}"); cats["domain"]+=6; score+=6

    # TLD impersonation detection
    is_impersonating, impersonated_tld = _detect_tld_impersonation(fqdn, tld)
    if is_impersonating:
        if impersonated_tld in PROTECTED_TLDS:
            reasons.append(f"TLD impersonation: {impersonated_tld} in subdomain")
            cats["impersonation"]+=40; score+=40
        else:
            reasons.append(f"ccTLD in subdomain: {impersonated_tld}")
            cats["impersonation"]+=30; score+=30

    # Forms/keywords
    forms = (feat or {}).get("forms") or {}
    form_count = _safe_int((feat or {}).get("form_count") or forms.get("count"))
    pw = _safe_int((feat or {}).get("password_fields") or forms.get("password_fields"))
    em = _safe_int((feat or {}).get("email_fields") or forms.get("email_fields"))
    has_cred = bool((feat or {}).get("has_credential_form") or (pw>0 and em>0))
    kw_count = _safe_int((feat or {}).get("keyword_count") or (feat or {}).get("text_keywords_count"))

    if has_cred: reasons.append("Credential form"); cats["forms"]+=22; score+=22
    if _safe_int((feat or {}).get("suspicious_form_count") or forms.get("suspicious_form_count"))>0:
        reasons.append("Suspicious forms"); cats["forms"]+=18; score+=18
    if _safe_int((feat or {}).get("forms_to_ip") or forms.get("forms_to_ip"))>0:
        reasons.append("Forms submit to IP"); cats["forms"]+=10; score+=10
    if _safe_int((feat or {}).get("forms_to_suspicious_tld") or forms.get("forms_to_suspicious_tld"))>0:
        reasons.append("Forms submit to suspicious TLD"); cats["forms"]+=10; score+=10
    if _safe_int((feat or {}).get("forms_to_private_ip") or forms.get("forms_to_private_ip"))>0:
        reasons.append("Forms submit to private IP"); cats["forms"]+=10; score+=10
    if kw_count >= 8: reasons.append("Many phishing keywords"); cats["content"]+=18; score+=18
    elif kw_count >= 3: reasons.append("Phishing keywords present"); cats["content"]+=12; score+=12
    elif kw_count >= 1: reasons.append("Keyword hint"); cats["content"]+=8; score+=8

    # JavaScript obfuscation
    js_obfuscated = bool((feat or {}).get("js_obfuscated"))
    js_obfuscated_count = _safe_int((feat or {}).get("js_obfuscated_count"))
    if js_obfuscated or js_obfuscated_count > 0:
        reasons.append("Obfuscated JavaScript detected"); cats["javascript"]+=15; score+=15

    # TLS
    tls = (http or {}).get("tls") or {}
    if tls.get("is_self_signed"):      reasons.append("TLS self-signed"); cats["ssl"]+=40; score+=40
    if tls.get("has_domain_mismatch"): reasons.append("TLS CN mismatch"); cats["ssl"]+=25; score+=25
    if tls.get("cert_is_very_new"):    reasons.append("Cert very new (<7d)"); cats["ssl"]+=12; score+=12
    elif tls.get("is_newly_issued"):   reasons.append("Cert new (<30d)");     cats["ssl"]+=8;  score+=8
    if _safe_int(tls.get("cert_risk_score")):
        inc = min(20, int(_safe_int(tls.get("cert_risk_score")) * 0.2))
        cats["ssl"] += inc; score += inc

    # Redirect cross-registrable
    if _is_cross_registrable((http or {}).get("original_host") or (http or {}).get("host"),
                             (http or {}).get("final_url") or (http or {}).get("url")):
        reasons.append("Redirect crosses registrable"); cats["http"]+=12; score+=12

    # DNS anomaly detection
    dns = (domain or {}).get("dns") or {}
    mx_records = dns.get("MX") or []
    ttls = dns.get("ttls") or {}
    ns_records = dns.get("NS") or []

    if _check_self_referential_mx(fqdn, mx_records):
        reasons.append("Self-referential MX record"); cats["dns"]+=10; score+=10

    if _check_low_ttl(ttls):
        reasons.append("Suspiciously low TTL (fast-flux)"); cats["dns"]+=8; score+=8

    whois_error = whois.get("error")
    if whois_error and "no output" in str(whois_error).lower():
        reasons.append("WHOIS data unavailable"); cats["dns"]+=5; score+=5

    for ns in ns_records:
        ns_lower = (ns or "").lower()
        for suspicious_provider in SUSPICIOUS_NAMESERVERS:
            if suspicious_provider in ns_lower:
                reasons.append(f"Suspicious nameserver ({suspicious_provider})"); cats["dns"]+=12; score+=12
                break

    # Geographic mismatch detection
    geoip = (domain or {}).get("geoip") or {}
    has_geo_mismatch, claimed_tld = _check_geographic_mismatch(fqdn, geoip)
    if has_geo_mismatch:
        actual_country = geoip.get("country", "unknown")
        reasons.append(f"Geographic mismatch: claims {claimed_tld}, hosted in {actual_country}")
        cats["geo"]+=15; score+=15

    # Typosquatting detection
    seed_registrable = (domain or {}).get("seed_registrable") or (http or {}).get("seed_registrable") or (feat or {}).get("seed_registrable")
    is_original_seed = (domain or {}).get("is_original_seed") or (http or {}).get("is_original_seed") or (feat or {}).get("is_original_seed")

    if seed_registrable and not is_original_seed and seed_registrable != registrable:
        reasons.append(f"Potential typosquat of {seed_registrable}")
        cats["typosquat"]+=25; score+=25

    # === ENHANCED SCORING MODULES ===

    # 1. Temporal Correlation
    temp_score, temp_reasons = score_temporal_correlation(domain, http)
    if temp_score > 0:
        score += temp_score
        cats["temporal"] += temp_score
        reasons.extend(temp_reasons)

    # 2. Behavioral Fingerprinting
    behavior_score, behavior_reasons = score_behavioral_fingerprints(feat, http)
    if behavior_score > 0:
        score += behavior_score
        cats["behavior"] += behavior_score
        reasons.extend(behavior_reasons)

    # 3. Infrastructure Risk
    infra_score, infra_reasons = score_infrastructure_risk(domain, http)
    if infra_score > 0:
        score += infra_score
        cats["infrastructure"] += infra_score
        reasons.extend(infra_reasons)

    # 4. Enhanced Parked Detection
    is_parked, parked_signals, parked_confidence = detect_parked_domain(domain, http, feat)

    # === VERDICT DETERMINATION ===
    monitor_until = None
    monitor_reason = None
    requires_monitoring = False

    if is_parked and parked_confidence >= 50:
        verdict = "parked"
        conf = min(0.95, 0.5 + parked_confidence / 200)
        final_score = parked_confidence  # Use confidence as score for parked
        reasons = parked_signals  # Replace reasons with parking signals
        cats = {"parked": parked_confidence}

        # Only monitor newly registered parked domains
        if whois.get("is_newly_registered") and MONITOR_PARKED:
            monitor_until = int(time.time() + (MONITOR_DAYS * 86400))
            monitor_reason = "parked"
            requires_monitoring = True
    else:
        final_score = score

        if score >= THRESH_PHISHING:
            verdict = "phishing"
            conf = min(0.99, 0.9 + (score - THRESH_PHISHING) / 100.0)
        elif score >= THRESH_SUSPICIOUS:
            verdict = "suspicious"
            conf = 0.65 + (score - THRESH_SUSPICIOUS) / 200.0
            if MONITOR_SUSPICIOUS:
                monitor_until = int(time.time() + (MONITOR_DAYS * 86400))
                monitor_reason = "suspicious"
                requires_monitoring = True
        else:
            verdict = "benign"
            conf = 0.5
            requires_monitoring = False

    # Build result
    result = {
        "verdict": verdict,
        "final_verdict": verdict,
        "confidence": round(conf, 3),
        "score": final_score,
        "reasons": reasons[:20],  # Limit to top 20 reasons
        "categories": dict(cats),
        "canonical_fqdn": fqdn,
        "registrable": registrable,
        "url": url,
        "requires_monitoring": requires_monitoring,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    if monitor_until:
        result["monitor_until"] = monitor_until
        result["monitor_reason"] = monitor_reason

    # Add enrichment metadata
    result["enrichment"] = {
        "has_temporal_analysis": temp_score > 0,
        "has_behavioral_analysis": behavior_score > 0,
        "has_infrastructure_analysis": infra_score > 0,
        "parked_confidence": parked_confidence if is_parked else 0
    }

    return result

# ------------ Cross-Domain Redirect Handling ------------

def extract_registrable_domain(url: str) -> Optional[str]:
    """
    Extract registrable domain from URL, normalizing www. subdomain.
    Examples:
        https://www.example.com/path -> example.com
        https://example.com -> example.com
        https://sub.example.com -> sub.example.com
    """
    if not url:
        return None

    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return None

        hostname = hostname.lower()

        # Normalize www. subdomain
        if hostname.startswith("www.") and "." in hostname[4:]:
            hostname = hostname[4:]

        return hostname
    except:
        return None

def extract_cross_domain_redirect_info(http: dict, feat: dict) -> Tuple[bool, Optional[str], Optional[str], List[str], int]:
    """
    Detect if redirect crosses domain boundaries.

    Returns:
        (is_cross_domain, original_domain, final_domain, redirect_chain, cross_domain_hop_count)

    Examples:
        phishing.com -> legitimate.com: (True, "phishing.com", "legitimate.com", [...], 1)
        example.com -> www.example.com: (False, "example.com", "example.com", [...], 0)
    """
    # Extract redirect chain from http or feat data
    redirect_chain = (http or {}).get("redirect_chain") or \
                     (feat or {}).get("redirect_chain") or []

    # Need at least 2 URLs for a redirect
    if not redirect_chain or len(redirect_chain) < 2:
        return False, None, None, [], 0

    # Extract domains from each URL in chain
    domains = []
    for url in redirect_chain:
        domain = extract_registrable_domain(url)
        if domain:
            domains.append(domain)

    if len(domains) < 2:
        return False, None, None, redirect_chain, 0

    # Track unique domains (already normalized with www. stripped)
    unique_domains = []
    for d in domains:
        if d not in unique_domains:
            unique_domains.append(d)

    # Cross-domain if we have multiple unique domains
    is_cross_domain = len(unique_domains) > 1
    original_domain = domains[0] if domains else None
    final_domain = domains[-1] if domains else None
    cross_domain_hops = len(unique_domains) - 1

    return is_cross_domain, original_domain, final_domain, redirect_chain, cross_domain_hops

def calculate_redirect_penalty(redirect_chain: List[str], cross_domain_hops: int) -> Tuple[int, List[str]]:
    """
    Calculate penalty for redirect behavior.

    Scoring:
        +10 points per cross-domain hop
        +15 bonus for URL shorteners in chain
        +10 bonus for free hosting in chain

    Returns:
        (penalty_score, penalty_reasons)
    """
    penalty = cross_domain_hops * 10
    reasons = []

    if cross_domain_hops > 0:
        reasons.append(f"Cross-domain redirect: {cross_domain_hops} hop(s)")

    # Check intermediate domains for suspicious patterns
    # Skip first (original) and last (final) - only check middle hops
    if len(redirect_chain) > 2:
        intermediate_urls = redirect_chain[1:-1]

        # URL shortener patterns
        shortener_patterns = [
            "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
            "rebrandly.com", "short.io", "cutt.ly", "is.gd", "v.gd"
        ]

        # Free hosting patterns
        free_hosting_patterns = [
            "000webhostapp.com", "infinityfreeapp.com", "netlify.app",
            "vercel.app", "herokuapp.com", "repl.co", "glitch.me"
        ]

        for url in intermediate_urls:
            domain = extract_registrable_domain(url) or ""

            # Check for URL shorteners
            for pattern in shortener_patterns:
                if pattern in domain:
                    penalty += 15
                    reasons.append(f"Redirect via URL shortener: {domain}")
                    break

            # Check for free hosting
            for pattern in free_hosting_patterns:
                if pattern in domain:
                    penalty += 10
                    reasons.append(f"Redirect via free hosting: {domain}")
                    break

    return penalty, reasons

def build_nested_final_website_data(domain: dict, http: dict, feat: dict, final_domain: str, final_score: int, final_verdict: str, final_reasons: List[str]) -> dict:
    """
    Build nested data structure containing all information about the final redirect destination.

    This includes DNS, WHOIS, features, artifacts, and individual scoring for the final domain.
    """
    nested_data = {
        "domain": final_domain,
        "url": (feat or {}).get("url") or (http or {}).get("final_url") or "",
    }

    # Add DNS data if available (from original domain record or probed data)
    if domain and domain.get("dns"):
        nested_data["dns"] = domain.get("dns")

    if domain and domain.get("whois"):
        nested_data["whois"] = domain.get("whois")

    if domain and domain.get("geoip"):
        nested_data["geoip"] = domain.get("geoip")

    if domain and domain.get("rdap"):
        nested_data["rdap"] = domain.get("rdap")

    # Add all features from final domain
    if feat:
        # URL features
        if feat.get("url_features"):
            nested_data["url_features"] = feat["url_features"]

        # Forms analysis
        if feat.get("forms"):
            nested_data["forms"] = feat["forms"]

        # IDN analysis
        if feat.get("idn"):
            nested_data["idn"] = feat["idn"]

        # TLS/SSL info
        if feat.get("ssl_info") or feat.get("tls"):
            nested_data["tls"] = feat.get("ssl_info") or feat.get("tls")

        # JavaScript analysis
        if feat.get("javascript"):
            nested_data["javascript"] = feat["javascript"]

        # Text keywords
        if feat.get("text_keywords"):
            nested_data["text_keywords"] = feat["text_keywords"]

        # OCR data
        if feat.get("ocr"):
            nested_data["ocr"] = feat["ocr"]

        # Image OCR
        if feat.get("image_ocr"):
            nested_data["image_ocr"] = feat["image_ocr"]

        # Image metadata
        if feat.get("image_metadata"):
            nested_data["image_metadata"] = feat["image_metadata"]

        # Favicon
        if feat.get("favicon_md5"):
            nested_data["favicon_md5"] = feat["favicon_md5"]
        if feat.get("favicon_sha256"):
            nested_data["favicon_sha256"] = feat["favicon_sha256"]
        if feat.get("favicon_color_scheme"):
            nested_data["favicon_color_scheme"] = feat["favicon_color_scheme"]

        # Page metadata
        if feat.get("title"):
            nested_data["title"] = feat["title"]
        if feat.get("html_length_bytes"):
            nested_data["html_size"] = feat["html_length_bytes"]
        if feat.get("external_links") is not None:
            nested_data["external_links"] = feat["external_links"]
        if feat.get("internal_links") is not None:
            nested_data["internal_links"] = feat["internal_links"]
        if feat.get("images_count") is not None:
            nested_data["images_count"] = feat["images_count"]
        if feat.get("iframes") is not None:
            nested_data["iframe_count"] = feat["iframes"]

        # Artifacts (file paths)
        if feat.get("html_path"):
            nested_data["html_path"] = feat["html_path"]
        if feat.get("screenshot_paths"):
            nested_data["screenshot_path"] = feat["screenshot_paths"][0] if isinstance(feat["screenshot_paths"], list) else feat["screenshot_paths"]
        if feat.get("pdf_path"):
            nested_data["pdf_path"] = feat["pdf_path"]

    # Add individual scoring for final domain
    nested_data["individual_score"] = final_score
    nested_data["individual_verdict"] = final_verdict
    nested_data["individual_reasons"] = final_reasons

    return nested_data

# ------------ Output shaping for your ingestor ------------
def make_merged_record(domain: dict, http: dict, feat: dict, scored: dict):
    """
    Produce a compact 'merged' record compatible with apps/chroma-ingestor/ingest.py.
    - Handles cross-domain redirects by nesting final destination data
    - Puts verdict into 'stage' so your ingestor will keep it in metadata.
    - Adds monitoring metadata when applicable.
    - Keeps 'reasons' (already used by ingestor for text+metadata).
    - Carries over common fields when present.
    - Drops heavy blobs.
    """
    verdict = scored["verdict"]
    final_verdict = scored.get("final_verdict", verdict)
    stage = f"rules:monitor" if scored.get("monitor_until") else f"rules:{verdict}"

    # Detect cross-domain redirects
    is_cross_domain, original_domain, final_domain, redirect_chain, cross_domain_hops = \
        extract_cross_domain_redirect_info(http, feat)

    # Normalize original domain for marketplace/parking redirects.
    # If we detect a redirect into marketplace hosts, prefer the canonical seed domain
    # to avoid splitting records under the marketplace hostname.
    try:
        canonical_seed = (scored.get("canonical_fqdn") or "").lower()
        MARKETPLACE_HOST_HINTS = (
            "atom.com",
            "domains.atom.com",
            "img.atom.com",
            "sedo.com",
            "afternic.com",
            "godaddy.com",
            "dan.com",
            "hugedomains.com",
            "bodis.com",
            "undeveloped.com",
            "namesilo.com",
            "namecheap.com",
            "parkingcrew",
            "dnparking",
        )

        def _is_marketplace(host: str) -> bool:
            return bool(host) and any(hint in host.lower() for hint in MARKETPLACE_HOST_HINTS)

        if is_cross_domain and canonical_seed:
            # If original_domain is missing, equals the final domain, or is itself a marketplace host,
            # treat the canonical seed as the true original.
            if (not original_domain) or (original_domain == final_domain) or _is_marketplace(original_domain):
                original_domain = canonical_seed
            # Also, if final domain is marketplace and original doesn't match canonical, snap to canonical
            elif _is_marketplace(final_domain) and original_domain != canonical_seed:
                original_domain = canonical_seed
    except Exception:
        # Best-effort normalization; do not break scoring on errors
        pass

    out = {
        "record_type": "merged",
        "canonical_fqdn": scored["canonical_fqdn"],
        "registrable": scored["registrable"],  # Will be corrected below for cross-domain redirects
        "url": scored["url"] or (http or {}).get("final_url") or (feat or {}).get("url"),
        "reasons": scored["reasons"],
        "stage": stage,
        "score": scored["score"],
        "confidence": scored["confidence"],
        "verdict": verdict,
        "final_verdict": final_verdict,
        "first_seen": datetime.now(timezone.utc).isoformat(),
    }

    # Add monitoring metadata if applicable
    if scored.get("requires_monitoring"):
        out["requires_monitoring"] = True
        if scored.get("monitor_until"):
            out["monitor_until"] = scored["monitor_until"]
        if scored.get("monitor_reason"):
            out["monitor_reason"] = scored["monitor_reason"]

    # Bring common metadata if available
    for src in (domain or {}), (http or {}), (feat or {}):
        for key in ("cse_id","seed_registrable","is_original_seed"):
            if key in src and key not in out:
                out[key] = src[key]

    # === HANDLE CROSS-DOMAIN REDIRECTS ===
    if is_cross_domain:
        # Add redirect tracking metadata
        out["had_cross_domain_redirect"] = True
        out["cross_domain_redirect_count"] = cross_domain_hops
        out["redirect_chain"] = redirect_chain
        out["redirected_to_domain"] = final_domain
        out["original_domain"] = original_domain

        # CRITICAL FIX: Ensure registrable uses ORIGINAL domain, not redirect target
        # This prevents duplicate database entries in chroma-ingestor
        if original_domain:
            out["registrable"] = original_domain

        # Calculate redirect penalty
        redirect_penalty, redirect_reasons = calculate_redirect_penalty(redirect_chain, cross_domain_hops)
        out["redirect_penalty_score"] = redirect_penalty

        # Add redirect reasons to main reasons list
        if redirect_reasons:
            out["reasons"] = out["reasons"] + redirect_reasons if isinstance(out["reasons"], list) else out["reasons"] + "," + ",".join(redirect_reasons)

        # Separate scoring components (for transparency)
        # Original domain score would be from DNS/WHOIS rules
        # Final domain score would be from feature rules
        # For now, we'll estimate:  total_score - redirect_penalty = base_score
        base_score = max(0, out["score"] - redirect_penalty)
        out["original_domain_score"] = base_score // 2  # Rough split
        out["final_domain_score"] = base_score - out["original_domain_score"]

        # Build nested final website data
        # Note: For cross-domain redirects, feat contains data from FINAL domain
        # while domain contains DNS data (which might be from original or final depending on pipeline)
        nested_final_data = build_nested_final_website_data(
            domain=domain,
            http=http,
            feat=feat,
            final_domain=final_domain,
            final_score=out["final_domain_score"],
            final_verdict="benign" if out["final_domain_score"] < THRESH_SUSPICIOUS else "suspicious",
            final_reasons=[r for r in out["reasons"] if "redirect" not in r.lower()] if isinstance(out["reasons"], list) else []
        )
        out["redirected_final_website_data"] = nested_final_data

        # For the main record, keep ORIGINAL domain's DNS/WHOIS
        # (The nested_final_data already has the final domain's data)
        # We should preserve the original domain data at top level

    # DNS/WHOIS from domain (original domain for cross-domain redirects)
    if domain:
        dcopy = dict(domain)
        _drop_heavy(dcopy)
        for k in ("dns","whois","rdap","geoip","a_count","mx_count","ns_count","country","ns_features","ttl_summary"):
            if k in dcopy: out[k] = dcopy[k]

    # TLS/basic HTTP
    if http:
        hcopy = dict(http)
        _drop_heavy(hcopy)
        for k in ("ssl_info","tls","had_redirects","status","server","title","final_url","original_host","host","redirect_count"):
            if k in hcopy: out[k] = hcopy[k]

    # Features (preserve nested structures used by ingestor)
    # For cross-domain redirects, these are from the FINAL domain (already nested above)
    # But we still include them at top level for backward compatibility
    if feat:
        fcopy = dict(feat)
        _drop_heavy(fcopy)
        for k in ("url_features","idn","forms","text_keywords","javascript",
                  "html_size","html_length_bytes","external_links","iframe_count","iframes",
                  "form_count","password_fields","email_fields",
                  "has_credential_form","keyword_count",
                  "suspicious_form_count","has_suspicious_forms",
                  "forms_to_ip","forms_to_suspicious_tld","forms_to_private_ip",
                  "favicon_md5","favicon_sha256","redirect_count","had_redirects",
                  "ocr","image_ocr","image_metadata","favicon_color_scheme",
                  "html_path","screenshot_paths","pdf_path"):
            if k in fcopy: out[k] = fcopy[k]

    return out

# ------------ Worker ------------
def fusion_key(payload: dict):
    fqdn = (payload.get("canonical_fqdn") or payload.get("domain") or payload.get("host") or "").lower()
    url  = (payload.get("final_url") or payload.get("url") or "").lower()
    return fqdn, url

async def main():
    print(f"[scorer] bootstrap={KAFKA_BOOTSTRAP}")
    print(f"[scorer] inputs={INPUT_TOPICS} -> output={OUTPUT_TOPIC}")

    consumer = AIOKafkaConsumer(
        *INPUT_TOPICS,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=GROUP_ID,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda v: v.decode("utf-8") if v else None,
        key_deserializer=lambda v: v.decode("utf-8") if v else None,
    )
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: v.encode("utf-8"),
        key_serializer=lambda v: v.encode("utf-8"),
        linger_ms=25,
    )

    # Optional JSONL mirror
    jsonl_fp = None
    if WRITE_JSONL:
        os.makedirs(OUT_DIR, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        jsonl_fp = open(os.path.join(OUT_DIR, f"rules_verdicts_{ts}.jsonl"), "a", encoding="utf-8")

    await consumer.start(); await producer.start()
    try:
        async for msg in consumer:
            try:
                payload = json.loads(msg.value) if msg.value else {}
            except Exception:
                continue

            _drop_heavy(payload)
            part = "domain" if msg.topic == "domains.resolved" else ("http" if msg.topic == "http.probed" else "features")
            key = fusion_key(payload)
            v = state.upsert(key, part, payload)

            domain  = v["parts"].get("domain")
            http    = v["parts"].get("http")
            feat    = v["parts"].get("features")

            scored = enhanced_score_bundle(domain, http, feat)
            merged = make_merged_record(domain, http, feat, scored)

            # Emit to Kafka (no Chroma upsert here)
            out_key = (merged.get("registrable") or merged.get("canonical_fqdn") or "").lower()
            await producer.send_and_wait(OUTPUT_TOPIC, json.dumps(merged), key=out_key)

            # Log verdicts for debugging (use full FQDN, not registrable)
            verdict = merged.get("verdict", "unknown")
            if verdict in ("parked", "suspicious", "phishing"):
                log_fqdn = merged.get("canonical_fqdn") or merged.get("fqdn") or merged.get("registrable") or "unknown"
                print(f"[scorer] {log_fqdn}: {verdict} (monitoring: {merged.get('requires_monitoring', False)})")

            # Optional JSONL
            if jsonl_fp:
                jsonl_fp.write(json.dumps(merged) + "\n"); jsonl_fp.flush()

            state.gc()
    finally:
        await consumer.stop(); await producer.stop()
        if jsonl_fp: jsonl_fp.close()

if __name__ == "__main__":
    asyncio.run(main())
