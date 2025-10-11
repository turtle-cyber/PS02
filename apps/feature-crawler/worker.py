#!/usr/bin/env python3
"""
apps/feature-crawler/worker.py

Consumes URLs from Kafka (IN_TOPIC), crawls them with Playwright,
extracts artifacts (HTML, screenshots, PDF) and page features,
publishes results to Kafka (OUT_TOPIC_RAW, OUT_TOPIC_FEAT),
and also appends JSONL locally under OUT_DIR:
  - {OUT_DIR}/http_crawled.jsonl
  - {OUT_DIR}/features_page.jsonl

This file only ADDS local file writes; core behavior is unchanged.
"""
import os, sys, time, json, ujson, math, re, traceback, hashlib
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, urlsplit
from typing import Dict, Any, List, Optional

import logging
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL","INFO"),
    format="%(asctime)s | %(levelname)s | %(message)s",
)
log = logging.getLogger(__name__)

# Kafka
from kafka import KafkaConsumer, KafkaProducer, TopicPartition

# HTML parsing
from bs4 import BeautifulSoup

# Playwright
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

# --------------- Env -----------------
BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP") or os.environ.get("KAFKA_BROKERS","kafka:9092")
IN_TOPIC = os.environ.get("IN_TOPIC","phish.urls.crawl")
OUT_TOPIC_RAW = os.environ.get("OUT_TOPIC_RAW","phish.http.crawled")
OUT_TOPIC_FEAT = os.environ.get("OUT_TOPIC_FEAT","phish.features.page")
GROUP_ID = os.environ.get("GROUP_ID","feature-crawler")
AUTO_OFFSET_RESET = os.environ.get("AUTO_OFFSET_RESET","earliest")
OUT_DIR = Path(os.environ.get("OUT_DIR","/workspace/out"))
HEADLESS = (os.environ.get("PLAYWRIGHT_HEADLESS","1") != "0")
NAV_TIMEOUT_MS = int(os.environ.get("NAV_TIMEOUT_MS","15000"))

OUT_DIR.mkdir(parents=True, exist_ok=True)
(OUT_DIR/"html").mkdir(exist_ok=True, parents=True)
(OUT_DIR/"screenshots").mkdir(exist_ok=True, parents=True)
(OUT_DIR/"pdfs").mkdir(exist_ok=True, parents=True)

HTTP_JSONL = OUT_DIR/"http_crawled.jsonl"
FEAT_JSONL = OUT_DIR/"features_page.jsonl"

# --------------- helpers -----------------
def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def safe_write_jsonl(path: Path, record: Dict[str,Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    line = ujson.dumps(record, ensure_ascii=False) + "\n"
    with open(tmp, "ab") as f:
        f.write(line.encode("utf-8"))
    os.replace(tmp, path)

def entropy(s: str) -> float:
    if not s:
        return 0.0
    import collections, math
    p, lns = collections.Counter(s), float(len(s))
    return -sum( count/lns * math.log2(count/lns) for count in p.values() )

SPECIALS = set("@&%$!#?=._-/")

def url_struct_features(url: str) -> Dict[str, Any]:
    parts = urlsplit(url)
    full = url
    domain = parts.hostname or ""
    path = parts.path or "/"
    q = parts.query or ""
    frag = parts.fragment or ""
    # counts
    def count_chars(s, chars): return sum(1 for ch in s if ch in chars)
    return {
        "url_length": len(full),
        "num_dots": full.count("."),
        "has_repeated_digits": bool(re.search(r"(\d)\1{1,}", full)),
        "num_special_chars": count_chars(full, set("@&%$!#?=_%")),  # conservative
        "num_hyphens": full.count("-"),
        "num_slashes": full.count("/"),
        "num_underscores": full.count("_"),
        "num_question_marks": full.count("?"),
        "num_equal_signs": full.count("="),
        "num_dollar_signs": full.count("$"),
        "num_exclamation_marks": full.count("!"),
        "num_hashtags": full.count("#"),
        "num_percent_signs": full.count("%"),
        "domain_length": len(domain),
        "domain_hyphens": domain.count("-"),
        "domain_has_special_chars": any(c in SPECIALS for c in domain),
        "domain_num_special_chars": count_chars(domain, SPECIALS),
        "url_entropy": round(entropy(full), 4),
        "domain_entropy": round(entropy(domain), 4),
        # subdomain analysis
        "num_subdomains": max(0, domain.count(".") - 1) if domain else 0,
        "avg_subdomain_length": (
            (sum(len(x) for x in domain.split(".")[:-2]) / max(1, len(domain.split(".")[:-2])))
            if domain and domain.count(".") >= 2 else 0.0
        ),
        "subdomain_entropy": (
            round(entropy("".join(domain.split(".")[:-2])), 4)
            if domain and domain.count(".") >= 2 else 0.0
        ),
        "subdomain_num_special_chars": count_chars("".join(domain.split(".")[:-2]), SPECIALS) if domain and domain.count(".") >= 2 else 0,
        "subdomain_has_hyphen": "-" in ("".join(domain.split(".")[:-2])) if domain and domain.count(".") >= 2 else False,
        "subdomain_has_repeated_digits": bool(re.search(r"(\d)\1{1,}", "".join(domain.split(".")[:-2]))) if domain and domain.count(".") >= 2 else False,
        # path analysis
        "path_length": len(path or "/"),
        "path_has_query": bool(q),
        "path_has_fragment": bool(frag),
        "url_has_anchor": "#" in full,
    }

def idn_features(host: str) -> Dict[str,Any]:
    is_idn = False
    puny = host or ""
    mixed = False
    confusable = 0
    try:
        import idna
        # if host contains non-ascii, idna will encode/decode
        enc = idna.encode(host).decode("ascii") if host else ""
        dec = idna.decode(enc) if enc else host
        puny = enc or host
        is_idn = any(ord(c) > 127 for c in host) if host else False
        # naive mixed script check
        scripts = set("latin" if ord(c) < 128 else "nonlatin" for c in host)
        mixed = len(scripts) > 1
        # confusable: count of non-ascii
        confusable = sum(1 for c in host if ord(c) > 127)
    except Exception:
        pass
    return {
        "is_idn": is_idn,
        "punycode": puny or host,
        "mixed_script": mixed,
        "confusable_count": confusable,
    }

def fetch_and_hash_favicon(page, base_url: str) -> Dict[str, Any]:
    """
    Download favicon using Playwright and compute hash.
    This allows brand impersonation detection.
    """
    result = {
        "favicon_url": None,
        "favicon_md5": None,
        "favicon_sha256": None,
        "favicon_size": None,
        "favicon_present": False,
        "favicon_error": None
    }

    try:
        # Try to find favicon URL from HTML
        favicon_urls = []

        # Check link tags
        links = page.query_selector_all("link[rel*='icon']")
        for link in links:
            href = link.get_attribute("href")
            if href:
                favicon_urls.append(href)

        # Fallback to /favicon.ico
        if not favicon_urls:
            favicon_urls = ["/favicon.ico"]

        # Try each favicon URL until one works
        for fav_url in favicon_urls:
            try:
                # Make absolute URL
                from urllib.parse import urljoin
                full_url = urljoin(base_url, fav_url)
                result["favicon_url"] = full_url

                # Fetch favicon using Playwright's network capabilities
                response = page.evaluate("""
                    async (url) => {
                        try {
                            const resp = await fetch(url);
                            if (!resp.ok) return null;
                            const blob = await resp.blob();
                            const buffer = await blob.arrayBuffer();
                            const bytes = Array.from(new Uint8Array(buffer));
                            return bytes;
                        } catch {
                            return null;
                        }
                    }
                """, full_url)

                if response and isinstance(response, list):
                    # Convert to bytes
                    favicon_bytes = bytes(response)
                    result["favicon_size"] = len(favicon_bytes)
                    result["favicon_present"] = True

                    # Compute hashes for brand matching
                    result["favicon_md5"] = hashlib.md5(favicon_bytes).hexdigest()
                    result["favicon_sha256"] = hashlib.sha256(favicon_bytes).hexdigest()

                    log.debug(f"[favicon] Downloaded and hashed: {full_url} (size={len(favicon_bytes)})")
                    break  # Success, stop trying

            except Exception as e:
                log.debug(f"[favicon] Failed to fetch {fav_url}: {e}")
                continue

    except Exception as e:
        result["favicon_error"] = str(e)
        log.debug(f"[favicon] Error: {e}")

    return result

def analyze_javascript(soup, base_url: str, base_host: str) -> Dict[str, Any]:
    """
    Analyze JavaScript for suspicious patterns:
    - Obfuscation (eval, atob, fromCharCode)
    - Redirects (window.location manipulation)
    - Form manipulation (changing action dynamically)
    - Keyloggers (addEventListener on keypress/keydown)
    - External form submissions
    """
    result = {
        "inline_scripts": 0,
        "external_scripts": 0,
        "obfuscated_scripts": 0,
        "redirect_scripts": 0,
        "form_manipulation": 0,
        "keylogger_patterns": 0,
        "external_form_submissions": [],
        "suspicious_patterns": [],
        "base64_decoding": 0,
        "eval_usage": 0
    }

    for script in soup.find_all("script"):
        if script.get("src"):
            result["external_scripts"] += 1
            continue

        result["inline_scripts"] += 1
        code = script.string or ""

        if not code:
            continue

        # Detect obfuscation techniques
        if re.search(r"eval\s*\(", code, re.IGNORECASE):
            result["obfuscated_scripts"] += 1
            result["eval_usage"] += 1
            result["suspicious_patterns"].append("eval_usage")

        if re.search(r"atob\s*\(", code, re.IGNORECASE):
            result["obfuscated_scripts"] += 1
            result["base64_decoding"] += 1
            result["suspicious_patterns"].append("base64_decoding")

        if re.search(r"fromCharCode|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", code):
            result["obfuscated_scripts"] += 1
            result["suspicious_patterns"].append("char_encoding")

        # Detect heavily obfuscated code (long strings, minimal whitespace)
        if len(code) > 1000:
            # Check for suspiciously low whitespace ratio
            whitespace_ratio = len(re.findall(r"\s", code)) / len(code)
            if whitespace_ratio < 0.05:  # Less than 5% whitespace
                result["obfuscated_scripts"] += 1
                result["suspicious_patterns"].append("minified_obfuscated")

        # Detect redirects
        redirect_patterns = [
            r"window\.location\s*=",
            r"window\.location\.href\s*=",
            r"window\.location\.replace\s*\(",
            r"document\.location\s*=",
            r"location\.href\s*=",
            r"location\.replace\s*\("
        ]
        for pattern in redirect_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                result["redirect_scripts"] += 1
                result["suspicious_patterns"].append("js_redirect")
                break

        # Detect form manipulation
        form_manip_patterns = [
            r"\.action\s*=",
            r"\.submit\s*\(",
            r"setAttribute\s*\(\s*['\"]action['\"]"
        ]
        for pattern in form_manip_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                result["form_manipulation"] += 1
                result["suspicious_patterns"].append("form_manipulation")
                break

        # Detect keyloggers
        keylogger_patterns = [
            r"addEventListener\s*\(\s*['\"]keypress['\"]",
            r"addEventListener\s*\(\s*['\"]keydown['\"]",
            r"addEventListener\s*\(\s*['\"]keyup['\"]",
            r"onkeypress\s*=",
            r"onkeydown\s*=",
            r"\.keyCode",
            r"\.key\s*=="
        ]
        keylogger_count = sum(1 for pattern in keylogger_patterns if re.search(pattern, code, re.IGNORECASE))
        if keylogger_count >= 2:  # At least 2 patterns = likely keylogger
            result["keylogger_patterns"] += 1
            result["suspicious_patterns"].append("keylogger")

        # Extract external form submission URLs (from JS)
        # Look for patterns like: action='http://evil.com' or .action = "http://..."
        action_matches = re.findall(r"action\s*[=:]\s*['\"]([^'\"]+)['\"]", code, re.IGNORECASE)
        for url in action_matches:
            if "://" in url:
                action_host = urlsplit(url).hostname or ""
                if action_host and action_host != base_host:
                    result["external_form_submissions"].append(url)

    # Deduplicate suspicious patterns
    result["suspicious_patterns"] = list(set(result["suspicious_patterns"]))

    # Calculate risk score
    risk_score = 0
    if result["eval_usage"] > 0:
        risk_score += 15
    if result["base64_decoding"] > 0:
        risk_score += 10
    if result["keylogger_patterns"] > 0:
        risk_score += 25
    if result["form_manipulation"] > 0:
        risk_score += 10
    if result["obfuscated_scripts"] >= 3:
        risk_score += 20

    result["js_risk_score"] = min(risk_score, 100)

    return result

def extract_html_features(html: str, base_url: str, favicon_data: Dict = None) -> Dict[str,Any]:
    soup = BeautifulSoup(html or "", "html.parser")
    # links
    links = [a.get("href","") for a in soup.find_all("a")]
    internal, external = 0, 0
    base_host = urlsplit(base_url).hostname or ""
    for href in links:
        if not href:
            continue
        if href.startswith("#"):
            internal += 1
            continue
        if href.startswith("/") or (urlsplit(href).hostname or "") == base_host:
            internal += 1
        else:
            external += 1
    # forms with enhanced analysis
    forms = soup.find_all("form")
    form_actions = []
    pw_fields = 0
    email_fields = 0
    submit_texts = []
    suspicious_form_count = 0

    # Suspicious TLDs commonly used in phishing
    SUSPICIOUS_TLDS = [
        ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs
        ".xyz", ".top", ".work", ".click", ".link",  # Cheap/abused TLDs
        ".zip", ".icu", ".loan", ".download", ".racing"
    ]

    for f in forms:
        act = f.get("action") or base_url
        action_host = urlsplit(act).hostname or ""

        # Enhanced action analysis
        is_cross_domain = action_host not in ("", base_host)

        # Check if submitting to IP address (major red flag)
        is_ip_address = bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", action_host)) if action_host else False

        # Check if submitting to suspicious TLD
        is_suspicious_tld = any(action_host.endswith(tld) for tld in SUSPICIOUS_TLDS) if action_host else False

        # Check for localhost/private IPs (testing artifacts or malicious)
        is_localhost = action_host in ("localhost", "127.0.0.1", "0.0.0.0") if action_host else False
        is_private_ip = False
        if action_host and re.match(r"^\d", action_host):
            # Check for private IP ranges
            parts = action_host.split(".")
            if len(parts) == 4:
                try:
                    first = int(parts[0])
                    second = int(parts[1])
                    # 10.x.x.x, 192.168.x.x, 172.16-31.x.x
                    is_private_ip = (first == 10) or (first == 192 and second == 168) or (first == 172 and 16 <= second <= 31)
                except:
                    pass

        # Track suspicious forms
        if is_ip_address or is_suspicious_tld or is_localhost or is_private_ip:
            suspicious_form_count += 1

        form_actions.append({
            "url": act,
            "cross_domain": is_cross_domain,
            "action_host": action_host,
            "is_ip_address": is_ip_address,
            "is_suspicious_tld": is_suspicious_tld,
            "is_localhost": is_localhost,
            "is_private_ip": is_private_ip
        })

        # inputs
        for inp in f.find_all(["input","textarea","button","select"]):
            t = (inp.get("type") or "").lower()
            if t == "password":
                pw_fields += 1
            if t in ("email","text","username","tel","number"):
                if t == "email":
                    email_fields += 1
        # submit text
        sub = f.find("button", {"type":"submit"})
        if sub and sub.get_text(strip=True):
            submit_texts.append(sub.get_text(strip=True))
    # iframes, scripts, styles
    iframes = len(soup.find_all("iframe"))
    extern_scripts = sum(1 for s in soup.find_all("script") if s.get("src"))
    extern_styles = sum(1 for l in soup.find_all("link") if (l.get("rel") and "stylesheet" in [r.lower() for r in l.get("rel")]) and l.get("href"))

    # JavaScript analysis - detect suspicious patterns
    js_analysis = analyze_javascript(soup, base_url, base_host)

    # Use pre-fetched favicon data if available
    if favicon_data:
        fav_present = favicon_data.get("favicon_present", False)
        favicon_url = favicon_data.get("favicon_url")
        favicon_md5 = favicon_data.get("favicon_md5")
        favicon_sha256 = favicon_data.get("favicon_sha256")
        favicon_size = favicon_data.get("favicon_size")
    else:
        # Fallback to basic detection
        favicon_url = None
        for l in soup.find_all("link"):
            rels = [r.lower() for r in (l.get("rel") or [])]
            if any(r in ("icon","shortcut icon","mask-icon","apple-touch-icon") for r in rels):
                href = l.get("href")
                if href:
                    favicon_url = href
                    break
        fav_present = bool(favicon_url)
        favicon_md5 = None
        favicon_sha256 = None
        favicon_size = None

    # images
    imgs = soup.find_all("img")
    images_count = len(imgs)

    return {
        "favicon_present": fav_present,
        "favicon_url": favicon_url,
        "favicon_md5": favicon_md5,
        "favicon_sha256": favicon_sha256,
        "favicon_size": favicon_size,
        "images_count": images_count,
        "html_length_bytes": len(html.encode("utf-8")) if html else 0,
        "external_links": external,
        "internal_links": internal,
        "forms": {
            "count": len(forms),
            "password_fields": pw_fields,
            "email_fields": email_fields,
            "submit_texts": submit_texts[:10] if submit_texts else [],
            "actions": form_actions[:10] if form_actions else [],
            "suspicious_form_count": suspicious_form_count,
        },
        "iframes": iframes,
        "external_scripts": extern_scripts,
        "external_stylesheets": extern_styles,
        "javascript": js_analysis,
    }

def pick_url(rec: Dict[str,Any]) -> str:
    return rec.get("url") or rec.get("final_url") or rec.get("final",{}).get("url") or rec.get("input_url") or rec.get("href") or ""

# --------------- crawler -----------------
def crawl_once(play, url: str) -> Dict[str,Any]:
    """
    Crawl URL with proper redirect tracking.
    Waits for final destination before extracting features.
    """
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    t0 = time.time()

    browser = None
    ctx = None
    page = None

    try:
        # Track redirects
        redirect_chain = []
        response_status = None

        browser = play.chromium.launch(headless=HEADLESS, args=["--no-sandbox"])
        ctx = browser.new_context(ignore_https_errors=True, java_script_enabled=True)
        page = ctx.new_page()
        page.set_default_navigation_timeout(NAV_TIMEOUT_MS)
        page.set_default_timeout(NAV_TIMEOUT_MS)

        # Set up redirect tracking
        def handle_response(response):
            nonlocal response_status
            # Track all responses in the chain
            redirect_chain.append({
                "url": response.url,
                "status": response.status,
                "headers": dict(response.headers) if response.headers else {}
            })
            # Keep the last status
            response_status = response.status

        page.on("response", handle_response)

        # Navigate and wait for network to be idle (all redirects complete)
        log.info(f"[crawl] Navigating to {url}")
        response = page.goto(url, wait_until="networkidle")

        # Get final URL after all redirects
        final_url = page.url

        # Log redirect chain
        if len(redirect_chain) > 1:
            log.info(f"[redirects] {url} -> {final_url} ({len(redirect_chain)} hops)")
            for i, hop in enumerate(redirect_chain):
                log.debug(f"  [{i+1}] {hop['status']} {hop['url']}")

        # Wait a bit more for JavaScript redirects and dynamic content
        try:
            page.wait_for_load_state("networkidle", timeout=3000)
            # Check if URL changed (JS redirect)
            if page.url != final_url:
                log.info(f"[js-redirect] {final_url} -> {page.url}")
                redirect_chain.append({
                    "url": page.url,
                    "status": "JS_REDIRECT",
                    "headers": {}
                })
                final_url = page.url
        except Exception:
            pass  # Timeout on wait is OK

        # NOW extract features from the final page
        title = page.title()
        status = response_status or 200

        # Use final URL hash for file names
        h = hashlib.sha256(final_url.encode("utf-8")).hexdigest()
        html_path = OUT_DIR/"html"/f"{h}.html"
        shot_path = OUT_DIR/"screenshots"/f"{h}_full.png"
        pdf_path = OUT_DIR/"pdfs"/f"page_{ts}.pdf"

        # Save HTML from final page
        html = page.content()
        html_path.write_text(html, encoding="utf-8")

        # Screenshot final page
        page.screenshot(path=str(shot_path), full_page=True)

        favicon_data = fetch_and_hash_favicon(page, final_url)

        # PDF from final page (Chromium only)
        try:
            page.pdf(path=str(pdf_path), format="A4", print_background=True)
        except Exception:
            pdf_path = None

        latency_ms = int((time.time() - t0) * 1000)

        # Extract redirect summary
        redirect_summary = {
            "redirect_count": len(redirect_chain) - 1,  # Exclude initial request
            "redirect_chain": [hop["url"] for hop in redirect_chain],
            "redirect_statuses": [hop["status"] for hop in redirect_chain],
            "had_redirects": len(redirect_chain) > 1
        }

        return {
            "schema_version":"v1",
            "event_time": utcnow(),
            "url": url,
            "final_url": final_url,
            "status": status,
            "title": title,
            "html_path": str(html_path),
            "screenshot_paths": [str(shot_path)],
            "pdf_path": str(pdf_path) if pdf_path else None,
            "latency_ms": latency_ms,
            "redirects": redirect_summary,
            "favicon": favicon_data,
        }

    finally:
        # Always clean up browser resources
        if page:
            try: page.close()
            except: pass
        if ctx:
            try: ctx.close()
            except: pass
        if browser:
            try: browser.close()
            except: pass

def build_features(url: str, html_path: Path, artifacts: Dict[str,Any], registrable: Optional[str], cse_id: Optional[str]) -> Dict[str,Any]:
    html = ""
    try:
        html = Path(html_path).read_text(encoding="utf-8")
    except Exception:
        pass
    ufeat = url_struct_features(url)
    idnf = idn_features(urlsplit(url).hostname or "")

    # Pass favicon data to HTML feature extraction
    favicon_data = artifacts.get("favicon")
    htmlf = extract_html_features(html, url, favicon_data)

    # quick keywords
    keywords = []
    txt = BeautifulSoup(html, "html.parser").get_text(" ", strip=True) if html else ""
    for kw in ["password","account","login","secure","verify","suspended","urgent"]:
        if kw in txt.lower():
            keywords.append(kw)
    # OCR placeholder
    ocr_excerpt = None

    # Extract redirect information
    redirects = artifacts.get("redirects", {})

    return {
        "url": url,
        "registrable": registrable,
        "cse_id": cse_id,
        "pdf_path": artifacts.get("pdf_path"),
        "url_features": ufeat,
        "idn": idnf,
        "forms": htmlf.get("forms",{}),
        "text_keywords": keywords,
        "favicon_present": htmlf.get("favicon_present", False),
        "favicon_url": htmlf.get("favicon_url"),
        "favicon_md5": htmlf.get("favicon_md5"),
        "favicon_sha256": htmlf.get("favicon_sha256"),
        "images_count": htmlf.get("images_count", 0),
        "visual_logo_detected": False,
        "ocr_excerpt": ocr_excerpt,
        "html_length_bytes": htmlf.get("html_length_bytes", 0),
        "external_links": htmlf.get("external_links", 0),
        "internal_links": htmlf.get("internal_links", 0),
        "iframes": htmlf.get("iframes", 0),
        "external_scripts": htmlf.get("external_scripts", 0),
        "external_stylesheets": htmlf.get("external_stylesheets", 0),
        "redirect_count": redirects.get("redirect_count", 0),
        "redirect_chain": redirects.get("redirect_chain", []),
        "had_redirects": redirects.get("had_redirects", False),
    }

# --------------- main -----------------
def main():
    log.info("[feature-crawler] listening on %s → (%s, %s)", IN_TOPIC, OUT_TOPIC_RAW, OUT_TOPIC_FEAT)

    # Retry configuration
    MAX_RETRIES = int(os.environ.get("MAX_RETRIES", "3"))
    retry_tracker = {}  # {url: attempt_count}

    consumer = KafkaConsumer(
        IN_TOPIC,
        bootstrap_servers=BOOTSTRAP,
        group_id=GROUP_ID,
        enable_auto_commit=False,
        auto_offset_reset=AUTO_OFFSET_RESET,
        value_deserializer=lambda v: ujson.loads(v.decode("utf-8")),
        key_deserializer=lambda v: v.decode("utf-8") if v else None,
        consumer_timeout_ms=1000,
        max_poll_records=50,
    )
    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP,
        value_serializer=lambda v: ujson.dumps(v, ensure_ascii=False).encode("utf-8"),
        key_serializer=lambda v: v.encode("utf-8") if isinstance(v,str) else v,
        linger_ms=5,
        acks=1,
    )

    # Stats tracking
    total_processed = 0
    total_failed = 0
    total_retried = 0

    # Playwright driver
    with sync_playwright() as p:
        while True:
            polled = consumer.poll(timeout_ms=500)
            if not polled:
                time.sleep(0.25)
                continue

            for tp, msgs in polled.items():
                for m in msgs:
                    try:
                        rec = m.value if isinstance(m.value, dict) else {}
                        url = pick_url(rec)
                        if not url:
                            log.warning("[skip] no url in record keys=%s", list(rec.keys()))
                            consumer.commit()
                            continue

                        registrable = rec.get("registrable") or None
                        cse_id = rec.get("cse_id") or rec.get("cse") or None

                        # Track retry attempts
                        attempt = retry_tracker.get(url, 0) + 1
                        retry_tracker[url] = attempt

                        # Crawl
                        log.info(f"[crawl] attempt {attempt}/{MAX_RETRIES} for {url}")
                        art = crawl_once(p, url)
                        log.info("[ok] crawled %s -> %s (status=%s, ms=%s, redirects=%s)",
                                url, art.get("final_url"), art.get("status"),
                                art.get("latency_ms"), art.get("redirects", {}).get("redirect_count", 0))

                        # Features
                        feat = build_features(art.get("final_url"), Path(art["html_path"]), art, registrable, cse_id)

                        # ---- Kafka publish ----
                        producer.send(OUT_TOPIC_RAW, value=art, key=url.encode("utf-8"))
                        producer.send(OUT_TOPIC_FEAT, value=feat, key=url.encode("utf-8"))
                        producer.flush()

                        # ---- Local JSONL writes ----
                        safe_write_jsonl(HTTP_JSONL, art)
                        safe_write_jsonl(FEAT_JSONL, feat)

                        # Success - commit offset and clear retry tracker
                        consumer.commit()
                        if url in retry_tracker:
                            del retry_tracker[url]
                        total_processed += 1

                        # Log stats periodically
                        if total_processed % 10 == 0:
                            log.info(f"[stats] processed={total_processed}, failed={total_failed}, retried={total_retried}")

                    except PlaywrightTimeout as e:
                        url = pick_url(rec)
                        attempt = retry_tracker.get(url, 1)

                        if attempt < MAX_RETRIES:
                            log.warning(f"[retry] {url} timed out (attempt {attempt}/{MAX_RETRIES}), will retry")
                            total_retried += 1
                            # DON'T commit - message will be reprocessed
                            continue
                        else:
                            log.error(f"[failed] {url} exceeded retries after {attempt} attempts (timeout)")
                            total_failed += 1
                            # Send to dead letter queue topic
                            try:
                                failed_rec = dict(rec)
                                failed_rec["failure_reason"] = "timeout"
                                failed_rec["attempts"] = attempt
                                producer.send("phish.urls.failed", value=failed_rec, key=url.encode("utf-8"))
                            except Exception:
                                pass
                            # Commit to skip this message
                            consumer.commit()
                            if url in retry_tracker:
                                del retry_tracker[url]
                            continue

                    except Exception as e:
                        url = pick_url(rec)
                        attempt = retry_tracker.get(url, 1)
                        error_type = type(e).__name__

                        if attempt < MAX_RETRIES:
                            log.warning(f"[retry] {url} failed with {error_type} (attempt {attempt}/{MAX_RETRIES}), will retry")
                            log.debug(f"[retry-error] {e}")
                            total_retried += 1
                            # DON'T commit - message will be reprocessed
                            continue
                        else:
                            log.error(f"[failed] {url} exceeded retries after {attempt} attempts: {error_type}")
                            traceback.print_exc()
                            total_failed += 1
                            # Send to dead letter queue
                            try:
                                failed_rec = dict(rec)
                                failed_rec["failure_reason"] = str(e)
                                failed_rec["failure_type"] = error_type
                                failed_rec["attempts"] = attempt
                                producer.send("phish.urls.failed", value=failed_rec, key=url.encode("utf-8"))
                            except Exception:
                                pass
                            # Commit to skip this message
                            consumer.commit()
                            if url in retry_tracker:
                                del retry_tracker[url]
                            continue

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.info("interrupted")
    except Exception as e:
        log.error("fatal: %s", e)
        traceback.print_exc()
