#!/usr/bin/env python3
"""
IC-05 HTTP Fetcher/Crawler (Enhanced)
Now includes: parked domain detection, phishing indicators, SSL info
"""

import os, re, asyncio, time, socket, sys, ssl
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

import ujson
import httpx
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from selectolax.parser import HTMLParser
import tldextract

# ---------- env ----------
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")
INPUT_TOPIC     = os.getenv("INPUT_TOPIC", "domains.resolved")
OUTPUT_TOPIC    = os.getenv("OUTPUT_TOPIC", "http.probed")

OUTPUT_DIR      = Path(os.getenv("OUTPUT_DIR", "/out"))
CONCURRENCY     = int(os.getenv("CONCURRENCY", "20"))
USER_AGENT      = os.getenv("USER_AGENT", "IC05-Prober/1.0 (+https://example)")
TIMEOUT_CONN_S  = float(os.getenv("TIMEOUT_CONN_S", "4.0"))
TIMEOUT_READ_S  = float(os.getenv("TIMEOUT_READ_S", "6.0"))
MAX_BODY_BYTES  = int(os.getenv("MAX_BODY_BYTES", "200000"))
MAX_REDIRECTS   = int(os.getenv("MAX_REDIRECTS", "5"))
FALLBACK_RESOLVE= os.getenv("FALLBACK_RESOLVE", "false").lower()=="true"

extract = tldextract.TLDExtract(suffix_list_urls=None)

# Tunneling/Hosting service patterns (high risk for phishing)
TUNNELING_SERVICES = {
    # Tunneling services (very high risk)
    "ngrok": {"patterns": [r"ngrok\.io$", r"ngrok-free\.app$"], "risk": "critical", "type": "tunnel"},
    "localtunnel": {"patterns": [r"loca\.lt$", r"localtunnel\.me$"], "risk": "critical", "type": "tunnel"},
    "serveo": {"patterns": [r"serveo\.net$"], "risk": "critical", "type": "tunnel"},
    "localhost.run": {"patterns": [r"localhost\.run$"], "risk": "critical", "type": "tunnel"},
    "pagekite": {"patterns": [r"pagekite\.me$"], "risk": "critical", "type": "tunnel"},
    
    # Serverless/Edge platforms (high risk - easy abuse)
    "vercel": {"patterns": [r"vercel\.app$", r"vercel\.dev$", r"now\.sh$"], "risk": "high", "type": "serverless"},
    "netlify": {"patterns": [r"netlify\.app$", r"netlify\.com$"], "risk": "high", "type": "serverless"},
    "render": {"patterns": [r"render\.com$", r"onrender\.com$"], "risk": "high", "type": "serverless"},
    "railway": {"patterns": [r"railway\.app$", r"up\.railway\.app$"], "risk": "high", "type": "serverless"},
    "fly.io": {"patterns": [r"fly\.dev$", r"fly\.io$"], "risk": "high", "type": "serverless"},
    "heroku": {"patterns": [r"herokuapp\.com$"], "risk": "medium", "type": "paas"},
    "replit": {"patterns": [r"repl\.co$", r"replit\.dev$", r"replit\.app$"], "risk": "high", "type": "ide"},
    "glitch": {"patterns": [r"glitch\.me$"], "risk": "medium", "type": "ide"},
    
    # Cloud platforms (medium risk)
    "cloudflare-pages": {"patterns": [r"pages\.dev$"], "risk": "medium", "type": "edge"},
    "github-pages": {"patterns": [r"github\.io$"], "risk": "low", "type": "static"},
    "gitlab-pages": {"patterns": [r"gitlab\.io$"], "risk": "low", "type": "static"},
    "surge": {"patterns": [r"surge\.sh$"], "risk": "medium", "type": "static"},
    "firebase": {"patterns": [r"firebaseapp\.com$", r"web\.app$"], "risk": "medium", "type": "hosting"},
    
    # URL shorteners / redirectors (high risk)
    "bitly": {"patterns": [r"bit\.ly$", r"bitly\.com$"], "risk": "high", "type": "shortener"},
    "tinyurl": {"patterns": [r"tinyurl\.com$"], "risk": "high", "type": "shortener"},
    "rebrandly": {"patterns": [r"rebrandly\.com$", r"link\..*$"], "risk": "high", "type": "shortener"},
    
    # Website builders (medium risk)
    "wix": {"patterns": [r"wixsite\.com$", r"wix\.com$"], "risk": "medium", "type": "builder"},
    "weebly": {"patterns": [r"weebly\.com$"], "risk": "medium", "type": "builder"},
    "wordpress-com": {"patterns": [r"wordpress\.com$"], "risk": "low", "type": "builder"},
    "webflow": {"patterns": [r"webflow\.io$"], "risk": "low", "type": "builder"},
    
    # Free hosting (high risk)
    "infinityfree": {"patterns": [r"infinityfreeapp\.com$"], "risk": "high", "type": "free-hosting"},
    "000webhost": {"patterns": [r"000webhostapp\.com$"], "risk": "high", "type": "free-hosting"},
}

# Parking page indicators
PARKING_PATTERNS = [
    r"parked\s+domain",
    r"domain\s+for\s+sale",
    r"buy\s+this\s+domain",
    r"domain\s+is\s+available",
    r"domain\s+parking",
    r"expired\s+domain",
    r"godaddy\.com.*parking",
    r"sedo\.com",
    r"afternic\.com",
    r"namecheap.*parking",
    r"this\s+domain\s+may\s+be\s+for\s+sale",
    r"future\s+home\s+of",
    r"coming\s+soon",
    r"under\s+construction",
    r"domain\s+name\s+is\s+registered",
]

PHISHING_INDICATORS = [
    r"verify\s+your\s+account",
    r"suspended\s+account",
    r"unusual\s+activity",
    r"confirm\s+your\s+identity",
    r"security\s+alert",
    r"action\s+required",
    r"click\s+here\s+to\s+verify",
    r"update\s+payment\s+method",
    r"account\s+will\s+be\s+closed",
]

# ---------- helpers ----------
def now_iso():
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def registrable(host: str) -> str:
    t = extract(host or "")
    return f"{t.domain}.{t.suffix}" if t.suffix else t.domain

def is_parked(html: str, title: str, url: str) -> Dict[str, Any]:
    """
    Detect if domain is parked/for-sale/placeholder
    Returns: {is_parked: bool, confidence: str, indicators: []}
    """
    indicators = []
    text = (html or "").lower()
    title_lower = (title or "").lower()
    url_lower = url.lower()
    
    # Check patterns
    for pattern in PARKING_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE) or re.search(pattern, title_lower, re.IGNORECASE):
            indicators.append(f"pattern:{pattern[:30]}")
    
    # Check URL redirects to parking services
    parking_domains = ["sedo.com", "godaddy.com", "afternic.com", "parkingcrew", "sedoparking"]
    for pd in parking_domains:
        if pd in url_lower:
            indicators.append(f"redirect_to:{pd}")
    
    # Check for minimal content (often parking pages)
    if html and len(html) < 5000 and "domain" in text:
        if any(word in text for word in ["buy", "sale", "available", "register"]):
            indicators.append("minimal_content_with_sale_keywords")
    
    # Hostinger, GoDaddy specific parking
    if "hostinger" in text and "parked" in text:
        indicators.append("hostinger_parking")
    if "godaddy" in text and "parked" in text:
        indicators.append("godaddy_parking")
    
    confidence = "high" if len(indicators) >= 2 else ("medium" if len(indicators) == 1 else "none")
    
    return {
        "is_parked": len(indicators) > 0,
        "confidence": confidence,
        "indicators": indicators[:5]  # limit to 5
    }

def detect_phishing_signals(html: str, title: str, url: str, original_domain: str) -> Dict[str, Any]:
    """
    Detect potential phishing indicators
    Returns: {risk_score: int, signals: []}
    """
    signals = []
    score = 0
    text = (html or "").lower()
    title_lower = (title or "").lower()
    
    # Phishing language patterns
    for pattern in PHISHING_INDICATORS:
        if re.search(pattern, text, re.IGNORECASE):
            signals.append(f"phish_lang:{pattern[:30]}")
            score += 10
    
    # Check for brand impersonation in title
    major_brands = ["bank", "paypal", "amazon", "microsoft", "apple", "google", "facebook"]
    for brand in major_brands:
        if brand in title_lower and brand not in original_domain:
            signals.append(f"brand_impersonation:{brand}")
            score += 15
    
    # Suspicious redirects (many hops)
    # (we'll pass redirect_count from caller)
    
    # Login forms with suspicious domains
    if re.search(r"<input[^>]*type=[\"']password[\"']", html or "", re.IGNORECASE):
        signals.append("password_input_found")
        score += 5
    
    # Misleading domain in title
    if title and any(tld in title_lower for tld in [".com", ".net", ".org"]):
        signals.append("domain_in_title")
        score += 5
    
    return {
        "risk_score": min(score, 100),
        "signals": signals[:10]
    }

def extract_ssl_info(response: httpx.Response) -> Optional[Dict[str, Any]]:
    """
    Extract detailed SSL certificate information if HTTPS.
    Critical for phishing detection - self-signed certs are a major indicator.
    """
    import ssl
    import socket
    from datetime import datetime
    from urllib.parse import urlparse

    url = str(response.url)

    if not url.startswith("https://"):
        return {
            "uses_https": False,
            "scheme": "http"
        }

    ssl_info = {
        "uses_https": True,
        "scheme": "https"
    }

    try:
        hostname = urlparse(url).hostname
        port = urlparse(url).port or 443

        # Create SSL context that doesn't verify (so we can inspect invalid certs)
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if not cert:
                    ssl_info["error"] = "No certificate returned"
                    return ssl_info

                # Issuer information
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))

                issuer_cn = issuer.get("commonName", "")
                subject_cn = subject.get("commonName", "")

                ssl_info["issuer"] = issuer_cn
                ssl_info["subject"] = subject_cn
                ssl_info["issuer_org"] = issuer.get("organizationName", "")
                ssl_info["subject_org"] = subject.get("organizationName", "")

                # Self-signed detection (issuer == subject)
                ssl_info["is_self_signed"] = (issuer_cn == subject_cn)

                # Certificate validity dates
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")

                if not_before_str:
                    not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                    ssl_info["valid_from"] = not_before.isoformat()

                    # Certificate age (newly issued = suspicious)
                    cert_age_days = (datetime.utcnow() - not_before).days
                    ssl_info["cert_age_days"] = cert_age_days
                    ssl_info["is_newly_issued"] = cert_age_days < 30
                    ssl_info["is_very_new_cert"] = cert_age_days < 7

                if not_after_str:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    ssl_info["valid_until"] = not_after.isoformat()

                    days_until_expiry = (not_after - datetime.utcnow()).days
                    ssl_info["days_until_cert_expiry"] = days_until_expiry

                # Subject Alternative Names (all domains this cert covers)
                san_list = []
                for san in cert.get("subjectAltName", []):
                    if san[0] == "DNS":
                        san_list.append(san[1])
                ssl_info["san_domains"] = san_list

                # Domain mismatch check
                cert_domains = [subject_cn] + san_list
                ssl_info["domain_mismatch"] = hostname not in cert_domains

                # Trusted CA check (common legitimate issuers)
                trusted_issuers = [
                    "Let's Encrypt", "DigiCert", "GoDaddy", "Comodo", "Sectigo",
                    "GlobalSign", "Entrust", "Amazon", "Google Trust Services",
                    "IdenTrust", "Baltimore", "ISRG"  # Internet Security Research Group (Let's Encrypt)
                ]
                ssl_info["trusted_issuer"] = any(ca in issuer_cn for ca in trusted_issuers)
                ssl_info["untrusted_issuer"] = not ssl_info["trusted_issuer"] and not ssl_info["is_self_signed"]

                # Risk scoring
                risk_score = 0
                risk_reasons = []

                if ssl_info["is_self_signed"]:
                    risk_score += 30
                    risk_reasons.append("self_signed_cert")

                if ssl_info.get("domain_mismatch"):
                    risk_score += 25
                    risk_reasons.append("domain_mismatch")

                if ssl_info.get("is_very_new_cert"):
                    risk_score += 15
                    risk_reasons.append("very_new_cert")
                elif ssl_info.get("is_newly_issued"):
                    risk_score += 10
                    risk_reasons.append("newly_issued_cert")

                if ssl_info.get("untrusted_issuer"):
                    risk_score += 10
                    risk_reasons.append("untrusted_issuer")

                ssl_info["cert_risk_score"] = risk_score
                ssl_info["cert_risk_reasons"] = risk_reasons

    except ssl.SSLError as e:
        ssl_info["ssl_error"] = True
        ssl_info["error"] = f"SSLError: {str(e)}"
        ssl_info["cert_risk_score"] = 20  # SSL errors are suspicious
        ssl_info["cert_risk_reasons"] = ["ssl_error"]
    except socket.timeout:
        ssl_info["error"] = "Connection timeout"
    except Exception as e:
        ssl_info["error"] = str(e)

    return ssl_info

async def read_robots_ok(client: httpx.AsyncClient, base_url: str, ua: str) -> Optional[bool]:
    """Returns True/False if robots could be fetched & parsed, None if unavailable."""
    try:
        if "://" not in base_url:
            return None
        scheme, rest = base_url.split("://", 1)
        host = rest.split("/", 1)[0]
        robots_url = f"{scheme}://{host}/robots.txt"
        r = await client.get(robots_url, headers={"User-Agent": ua}, timeout=TIMEOUT_READ_S)
        if r.status_code >= 400 or not r.text:
            return None
        
        disallows: List[str] = []
        allows: List[str] = []
        active = False
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): 
                continue
            low = line.lower()
            if low.startswith("user-agent:"):
                agent = line.split(":",1)[1].strip()
                active = (agent == ua) or (agent == "*")
            elif active and low.startswith("disallow:"):
                path = line.split(":",1)[1].strip() or "/"
                disallows.append(path)
            elif active and low.startswith("allow:"):
                path = line.split(":",1)[1].strip() or "/"
                allows.append(path)
        
        path = "/"
        longest_allow = max([a for a in allows if path.startswith(a)], key=len, default=None)
        longest_dis   = max([d for d in disallows if path.startswith(d)], key=len, default=None)
        if longest_allow and longest_dis:
            return len(longest_allow) >= len(longest_dis)
        if longest_allow:
            return True
        if longest_dis:
            return False
        return True
    except Exception:
        return None

def extract_title(html: str) -> Optional[str]:
    if not html:
        return None
    try:
        tree = HTMLParser(html)
        n = tree.css_first("title")
        if n and n.text():
            t = n.text().strip()
            return re.sub(r"\s+", " ", t)[:300]
        n = tree.css_first("h1")
        if n and n.text():
            t = n.text().strip()
            return re.sub(r"\s+", " ", t)[:300]
    except Exception:
        return None
    return None

def extract_meta_description(html: str) -> Optional[str]:
    """Extract meta description for additional context"""
    if not html:
        return None
    try:
        tree = HTMLParser(html)
        meta = tree.css_first('meta[name="description"]')
        if meta:
            return meta.attributes.get("content", "")[:500]
    except:
        return None
    return None

async def fetch_head_then_get(client: httpx.AsyncClient, base: str) -> Tuple[Dict[str, Any], List[Dict[str, Any]], str]:
    """
    Probe site: follow redirects (limited). Capture chain and small body for title.
    Returns (final_result, chain, html_body)
    """
    chain: List[Dict[str, Any]] = []
    url = base if base.endswith("/") else (base + "/")
    timeout_config = httpx.Timeout(connect=TIMEOUT_CONN_S, read=TIMEOUT_READ_S, write=5.0, pool=5.0)
    html_body = ""
    
    try:
        r = await client.head(url, follow_redirects=True, 
                            timeout=timeout_config, 
                            headers={"User-Agent": USER_AGENT})
    except httpx.HTTPError:
        r = await client.get(url, follow_redirects=True, 
                           timeout=timeout_config, 
                           headers={"User-Agent": USER_AGENT})
    
    if r.history:
        for step in r.history:
            chain.append({"url": str(step.request.url), "status": step.status_code})
    chain.append({"url": str(r.request.url), "status": r.status_code})

    ctype = r.headers.get("content-type","").lower()
    content_length = None
    title = None
    meta_desc = None
    ssl_info = extract_ssl_info(r)
    
    if "text/html" in ctype or "application/xhtml" in ctype or (r.status_code == 200 and not ctype):
        try:
            timeout_config = httpx.Timeout(connect=TIMEOUT_CONN_S, read=TIMEOUT_READ_S, write=5.0, pool=5.0)
            gr = await client.get(str(r.request.url), headers={"User-Agent": USER_AGENT}, 
                                timeout=timeout_config, 
                                follow_redirects=False)
            total = 0
            chunks: List[bytes] = []
            async for chunk in gr.aiter_bytes():
                total += len(chunk)
                chunks.append(chunk)
                if total >= MAX_BODY_BYTES:
                    break
            body = b"".join(chunks)
            content_length = len(body)
            try:
                html_body = body.decode(errors="ignore")
                title = extract_title(html_body)
                meta_desc = extract_meta_description(html_body)
            except Exception:
                title = None
        except httpx.HTTPError:
            pass

    result = {
        "url": str(r.request.url),
        "status": r.status_code,
        "headers": {
            "server": r.headers.get("server"),
            "content_type": r.headers.get("content-type"),
            "x_powered_by": r.headers.get("x-powered-by"),
            "via": r.headers.get("via"),
            "cf_ray": r.headers.get("cf-ray"),
        },
        "ssl_info": ssl_info,
        "content_length": content_length,
        "title": title,
        "meta_description": meta_desc,
    }
    return result, chain, html_body

async def probe_host(fqdn: str) -> Dict[str, Any]:
    base_candidates = [f"https://{fqdn}", f"http://{fqdn}"]
    limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
    async with httpx.AsyncClient(
        http2=True,
        headers={"User-Agent": USER_AGENT},
        follow_redirects=False,
        limits=limits,
        max_redirects=MAX_REDIRECTS,
        verify=False,  # Don't fail on SSL errors
    ) as client:

        robots_respected: Optional[bool] = None
        final = None
        chain: List[Dict[str, Any]] = []
        scheme_used = None
        html_body = ""

        for base in base_candidates:
            try:
                robots_respected = await read_robots_ok(client, base, USER_AGENT)
                final, chain, html_body = await fetch_head_then_get(client, base)
                scheme_used = base.split("://",1)[0]
                break
            except httpx.HTTPError:
                continue

        if final is None:
            return {
                "ok": False,
                "error": "connect_failed",
                "robots_respected": robots_respected,
                "redirect_chain": [],
                "parking_detection": {"is_parked": False, "confidence": "none", "indicators": []},
                "phishing_signals": {"risk_score": 0, "signals": []},
            }

        # Analyze content
        parking = is_parked(html_body, final.get("title"), final.get("url"))
        phishing = detect_phishing_signals(html_body, final.get("title"), final.get("url"), fqdn)
        
        # Add redirect count to phishing score
        redirect_count = len(chain) - 1
        if redirect_count > 3:
            phishing["signals"].append(f"excessive_redirects:{redirect_count}")
            phishing["risk_score"] = min(phishing["risk_score"] + (redirect_count * 5), 100)

        return {
            "ok": True,
            "robots_respected": robots_respected,
            "scheme": scheme_used,
            "final": final,
            "redirect_chain": chain,
            "redirect_count": redirect_count,
            "parking_detection": parking,
            "phishing_signals": phishing,
        }

# ---------- kafka plumbing with retry ----------
async def kafka_producer(max_retries=30):
    delay = 2.0
    for attempt in range(max_retries):
        try:
            prod = AIOKafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP, linger_ms=50)
            await prod.start()
            print(f"[ic05] Kafka producer connected")
            return prod
        except Exception as e:
            print(f"[ic05] Producer connection attempt {attempt+1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(delay)
                delay = min(delay * 1.5, 10.0)
    raise Exception("Could not connect Kafka producer after retries")

async def kafka_consumer(topic: str, group_id: str, max_retries=30):
    delay = 2.0
    for attempt in range(max_retries):
        try:
            cons = AIOKafkaConsumer(
                topic,
                bootstrap_servers=KAFKA_BOOTSTRAP,
                group_id=group_id,
                enable_auto_commit=True,
                auto_offset_reset="earliest",
                value_deserializer=lambda v: ujson.loads(v.decode("utf-8")),
            )
            await cons.start()
            print(f"[ic05] Kafka consumer connected to topic: {topic}")
            return cons
        except Exception as e:
            print(f"[ic05] Consumer connection attempt {attempt+1}/{max_retries} failed: {e}")
            if attempt < max_retries - 1:
                await asyncio.sleep(delay)
                delay = min(delay * 1.5, 10.0)
    raise Exception(f"Could not connect Kafka consumer to {topic} after retries")

async def send_jsonl_line(fobj, obj: dict):
    line = ujson.dumps(obj, ensure_ascii=False) + "\n"
    fobj.write(line)
    fobj.flush()

# ---------- main worker ----------
async def worker(worker_id: int, queue: asyncio.Queue, prod, fobj):
    print(f"[ic05] Worker {worker_id} started")
    processed = 0
    while True:
        try:
            item = await queue.get()
            if item is None:
                queue.task_done()
                print(f"[ic05] Worker {worker_id} shutting down (processed {processed} items)")
                return
                
            fqdn = item["fqdn"]
            reg  = registrable(fqdn)
            
            try:
                probe = await probe_host(fqdn)
                out = {
                    "src": "ic05",
                    "observed_at": time.time(),
                    "canonical_fqdn": fqdn,
                    "registrable": reg,
                    "seed_registrable": item.get("seed_registrable"),  # Preserve seed for tracking
                    "cse_id": item.get("cse_id"),  # Preserve CSE ID
                    "is_original_seed": item.get("is_original_seed", False),  # Preserve original seed flag
                    "robots_respected": probe.get("robots_respected"),
                    "redirect_chain": probe.get("redirect_chain"),
                    "redirect_count": probe.get("redirect_count", 0),
                    "final": probe.get("final"),
                    "ok": probe.get("ok"),
                    "error": probe.get("error"),
                    "parking_detection": probe.get("parking_detection"),
                    "phishing_signals": probe.get("phishing_signals"),
                }
                await prod.send_and_wait(OUTPUT_TOPIC, ujson.dumps(out).encode("utf-8"), key=reg.encode())
                await send_jsonl_line(fobj, out)
                processed += 1
                if processed % 10 == 0:
                    print(f"[ic05] Worker {worker_id}: {processed} probes completed")
            except Exception as e:
                print(f"[ic05] Worker {worker_id} probe error for {fqdn}: {e}")
                out = {
                    "src": "ic05",
                    "observed_at": time.time(),
                    "canonical_fqdn": fqdn,
                    "registrable": reg,
                    "seed_registrable": item.get("seed_registrable"),  # Preserve seed for tracking
                    "cse_id": item.get("cse_id"),  # Preserve CSE ID
                    "is_original_seed": item.get("is_original_seed", False),  # Preserve original seed flag
                    "ok": False,
                    "error": f"probe_exception:{type(e).__name__}",
                    "parking_detection": {"is_parked": False, "confidence": "none", "indicators": []},
                    "phishing_signals": {"risk_score": 0, "signals": []},
                }
                try:
                    await prod.send_and_wait(OUTPUT_TOPIC, ujson.dumps(out).encode("utf-8"), key=reg.encode())
                    await send_jsonl_line(fobj, out)
                except:
                    pass
        except Exception as e:
            print(f"[ic05] Worker {worker_id} critical error: {e}")
        finally:
            queue.task_done()

async def main():
    print("[ic05] HTTP Fetcher starting...")
    print(f"[ic05] Concurrency: {CONCURRENCY}, Input: {INPUT_TOPIC}, Output: {OUTPUT_TOPIC}")
    sys.stdout.flush()
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    seg = OUTPUT_DIR / f"http_probed_{now_iso()}.jsonl"
    fobj = seg.open("a", encoding="utf-8", buffering=1)
    print(f"[ic05] Writing to: {seg}")
    
    try:
        prod = await kafka_producer()
        cons = await kafka_consumer(INPUT_TOPIC, group_id="ic05-http-fetcher")
        
        queue: asyncio.Queue = asyncio.Queue(maxsize=CONCURRENCY * 4)
        workers = [asyncio.create_task(worker(i, queue, prod, fobj)) for i in range(CONCURRENCY)]
        
        print(f"[ic05] Started {CONCURRENCY} workers, waiting for messages...")
        sys.stdout.flush()
        
        msg_count = 0
        
        async for msg in cons:
            try:
                doc = msg.value or {}
                fqdn = (doc.get("canonical_fqdn") or 
                       doc.get("fqdn") or 
                       doc.get("host") or 
                       doc.get("domain"))
                
                if not fqdn:
                    continue

                addrs = doc.get("A") or doc.get("AAAA")
                if addrs is None and not FALLBACK_RESOLVE:
                    pass

                # CRITICAL: Pass seed_registrable and cse_id from input document
                await queue.put({
                    "fqdn": fqdn,
                    "seed_registrable": doc.get("seed_registrable"),
                    "cse_id": doc.get("cse_id")
                })
                msg_count += 1
                
                if msg_count % 50 == 0:
                    print(f"[ic05] Queued {msg_count} domains for probing")
                    sys.stdout.flush()
                    
            except Exception as e:
                print(f"[ic05] Error processing message: {e}")
                
    except KeyboardInterrupt:
        print("[ic05] Received interrupt signal")
    except Exception as e:
        print(f"[ic05] Fatal error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("[ic05] Shutting down...")
        for _ in range(CONCURRENCY):
            await queue.put(None)
        await asyncio.gather(*workers, return_exceptions=True)
        
        try:
            await cons.stop()
        except:
            pass
        try:
            await prod.stop()
        except:
            pass
        
        fobj.close()
        print(f"[ic05] Shutdown complete. Output: {seg}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[ic05] Interrupted by user")
    except Exception as e:
        print(f"[ic05] Fatal: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)