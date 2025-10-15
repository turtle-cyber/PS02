#!/usr/bin/env python3
# apps/rule-scorer/worker.py
import os, asyncio, ujson as json, time, math, re
from collections import OrderedDict, defaultdict
from urllib.parse import urlparse
from datetime import datetime, timezone

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
    "RISKY_TLDS", "tk,ml,ga,cf,gq,xyz,top,club,info,online,site,website,space,tech"
).replace(" ", "").split(","))

# Known parking providers (DNS nameservers)
PARKING_NAMESERVERS = {
    "sedoparking.com", "parkingcrew.net", "bodis.com", "dns-parking.com",
    "cashparking.com", "dan.com", "undeveloped.com", "afternic.com",
    "hugedomains.com", "sav.com", "epik.com", "dynadot.com",
    "uniregistrymarket.link", "parklogic.com", "above.com", "voodoo.com",
    "parkweb.com", "parklogic.com", "parkingsolutions.com"
}

# Parking provider markers in HTTP/HTML
PARKING_MARKERS = [
    "domain for sale", "buy this domain", "this domain is parked",
    "make an offer", "inquire about this domain", "sponsored listings",
    "related searches", "sedoparking", "parkingcrew", "bodis",
    "cashparking", "afternic", "dan.com", "hugedomains"
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
    if num_subdom >= 5: reasons.append("Many subdomains (≥5)"); cats["url"]+=12; score+=12
    elif num_subdom >= 3: reasons.append("Multiple subdomains (≥3)"); cats["url"]+=8; score+=8
    if has_repdig: reasons.append("Repeated digits"); cats["url"]+=6; score+=6
    if tld in RISKY_TLDS: reasons.append(f"Risky TLD .{tld}"); cats["domain"]+=6; score+=6

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
        for parker in ["sedo.com", "dan.com", "afternic.com", "hugedomains.com", "godaddy.com/domainfind", "sav.com/auction"]:
            if parker in http_lower:
                is_parked = True
                parked_reasons.append(f"Redirects to parking marketplace ({parker})")
                break

    # 3. HTML content markers (if no DNS/redirect signal)
    if not is_parked and feat:
        title = (feat or {}).get("title") or ""
        page_text = (feat or {}).get("page_text") or ""
        combined = (title + " " + page_text).lower()
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

# ------------ Output shaping for your ingestor ------------
def make_merged_record(domain: dict, http: dict, feat: dict, scored: dict):
    """
    Produce a compact 'merged' record compatible with apps/chroma-ingestor/ingest.py.
    - Puts verdict into 'stage' so your ingestor will keep it in metadata.
    - Adds monitoring metadata when applicable.
    - Keeps 'reasons' (already used by ingestor for text+metadata).
    - Carries over common fields when present.
    - Drops heavy blobs.
    """
    verdict = scored["verdict"]
    final_verdict = scored.get("final_verdict", verdict)
    stage = f"rules:monitor" if scored.get("monitor_until") else f"rules:{verdict}"

    out = {
        "record_type": "merged",
        "canonical_fqdn": scored["canonical_fqdn"],
        "registrable": scored["registrable"],
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
        for key in ("cse_id","seed_registrable"):
            if key in src and key not in out:
                out[key] = src[key]

    # DNS/WHOIS from domain
    if domain:
        dcopy = dict(domain)
        _drop_heavy(dcopy)
        for k in ("dns","whois","rdap","geoip","a_count","mx_count","ns_count","country"):
            if k in dcopy: out[k] = dcopy[k]

    # TLS/basic HTTP
    if http:
        hcopy = dict(http)
        _drop_heavy(hcopy)
        for k in ("tls","had_redirects","status","server","title","final_url","original_host","host"):
            if k in hcopy: out[k] = hcopy[k]

    # Features (preserve nested structures used by ingestor)
    if feat:
        fcopy = dict(feat)
        _drop_heavy(fcopy)
        for k in ("url_features","idn","forms","text_keywords","javascript",
                  "html_size","external_links","iframe_count",
                  "form_count","password_fields","email_fields",
                  "has_credential_form","keyword_count",
                  "suspicious_form_count","has_suspicious_forms",
                  "forms_to_ip","forms_to_suspicious_tld","forms_to_private_ip"):
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

            scored = score_bundle(domain, http, feat)
            merged = make_merged_record(domain, http, feat, scored)

            # Emit to Kafka (no Chroma upsert here)
            out_key = (merged.get("registrable") or merged.get("canonical_fqdn") or "").lower()
            await producer.send_and_wait(OUTPUT_TOPIC, json.dumps(merged), key=out_key)

            # Log verdicts for debugging
            verdict = merged.get("verdict", "unknown")
            if verdict in ("parked", "suspicious", "phishing"):
                print(f"[scorer] {out_key}: {verdict} (monitoring: {merged.get('requires_monitoring', False)})")

            # Optional JSONL
            if jsonl_fp:
                jsonl_fp.write(json.dumps(merged) + "\n"); jsonl_fp.flush()

            state.gc()
    finally:
        await consumer.stop(); await producer.stop()
        if jsonl_fp: jsonl_fp.close()

if __name__ == "__main__":
    asyncio.run(main())
