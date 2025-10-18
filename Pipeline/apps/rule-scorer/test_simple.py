#!/usr/bin/env python3
"""
Simple test to verify enhanced rule logic without running full worker.
This tests the helper functions directly.
"""

import sys

# Configuration (copied from worker.py)
PROTECTED_TLDS = {"gov", "edu", "mil", "ac", "org", "gov.in", "gov.uk", "gov.au", "gov.ca", "gov.sg", "ac.uk", "edu.au", "mil.uk"}
CCTLDS = {"in", "uk", "au", "de", "fr", "cn", "ru", "br", "jp", "kr", "sg", "nz", "za", "nl", "se", "no", "dk", "fi", "es", "it", "pl", "ch", "at", "be", "gr", "ie", "pt", "cz"}
GEO_SENSITIVE_TLDS = {
    "gov.in": ["IN"],
    "gov.uk": ["GB", "UK"],
    "gov.au": ["AU"],
    "gov": ["US"],
    "mil": ["US"],
}
MIN_TTL_THRESHOLD = 60

# Helper functions (copied from worker.py)
def _extract_subdomain_labels(fqdn):
    if not fqdn or "." not in fqdn:
        return []
    parts = fqdn.lower().split(".")
    return parts[:-2] if len(parts) > 2 else []

def _detect_tld_impersonation(fqdn, actual_tld):
    if not fqdn:
        return False, None

    subdomain_labels = _extract_subdomain_labels(fqdn)

    # Check for multi-part protected TLDs first
    for i in range(len(subdomain_labels) - 1):
        combined = f"{subdomain_labels[i]}.{subdomain_labels[i+1]}"
        if combined in PROTECTED_TLDS and combined != actual_tld:
            return True, combined

    # Check for single-part protected TLDs or ccTLDs
    for label in subdomain_labels:
        if label in PROTECTED_TLDS and label != actual_tld:
            return True, label
        if label in CCTLDS and label != actual_tld:
            return True, label

    return False, None

def _count_subdomain_depth(fqdn):
    if not fqdn or "." not in fqdn:
        return 0
    parts = fqdn.split(".")
    return max(0, len(parts) - 2)

def _check_self_referential_mx(fqdn, mx_records):
    if not fqdn or not mx_records:
        return False
    fqdn_lower = fqdn.lower().rstrip(".")
    for mx in mx_records:
        mx_lower = (mx or "").lower().rstrip(".")
        if mx_lower == fqdn_lower:
            return True
    return False

def _check_low_ttl(ttls_dict):
    if not ttls_dict:
        return False
    for record_type, ttl in ttls_dict.items():
        if isinstance(ttl, int) and 0 <= ttl < MIN_TTL_THRESHOLD:
            return True
    return False

def _check_geographic_mismatch(fqdn, geoip_data):
    if not fqdn or not geoip_data:
        return False, None

    actual_country = geoip_data.get("country")
    if not actual_country:
        return False, None

    for sensitive_tld, expected_countries in GEO_SENSITIVE_TLDS.items():
        if f".{sensitive_tld}." in f".{fqdn.lower()}." or fqdn.lower().endswith(f".{sensitive_tld}"):
            if fqdn.lower().endswith(f".{sensitive_tld}"):
                continue
            if actual_country.upper() not in expected_countries:
                return True, sensitive_tld

    return False, None

# Manual scoring simulation
def simulate_scoring(domain_data, description):
    print(f"\n{'='*80}")
    print(f"Testing: {description}")
    print(f"{'='*80}")

    fqdn = domain_data.get("fqdn", "")
    actual_tld = domain_data.get("tld", "")

    score = 0
    reasons = []

    # TLD impersonation
    is_imp, imp_tld = _detect_tld_impersonation(fqdn, actual_tld)
    if is_imp:
        if imp_tld in PROTECTED_TLDS:
            score += 40
            reasons.append(f"TLD impersonation: {imp_tld} in subdomain (+40)")
        else:
            score += 30
            reasons.append(f"ccTLD in subdomain: {imp_tld} (+30)")

    # Subdomain depth
    depth = _count_subdomain_depth(fqdn)
    if depth >= 8:
        score += 20
        reasons.append(f"Extreme subdomain depth: {depth} levels (+20)")
    elif depth >= 6:
        score += 15
        reasons.append(f"Very deep subdomains: {depth} levels (+15)")
    elif depth >= 5:
        score += 12
        reasons.append(f"Many subdomains: {depth} levels (+12)")
    elif depth >= 3:
        score += 8
        reasons.append(f"Multiple subdomains: {depth} levels (+8)")

    # Self-referential MX
    mx_records = domain_data.get("mx_records", [])
    if _check_self_referential_mx(fqdn, mx_records):
        score += 10
        reasons.append("Self-referential MX record (+10)")

    # Low TTL
    ttls = domain_data.get("ttls", {})
    if _check_low_ttl(ttls):
        score += 8
        reasons.append("Suspiciously low TTL - fast-flux (+8)")

    # Missing WHOIS
    if domain_data.get("missing_whois", False):
        score += 5
        reasons.append("WHOIS data unavailable (+5)")

    # Geographic mismatch
    geoip = domain_data.get("geoip", {})
    has_geo_mismatch, claimed_tld = _check_geographic_mismatch(fqdn, geoip)
    if has_geo_mismatch:
        score += 15
        reasons.append(f"Geographic mismatch: claims {claimed_tld}, hosted in {geoip.get('country')} (+15)")

    # Risky TLD
    if actual_tld == "info":
        score += 6
        reasons.append("Risky TLD: .info (+6)")

    # Typosquatting
    if domain_data.get("is_typosquat", False):
        score += 25
        reasons.append(f"Typosquat of {domain_data.get('seed')} (+25)")

    # JavaScript obfuscation
    if domain_data.get("js_obfuscated", False):
        score += 15
        reasons.append("Obfuscated JavaScript detected (+15)")

    # Cross-registrable redirect
    if domain_data.get("cross_registrable_redirect", False):
        score += 12
        reasons.append("Redirect crosses registrable (+12)")

    print(f"FQDN: {fqdn}")
    print(f"Actual TLD: {actual_tld}")
    print(f"\nDetections:")
    for reason in reasons:
        print(f"  - {reason}")

    print(f"\nTotal Score: {score}")
    verdict = "phishing" if score >= 70 else ("suspicious" if score >= 40 else "benign")
    print(f"Verdict: {verdict}")

    return score, verdict

# Test 1: Government impersonation domain
test1 = {
    "fqdn": "dc.crsorgi.gov.in.web.index.dc-verify.info",
    "tld": "info",
    "mx_records": ["dc.crsorgi.gov.in.web.index.dc-verify.info"],
    "ttls": {"A": 0, "MX": 0, "NS": 0},
    "missing_whois": True,
    "geoip": {"country": "DE"}
}

# Test 2: Typosquat
test2 = {
    "fqdn": "www.ciaude.ai",
    "tld": "ai",
    "mx_records": [],
    "ttls": {"A": 300},
    "missing_whois": False,
    "geoip": {"country": "US"},
    "is_typosquat": True,
    "seed": "claude.ai",
    "js_obfuscated": True,
    "cross_registrable_redirect": True  # Redirected to claude.ai
}

# Test 3: Legitimate
test3 = {
    "fqdn": "www.google.com",
    "tld": "com",
    "mx_records": ["smtp.google.com"],
    "ttls": {"A": 300, "MX": 3600},
    "missing_whois": False,
    "geoip": {"country": "US"}
}

# Run tests
score1, verdict1 = simulate_scoring(test1, "dc.crsorgi.gov.in.web.index.dc-verify.info")
score2, verdict2 = simulate_scoring(test2, "www.ciaude.ai (typosquat)")
score3, verdict3 = simulate_scoring(test3, "www.google.com (legitimate)")

# Summary
print(f"\n{'='*80}")
print("TEST SUMMARY")
print(f"{'='*80}")

test1_pass = score1 >= 70 and verdict1 == "phishing"
test2_pass = score2 >= 40 and verdict2 in ["suspicious", "phishing"]
test3_pass = score3 < 40 and verdict3 == "benign"

print(f"Test 1 (gov impersonation): {'✓ PASS' if test1_pass else '✗ FAIL'} (score: {score1}, expected: ≥70)")
print(f"Test 2 (typosquatting):     {'✓ PASS' if test2_pass else '✗ FAIL'} (score: {score2}, expected: ≥40)")
print(f"Test 3 (legitimate):        {'✓ PASS' if test3_pass else '✗ FAIL'} (score: {score3}, expected: <40)")

if test1_pass and test2_pass and test3_pass:
    print("\n🎉 ALL TESTS PASSED!")
    sys.exit(0)
else:
    print("\n❌ SOME TESTS FAILED")
    sys.exit(1)
