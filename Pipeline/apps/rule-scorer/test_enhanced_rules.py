#!/usr/bin/env python3
"""
Test script for enhanced rule-scorer detection capabilities.
Tests the two problem domains that were incorrectly classified as benign.
"""

import sys
import os

# Add parent directory to path to import worker
sys.path.insert(0, os.path.dirname(__file__))

# Import the scoring function from worker
from worker import score_bundle

# Test case 1: dc.crsorgi.gov.in.web.index.dc-verify.info
# Expected: Should score high (phishing) due to:
# - TLD impersonation (gov.in in subdomain, actual TLD is .info)
# - Extreme subdomain depth (8 levels)
# - Self-referential MX
# - Zero TTL (fast-flux)
# - Missing WHOIS
# - Geographic mismatch (claims India gov, hosted in Germany)

test_domain_1 = {
    "canonical_fqdn": "dc.crsorgi.gov.in.web.index.dc-verify.info",
    "registrable": "dc-verify.info",
    "dns": {
        "A": ["157.90.176.32"],
        "MX": ["dc.crsorgi.gov.in.web.index.dc-verify.info"],
        "NS": ["dns4.netcloudns.com", "dns3.netcloudns.com"],
        "ttls": {
            "A": 0,
            "MX": 0,
            "NS": 0
        }
    },
    "whois": {
        "error": "Whois command returned no output"
    },
    "geoip": {
        "country": "DE",
        "city": "Falkenstein",
        "asn": 24940,
        "asn_org": "Hetzner Online GmbH"
    }
}

# Test case 2: www.ciaude.ai (typosquat)
# Expected: Should score higher due to:
# - Typosquatting detection (lookalike of claude.ai)
# - Obfuscated JavaScript (if detected in features)

test_domain_2 = {
    "canonical_fqdn": "www.ciaude.ai",
    "registrable": "ciaude.ai",
    "seed_registrable": "claude.ai",
    "is_original_seed": False,
    "dns": {
        "A": ["104.21.45.123"],
        "NS": ["ns1.example.com", "ns2.example.com"],
        "ttls": {
            "A": 300,
            "NS": 3600
        }
    },
    "whois": {
        "is_newly_registered": False
    },
    "geoip": {
        "country": "US",
        "asn": 13335,
        "asn_org": "Cloudflare"
    }
}

test_http_2 = {
    "had_redirects": True,
    "redirect_count": 7
}

test_feat_2 = {
    "url": "https://www.ciaude.ai/",
    "url_length": 22,
    "url_entropy": 3.6635,
    "num_subdomains": 1,
    "js_obfuscated": True,
    "js_obfuscated_count": 1
}

# Test case 3: Legitimate domain (should remain benign)
test_legitimate = {
    "canonical_fqdn": "www.google.com",
    "registrable": "google.com",
    "dns": {
        "A": ["142.250.185.46"],
        "NS": ["ns1.google.com", "ns2.google.com"],
        "ttls": {
            "A": 300,
            "NS": 3600
        }
    },
    "whois": {
        "is_newly_registered": False
    },
    "geoip": {
        "country": "US",
        "asn": 15169,
        "asn_org": "Google LLC"
    }
}

print("=" * 80)
print("ENHANCED RULE-SCORER TEST SUITE")
print("=" * 80)

# Test 1: Government impersonation
print("\n[TEST 1] dc.crsorgi.gov.in.web.index.dc-verify.info")
print("-" * 80)
result1 = score_bundle(test_domain_1, None, None)
print(f"Verdict: {result1['verdict']}")
print(f"Score: {result1['score']}")
print(f"Confidence: {result1['confidence']}")
print(f"Reasons:")
for reason in result1['reasons']:
    print(f"  - {reason}")
print(f"Categories: {result1['categories']}")

expected_verdict_1 = "phishing" if result1['score'] >= 70 else ("suspicious" if result1['score'] >= 40 else "benign")
print(f"\n✓ PASS" if result1['verdict'] == expected_verdict_1 and result1['score'] >= 70 else f"✗ FAIL (expected phishing with score ≥70)")

# Test 2: Typosquatting
print("\n[TEST 2] www.ciaude.ai (typosquat of claude.ai)")
print("-" * 80)
result2 = score_bundle(test_domain_2, test_http_2, test_feat_2)
print(f"Verdict: {result2['verdict']}")
print(f"Score: {result2['score']}")
print(f"Confidence: {result2['confidence']}")
print(f"Reasons:")
for reason in result2['reasons']:
    print(f"  - {reason}")
print(f"Categories: {result2['categories']}")

expected_verdict_2 = "phishing" if result2['score'] >= 70 else ("suspicious" if result2['score'] >= 40 else "benign")
print(f"\n✓ PASS" if result2['score'] >= 40 else f"✗ FAIL (expected at least suspicious with score ≥40)")

# Test 3: Legitimate domain
print("\n[TEST 3] www.google.com (legitimate)")
print("-" * 80)
result3 = score_bundle(test_legitimate, None, None)
print(f"Verdict: {result3['verdict']}")
print(f"Score: {result3['score']}")
print(f"Confidence: {result3['confidence']}")
print(f"Reasons:")
for reason in result3['reasons']:
    print(f"  - {reason}")
print(f"Categories: {result3['categories']}")

print(f"\n✓ PASS" if result3['verdict'] == 'benign' and result3['score'] < 40 else f"✗ FAIL (expected benign with score <40)")

# Summary
print("\n" + "=" * 80)
print("TEST SUMMARY")
print("=" * 80)

test1_pass = result1['score'] >= 70
test2_pass = result2['score'] >= 40
test3_pass = result3['score'] < 40

print(f"Test 1 (gov impersonation): {'✓ PASS' if test1_pass else '✗ FAIL'} (score: {result1['score']}/expected: ≥70)")
print(f"Test 2 (typosquatting):     {'✓ PASS' if test2_pass else '✗ FAIL'} (score: {result2['score']}/expected: ≥40)")
print(f"Test 3 (legitimate):        {'✓ PASS' if test3_pass else '✗ FAIL'} (score: {result3['score']}/expected: <40)")

if test1_pass and test2_pass and test3_pass:
    print("\n🎉 ALL TESTS PASSED!")
    sys.exit(0)
else:
    print("\n❌ SOME TESTS FAILED")
    sys.exit(1)
