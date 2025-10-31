#!/usr/bin/env python3
"""
Test script to verify aconica.space is now correctly detected as INACTIVE
(not PHISHING) after implementing Cloudflare parking detection + reduced typosquatting penalties
"""

import json
import sys
from fallback_detector import FallbackDetector

def load_real_metadata(domain):
    """Load real metadata from dump_all.jsonl"""
    with open('/home/turtleneck/Desktop/PS02/dump_all.jsonl', 'r') as f:
        for line in f:
            record = json.loads(line)
            if record.get('id', '').startswith(f"{domain}:"):
                return record.get('metadata', {})
    return None

def test_aconica_space():
    """Test with REAL aconica.space data"""
    print("=" * 80)
    print("TEST: aconica.space (REAL DATA from dump_all.jsonl)")
    print("Expected: INACTIVE (not PHISHING)")
    print("=" * 80)

    metadata = load_real_metadata('aconica.space')
    if not metadata:
        print("❌ FAILED: Could not load aconica.space metadata")
        return False

    print(f"\nLoaded metadata:")
    print(f"  Domain: {metadata.get('registrable')}")
    print(f"  ASN: {metadata.get('asn')} ({metadata.get('asn_org')})")

    # Parse DNS
    dns = json.loads(metadata.get('dns', '{}'))
    print(f"  A records: {dns.get('A', [])}")
    print(f"  NS records: {dns.get('NS', [])}")
    print(f"  MX records: {dns.get('MX', [])}")

    # Content availability
    print(f"  HTML size: {metadata.get('html_size', 0)}")
    print(f"  Screenshot: {metadata.get('screenshot_path', 'None')}")
    print(f"  OCR text length: {metadata.get('ocr_text_length', 0)}")
    print(f"  Domain age: {metadata.get('domain_age_days')} days")

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\n{'='*60}")
    print(f"RESULT:")
    print(f"{'='*60}")
    print(f"Domain: {result['domain']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Reason: {result['reason']}")
    print(f"Source: {result['source']}")
    print(f"Data Availability:")
    for key, val in result.get('data_availability', {}).items():
        print(f"  - {key}: {val}")

    # Validation
    expected_verdict = 'INACTIVE'
    if result['verdict'] == expected_verdict:
        print(f"\n✅ TEST PASSED: Correctly detected as {expected_verdict}")
        print(f"   Detection method: {result['source']}")
        print(f"   Reason: Cloudflare parking + no content → INACTIVE (not PHISHING)")
        return True
    else:
        print(f"\n❌ TEST FAILED: Expected {expected_verdict}, got {result['verdict']}")
        print(f"   This domain has:")
        print(f"   - Cloudflare IPs (104.21.x.x, 172.67.x.x)")
        print(f"   - No MX records")
        print(f"   - No content (html/screenshot/ocr all false)")
        print(f"   - Should be INACTIVE even if typosquatting detected")
        return False

def main():
    print("\n" + "=" * 80)
    print("ACONICA.SPACE FALSE POSITIVE FIX VALIDATION")
    print("=" * 80 + "\n")

    result = test_aconica_space()

    print("\n" + "=" * 80)
    if result:
        print("🎉 FIX SUCCESSFUL! aconica.space now correctly detected as INACTIVE")
    else:
        print("⚠️  FIX FAILED. Please review the output above.")
    print("=" * 80)

    return 0 if result else 1

if __name__ == '__main__':
    sys.exit(main())
