#!/usr/bin/env python3
"""
Test parking detection with REAL metadata from dump_all.jsonl
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

def test_real_airnote():
    """Test with REAL airnote.eu data"""
    print("=" * 80)
    print("TEST: airnote.eu (REAL DATA from dump_all.jsonl)")
    print("=" * 80)

    metadata = load_real_metadata('airnote.eu')
    if not metadata:
        print("❌ FAILED: Could not load airnote.eu metadata")
        return False

    print(f"\nLoaded metadata:")
    print(f"  ASN: {metadata.get('asn')} ({metadata.get('asn_org')})")
    print(f"  DNS: {metadata.get('dns', '')[:200]}...")
    print(f"  Registrar: {metadata.get('registrar')}")

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

    if result['verdict'] == 'PARKED':
        print(f"\n✅ TEST PASSED: Correctly detected as PARKED")
        return True
    else:
        print(f"\n❌ TEST FAILED: Expected PARKED, got {result['verdict']}")
        return False

def test_real_sibi():
    """Test with REAL sibi.hamburg data"""
    print("\n" + "=" * 80)
    print("TEST: sibi.hamburg (REAL DATA from dump_all.jsonl)")
    print("=" * 80)

    metadata = load_real_metadata('sibi.hamburg')
    if not metadata:
        print("❌ FAILED: Could not load sibi.hamburg metadata")
        return False

    print(f"\nLoaded metadata:")
    print(f"  ASN: {metadata.get('asn')} ({metadata.get('asn_org')})")
    print(f"  Registrar: {metadata.get('registrar')}")
    print(f"  Redirect chain: {len(json.loads(metadata.get('redirect_chain', '[]')))} redirects")
    print(f"  OCR excerpt: {metadata.get('ocr_text_excerpt', metadata.get('ocr', ''))[:100]}...")

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

    if result['verdict'] == 'PARKED':
        print(f"\n✅ TEST PASSED: Correctly detected as PARKED")
        return True
    else:
        print(f"\n❌ TEST FAILED: Expected PARKED, got {result['verdict']}")
        return False

def main():
    results = []

    print("\n" + "=" * 80)
    print("REAL DATA PARKING DETECTION TEST")
    print("=" * 80 + "\n")

    results.append(test_real_airnote())
    results.append(test_real_sibi())

    print("\n" + "=" * 80)
    print(f"SUMMARY: {sum(results)}/{len(results)} tests passed")
    print("=" * 80)

    return 0 if all(results) else 1

if __name__ == '__main__':
    sys.exit(main())
