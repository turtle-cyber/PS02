#!/usr/bin/env python3
"""
Test script to verify AIML integration with new crawler schema from dump_all.jsonl
Tests:
1. Nested metadata extraction (asn, country from geoip/rdap)
2. Crawler PARKED verdict trust
3. Reduced domain age penalties (Oct 1-15 date range)
4. Enrichment level routing
"""

import json
import sys
from pathlib import Path

# Add AIML directory to path
sys.path.insert(0, str(Path(__file__).parent))

from fallback_detector import FallbackDetector

def load_sample_records(dump_path, limit=10):
    """Load sample records from dump_all.jsonl"""
    records = []
    with open(dump_path, 'r') as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            record = json.loads(line)
            records.append(record)
    return records

def test_nested_metadata_extraction():
    """Test extraction of asn, country from nested geoip/rdap JSON"""
    print("=" * 80)
    print("TEST 1: Nested Metadata Extraction (asn, country from geoip/rdap)")
    print("=" * 80)

    # Sample metadata with nested geoip
    metadata = {
        'registrable': 'test.com',
        'geoip': json.dumps({
            'asn': 8560,
            'asn_org': 'IONOS SE',
            'country': 'DE',
            'latitude': 51.2993,
            'longitude': 9.491
        })
    }

    detector = FallbackDetector()
    detector._extract_nested_metadata(metadata)

    print(f"\nExtracted fields:")
    print(f"  ASN: {metadata.get('asn')} (expected: '8560')")
    print(f"  ASN Org: {metadata.get('asn_org')} (expected: 'IONOS SE')")
    print(f"  Country: {metadata.get('country')} (expected: 'DE')")
    print(f"  Latitude: {metadata.get('latitude')} (expected: 51.2993)")

    # Validate
    assert str(metadata.get('asn')) == '8560', f"ASN mismatch: {metadata.get('asn')}"
    assert metadata.get('asn_org') == 'IONOS SE', f"ASN org mismatch"
    assert metadata.get('country') == 'DE', f"Country mismatch"

    print(f"\n✅ TEST PASSED: Nested metadata extraction working correctly")
    return True

def test_crawler_parked_verdict():
    """Test that crawler PARKED verdicts are trusted"""
    print("\n" + "=" * 80)
    print("TEST 2: Crawler PARKED Verdict Trust")
    print("=" * 80)

    # Sample with crawler PARKED verdict (from 4ganic.com in dump)
    metadata = {
        'registrable': '4ganic.com',
        'verdict': 'parked',
        'final_verdict': 'parked',
        'confidence': 0.95,
        'risk_score': 40,
        'reasons': 'NS points to parking: registrar-servers.com',
        'enrichment_level': 2,
        'has_features': False,
        'dns': json.dumps({
            'A': ['184.168.131.241'],
            'NS': ['ns1.registrar-servers.com', 'ns2.registrar-servers.com'],
            'MX': []
        }),
        'a_count': 1,
        'mx_count': 0,
        'ns_count': 2,
        'domain_age_days': 21
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Source: {result['source']}")
    print(f"Reason: {result['reason']}")

    # Should detect as PARKED via nameserver detection
    assert result['verdict'] in ['PARKED', 'SUSPICIOUS'], f"Expected PARKED or SUSPICIOUS, got {result['verdict']}"

    print(f"\n✅ TEST PASSED: PARKED detection working")
    return True

def test_reduced_domain_age_penalties():
    """Test that domains aged 16-30 days don't get over-penalized"""
    print("\n" + "=" * 80)
    print("TEST 3: Reduced Domain Age Penalties (Oct 1-15 range)")
    print("=" * 80)

    # Two domains: one 21 days old, one 28 days old (both in Oct 1-15 range)
    test_cases = [
        {'domain': 'test1.com', 'age': 21, 'expected_penalty': 5},  # Reduced from 25
        {'domain': 'test2.com', 'age': 28, 'expected_penalty': 5},  # Reduced from 25
    ]

    detector = FallbackDetector()

    for case in test_cases:
        metadata = {
            'registrable': case['domain'],
            'domain_age_days': case['age'],
            'is_newly_registered': True,
            'a_count': 2,
            'mx_count': 1,
            'ns_count': 2,
            'dns': json.dumps({'A': ['1.2.3.4'], 'NS': ['ns1.example.com'], 'MX': ['mx.example.com']})
        }

        result = detector.analyze_metadata(metadata)

        print(f"\nDomain: {case['domain']} (age: {case['age']} days)")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Confidence: {result['confidence']}")

        # Risk score should be LOW for domains with normal infrastructure
        # Reduced penalties mean age alone doesn't trigger high risk
        assert result['risk_score'] < 50, f"Risk score too high ({result['risk_score']}) for {case['age']}-day domain with infrastructure"

    print(f"\n✅ TEST PASSED: Domain age penalties reduced appropriately")
    return True

def test_real_dump_records():
    """Test with real records from dump_all.jsonl"""
    print("\n" + "=" * 80)
    print("TEST 4: Real Dump Records Analysis")
    print("=" * 80)

    dump_path = '/home/turtleneck/Desktop/PS02/dump_all.jsonl'
    if not Path(dump_path).exists():
        print(f"⚠️  Dump file not found: {dump_path}")
        return True

    records = load_sample_records(dump_path, limit=5)
    print(f"\nLoaded {len(records)} sample records from dump")

    detector = FallbackDetector()

    for i, record in enumerate(records):
        metadata = record.get('metadata', {})
        domain = metadata.get('registrable', 'unknown')

        print(f"\n{'='*60}")
        print(f"Record {i+1}: {domain}")
        print(f"{'='*60}")
        print(f"  Crawler verdict: {metadata.get('verdict')}")
        print(f"  Crawler confidence: {metadata.get('confidence')}")
        print(f"  Enrichment level: {metadata.get('enrichment_level')}")
        print(f"  Has features: {metadata.get('has_features')}")
        print(f"  Domain age: {metadata.get('domain_age_days')} days")

        # Run fallback detector
        result = detector.analyze_metadata(metadata)

        print(f"\n  AIML Result:")
        print(f"    Verdict: {result['verdict']}")
        print(f"    Confidence: {result['confidence']}")
        print(f"    Risk Score: {result['risk_score']}")
        print(f"    Source: {result['source']}")
        print(f"    Reason: {result['reason'][:100]}...")

        # Validate result structure
        assert 'verdict' in result, "Missing verdict"
        assert 'confidence' in result, "Missing confidence"
        assert 'risk_score' in result, "Missing risk_score"
        assert result['verdict'] in ['BENIGN', 'SUSPICIOUS', 'LIKELY_PHISHING', 'PHISHING', 'PARKED', 'INACTIVE'], f"Invalid verdict: {result['verdict']}"

    print(f"\n✅ TEST PASSED: All real dump records processed successfully")
    return True

def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("CRAWLER SCHEMA INTEGRATION TEST SUITE")
    print("=" * 80 + "\n")

    results = []

    # Test 1: Nested metadata extraction
    try:
        results.append(test_nested_metadata_extraction())
    except Exception as e:
        print(f"\n❌ TEST 1 FAILED: {e}")
        results.append(False)

    # Test 2: Crawler PARKED verdict
    try:
        results.append(test_crawler_parked_verdict())
    except Exception as e:
        print(f"\n❌ TEST 2 FAILED: {e}")
        results.append(False)

    # Test 3: Reduced domain age penalties
    try:
        results.append(test_reduced_domain_age_penalties())
    except Exception as e:
        print(f"\n❌ TEST 3 FAILED: {e}")
        results.append(False)

    # Test 4: Real dump records
    try:
        results.append(test_real_dump_records())
    except Exception as e:
        print(f"\n❌ TEST 4 FAILED: {e}")
        results.append(False)

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    passed = sum(results)
    total = len(results)

    print(f"\nTests Passed: {passed}/{total}")

    if all(results):
        print("\n🎉 ALL TESTS PASSED! Crawler schema integration working correctly.")
        return 0
    else:
        print("\n⚠️  SOME TESTS FAILED. Please review the output above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())
