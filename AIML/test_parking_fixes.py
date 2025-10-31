#!/usr/bin/env python3
"""
Test script to verify parking detection fixes for airnote.eu and sibi.hamburg
"""

import json
import sys
from fallback_detector import FallbackDetector

def test_airnote_eu():
    """Test airnote.eu - SEDO parking with yoursrs.com nameservers"""
    print("=" * 80)
    print("TEST 1: airnote.eu (SEDO parking with yoursrs.com nameservers)")
    print("=" * 80)

    metadata = {
        'registrable': 'airnote.eu',
        'domain': 'airnote.eu',
        'asn': '47846',
        'asn_org': 'SEDO GmbH',
        'dns': json.dumps({
            'A': ['91.195.241.239'],
            'NS': ['eu-sedo-ns1.yoursrs.com', 'eu-sedo-ns2.yoursrs.com'],
            'MX': ['']
        }),
        'a_count': 1,
        'mx_count': 1,
        'ns_count': 2,
        'registrar': 'Realtime Register B.V.',
        'country': 'DE',
        'rdap': json.dumps({
            'remarks': [{
                'description': 'Sedo Domain Parking\nIm Mediapark 6b\n50670 Koeln'
            }]
        }),
        'html_size': 0,
        'screenshot_path': None,
        'ocr_text_length': 0,
        'document_text': 'buy this domain for sale',  # Simulated parking content
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Reason: {result['reason']}")
    print(f"Source: {result['source']}")
    print(f"Data Availability: {result['data_availability']}")

    # Validation
    expected_verdict = 'PARKED'
    if result['verdict'] == expected_verdict:
        print(f"\n✅ TEST PASSED: airnote.eu correctly detected as {expected_verdict}")
        print(f"   Detection method: {result['source']}")
        return True
    else:
        print(f"\n❌ TEST FAILED: Expected {expected_verdict}, got {result['verdict']}")
        return False


def test_sibi_hamburg():
    """Test sibi.hamburg - IONOS parking with sedoparking.com redirect"""
    print("\n" + "=" * 80)
    print("TEST 2: sibi.hamburg (IONOS + sedoparking.com redirect)")
    print("=" * 80)

    metadata = {
        'registrable': 'sibi.hamburg',
        'domain': 'sibi.hamburg',
        'asn': '8560',
        'asn_org': 'IONOS SE',
        'dns': json.dumps({
            'A': ['217.160.122.187'],
            'NS': ['ns-de.1and1-dns.com', 'ns-de.1and1-dns.org', 'ns-de.1and1-dns.biz', 'ns-de.1and1-dns.de'],
            'MX': ['mx01.ionos.de', 'mx00.ionos.de']
        }),
        'a_count': 1,
        'mx_count': 2,
        'ns_count': 4,
        'registrar': '1&1 Internet AG',
        'country': 'DE',
        'redirect_chain': json.dumps([
            'http://sibi.hamburg/',
            'http://sibi.hamburg/defaultsite',
            'http://sedoparking.com/frmpark/sibi.hamburg/IONOSParkingDE/park.js',
            'http://pagead2.googlesyndication.com/apps/domainpark/show_afd_ads.js'
        ]),
        'html_size': 1910,
        'screenshot_path': '/workspace/out/screenshots/sibi.hamburg_2ef1770e_full.png',
        'ocr_text_length': 127,
        'ocr_text_excerpt': 'name has just been registered',
        'ocr': json.dumps({
            'text_excerpt': 'name has just been registered, Related searches'
        })
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Reason: {result['reason']}")
    print(f"Source: {result['source']}")
    print(f"Data Availability: {result['data_availability']}")

    # Validation
    expected_verdict = 'PARKED'
    if result['verdict'] == expected_verdict:
        print(f"\n✅ TEST PASSED: sibi.hamburg correctly detected as {expected_verdict}")
        print(f"   Detection method: {result['source']}")
        return True
    else:
        print(f"\n❌ TEST FAILED: Expected {expected_verdict}, got {result['verdict']}")
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 80)
    print("PARKING DETECTION FIX VALIDATION")
    print("Testing: airnote.eu + sibi.hamburg")
    print("=" * 80 + "\n")

    results = []

    # Test 1: airnote.eu
    results.append(test_airnote_eu())

    # Test 2: sibi.hamburg
    results.append(test_sibi_hamburg())

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    passed = sum(results)
    total = len(results)

    print(f"\nTests Passed: {passed}/{total}")

    if all(results):
        print("\n🎉 ALL TESTS PASSED! Parking detection fixes working correctly.")
        return 0
    else:
        print("\n⚠️  SOME TESTS FAILED. Please review the output above.")
        return 1


if __name__ == '__main__':
    sys.exit(main())
