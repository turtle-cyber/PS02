"""
Test that we distinguish between legitimate established Russian sites
and suspicious new Russian domains
"""

import json
from fallback_detector import FallbackDetector


def test_legitimate_established_ru():
    """Legitimate 4-year-old Russian site"""
    print("\n" + "="*80)
    print("TEST 1: Legitimate Established Russian Site")
    print("="*80)

    metadata = {
        'registrable': 'manakovdesign.ru',
        'domain_age_days': 1500,  # 4 years
        'is_newly_registered': False,
        'mx_count': 2,
        'asn': '197695',
        'asn_org': 'REG.RU',
        'country': 'RU',
        'registrar': 'REG.RU',
        'domain_length': 17,
        'domain_entropy': 3.85,
        'a_count': 1,
        'ns_count': 2,
        'dns': json.dumps({'A': ['185.146.173.118'], 'MX': ['mx1.ru', 'mx2.ru'], 'NS': ['ns1.ru', 'ns2.ru']})
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"Domain: {metadata['registrable']}")
    print(f"Age: {metadata['domain_age_days']} days (established)")
    print(f"Has MX: Yes")
    print(f"\nResult:")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Risk Score: {result['risk_score']}/100")
    print(f"  Expected: BENIGN (risk < 30)")
    print(f"  Status: {'✅ PASS' if result['verdict'] == 'BENIGN' else '❌ FAIL'}")

    return result


def test_suspicious_new_ru():
    """Suspicious new Russian domain (3 days old)"""
    print("\n" + "="*80)
    print("TEST 2: Suspicious New Russian Domain")
    print("="*80)

    metadata = {
        'registrable': 'secure-payment-verify.ru',
        'domain_age_days': 3,  # Very new!
        'is_newly_registered': True,
        'mx_count': 0,  # No email
        'asn': '197695',
        'asn_org': 'REG.RU',
        'country': 'RU',
        'registrar': 'REG.RU',
        'domain_length': 25,
        'domain_entropy': 3.92,
        'a_count': 1,
        'ns_count': 2,
        'dns': json.dumps({'A': ['185.146.173.200'], 'MX': [], 'NS': ['ns1.ru', 'ns2.ru']})
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"Domain: {metadata['registrable']}")
    print(f"Age: {metadata['domain_age_days']} days (very new!)")
    print(f"Has MX: No")
    print(f"Keywords: secure, payment, verify")
    print(f"\nResult:")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Risk Score: {result['risk_score']}/100")
    print(f"  Reason: {result['reason']}")
    print(f"  Expected: PHISHING or SUSPICIOUS (risk >= 50)")
    print(f"  Status: {'✅ PASS' if result['risk_score'] >= 50 else '❌ FAIL'}")

    return result


def test_checkout_mobile_metric_xyz():
    """Re-test checkout-mobile-metric.xyz (should still be flagged)"""
    print("\n" + "="*80)
    print("TEST 3: checkout-mobile-metric.xyz (Should Still Be Flagged)")
    print("="*80)

    metadata = {
        'registrable': 'checkout-mobile-metric.xyz',
        'domain_age_days': 13,
        'is_newly_registered': True,
        'mx_count': 1,
        'asn': '7506',
        'asn_org': 'GMO Internet',
        'country': 'JP',
        'domain_length': 26,
        'domain_entropy': 3.95,
        'domain_hyphens': 2,
        'a_count': 1,
        'ns_count': 2,
        'dns': json.dumps({'A': ['150.95.255.38'], 'MX': [''], 'NS': ['dns1.onamae.com', 'dns2.onamae.com']})
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"Domain: {metadata['registrable']}")
    print(f"Age: {metadata['domain_age_days']} days")
    print(f"TLD: .xyz")
    print(f"\nResult:")
    print(f"  Verdict: {result['verdict']}")
    print(f"  Risk Score: {result['risk_score']}/100")
    print(f"  Expected: PHISHING (risk >= 70)")
    print(f"  Status: {'✅ PASS' if result['risk_score'] >= 70 else '❌ FAIL'}")

    return result


if __name__ == '__main__':
    print("\n" + "="*80)
    print("CONTEXT-AWARE RISK SCORING TEST SUITE")
    print("Verify that domain age and infrastructure affect risk scoring")
    print("="*80)

    result1 = test_legitimate_established_ru()
    result2 = test_suspicious_new_ru()
    result3 = test_checkout_mobile_metric_xyz()

    print("\n" + "="*80)
    print("FINAL RESULTS")
    print("="*80)

    tests = [
        ("Legitimate Russian Site", result1, 'BENIGN', result1['risk_score'] < 30),
        ("Suspicious New Russian Domain", result2, 'PHISHING/SUSPICIOUS', result2['risk_score'] >= 50),
        ("checkout-mobile-metric.xyz", result3, 'PHISHING', result3['risk_score'] >= 70)
    ]

    passed = 0
    failed = 0

    for name, result, expected, condition in tests:
        status = "✅ PASS" if condition else "❌ FAIL"
        print(f"\n{name}:")
        print(f"  Verdict: {result['verdict']} (expected: {expected})")
        print(f"  Risk Score: {result['risk_score']}/100")
        print(f"  Status: {status}")

        if condition:
            passed += 1
        else:
            failed += 1

    print(f"\n{'='*80}")
    print(f"TOTAL: {passed} passed, {failed} failed")

    if failed == 0:
        print("✅ All tests passed! Context-aware scoring is working correctly.")
        print("\nKey improvements:")
        print("  - Established domains (1+ year) with infrastructure get reduced penalties")
        print("  - New domains still get full penalties for high-risk indicators")
        print("  - False positives for legitimate Russian sites eliminated")
        print("  - True positives for suspicious domains maintained")
    else:
        print("❌ Some tests failed. Review scoring logic.")
