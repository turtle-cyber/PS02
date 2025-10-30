"""
Comprehensive test to validate fixes for BENIGN misclassification issues.

Tests the following improvements:
1. Missing domain_age_days handling (+20 risk penalty)
2. Increased DNS penalties (MX: 10→15, minimal: 15→20)
3. Lower thresholds (benign: 30→20, suspicious: 50→45)
4. High-risk e-commerce TLDs (.shop, .store added)
5. Early-exit checks for PARKED, INACTIVE, CSE whitelist
6. Context-aware scoring for established domains

Expected outcomes:
- beadedbylissi.shop: BENIGN (risk 27) → SUSPICIOUS (risk ~60)
- tugcelistore.com: BENIGN (risk 27) → SUSPICIOUS (risk ~42)
- angelsbreathboutique.shop: BENIGN (risk 5) → BENIGN (risk ~30)
- Parking domains → PARKED verdict
- No A records → INACTIVE verdict
"""

import json
from fallback_detector import FallbackDetector


def test_beadedbylissi_shop():
    """
    Original: BENIGN, risk_score 27
    Expected: SUSPICIOUS, risk_score ~60
    Changes: +20 (missing age) +5 (MX penalty increase) +5 (DNS penalty increase) +25 (.shop TLD)
    """
    print("\n" + "="*80)
    print("TEST 1: beadedbylissi.shop (E-commerce domain with missing age)")
    print("="*80)

    metadata = {
        'registrable': 'beadedbylissi.shop',
        'domain_age_days': None,  # Missing age data
        'is_newly_registered': False,
        'mx_count': 0,  # No email
        'a_count': 1,
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['192.0.2.1'],
            'MX': [],
            'NS': ['ns1.example.com', 'ns2.example.com']
        }),
        'asn': '12345',
        'asn_org': 'Generic Hosting',
        'country': 'US',
        'registrar': 'Generic Registrar',
        'domain_length': 20,
        'domain_entropy': 3.5
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Original: BENIGN (risk 27)")
    print(f"Current:  {result['verdict']} (risk {result['risk_score']})")
    print(f"Confidence: {result['confidence']}")
    print(f"Reason: {result['reason']}")
    print(f"\nExpected: SUSPICIOUS (risk ~60)")

    # Validate
    expected_min_risk = 55
    expected_verdicts = ['SUSPICIOUS', 'LIKELY_PHISHING', 'PHISHING']  # Better than BENIGN!
    passed = result['risk_score'] >= expected_min_risk and result['verdict'] in expected_verdicts

    print(f"\nValidation:")
    print(f"  Risk >= {expected_min_risk}: {result['risk_score'] >= expected_min_risk} (actual: {result['risk_score']})")
    print(f"  Verdict in {expected_verdicts}: {result['verdict'] in expected_verdicts}")
    print(f"  Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result, passed


def test_tugcelistore_com():
    """
    Original: BENIGN, risk_score 27
    Expected: SUSPICIOUS, risk_score ~42
    Changes: +20 (missing age) +5 (MX penalty increase) +5 (DNS penalty increase)
    """
    print("\n" + "="*80)
    print("TEST 2: tugcelistore.com (Missing age, no email)")
    print("="*80)

    metadata = {
        'registrable': 'tugcelistore.com',
        'domain_age_days': None,  # Missing age data
        'is_newly_registered': False,
        'mx_count': 0,
        'a_count': 1,
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['192.0.2.2'],
            'MX': [],
            'NS': ['ns1.example.com', 'ns2.example.com']
        }),
        'asn': '12345',
        'asn_org': 'Generic Hosting',
        'country': 'US',
        'registrar': 'Generic Registrar',
        'domain_length': 17,
        'domain_entropy': 3.6
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Original: BENIGN (risk 27)")
    print(f"Current:  {result['verdict']} (risk {result['risk_score']})")
    print(f"Confidence: {result['confidence']}")
    print(f"Reason: {result['reason']}")
    print(f"\nExpected: SUSPICIOUS (risk ~42)")

    # Validate
    expected_min_risk = 40
    expected_verdicts = ['SUSPICIOUS', 'LIKELY_PHISHING', 'PHISHING']  # Better than BENIGN!
    passed = result['risk_score'] >= expected_min_risk and result['verdict'] in expected_verdicts

    print(f"\nValidation:")
    print(f"  Risk >= {expected_min_risk}: {result['risk_score'] >= expected_min_risk} (actual: {result['risk_score']})")
    print(f"  Verdict in {expected_verdicts}: {result['verdict'] in expected_verdicts}")
    print(f"  Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result, passed


def test_angelsbreathboutique_shop():
    """
    Original: BENIGN, risk_score 5
    Expected: BENIGN (risk ~30) - legitimate-looking with minimal risk factors
    Changes: +25 (.shop TLD) +5 (threshold lowered to 20)
    """
    print("\n" + "="*80)
    print("TEST 3: angelsbreathboutique.shop (Legitimate-looking e-commerce)")
    print("="*80)

    metadata = {
        'registrable': 'angelsbreathboutique.shop',
        'domain_age_days': 365,  # 1 year old
        'is_newly_registered': False,
        'mx_count': 2,  # Has email
        'a_count': 1,
        'ns_count': 4,
        'dns': json.dumps({
            'A': ['192.0.2.3'],
            'MX': ['mx1.example.com', 'mx2.example.com'],
            'NS': ['ns1.example.com', 'ns2.example.com', 'ns3.example.com', 'ns4.example.com']
        }),
        'asn': '12345',
        'asn_org': 'Generic Hosting',
        'country': 'US',
        'registrar': 'Generic Registrar',
        'domain_length': 26,
        'domain_entropy': 3.8
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Original: BENIGN (risk 5)")
    print(f"Current:  {result['verdict']} (risk {result['risk_score']})")
    print(f"Confidence: {result['confidence']}")
    print(f"Reason: {result['reason']}")
    print(f"\nExpected: BENIGN (risk ~30) - .shop TLD adds risk but has infrastructure")

    # Validate
    expected_max_risk = 35
    expected_verdict = 'BENIGN'
    passed = result['risk_score'] <= expected_max_risk and result['verdict'] == expected_verdict

    print(f"\nValidation:")
    print(f"  Risk <= {expected_max_risk}: {result['risk_score'] <= expected_max_risk} (actual: {result['risk_score']})")
    print(f"  Verdict == {expected_verdict}: {result['verdict'] == expected_verdict}")
    print(f"  Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result, passed


def test_parking_domain():
    """
    Original: BENIGN, risk_score 15
    Expected: PARKED verdict (early-exit check)
    """
    print("\n" + "="*80)
    print("TEST 4: Parked Domain Detection")
    print("="*80)

    metadata = {
        'registrable': 'parked-example.com',
        'domain_age_days': 30,
        'is_newly_registered': True,
        'mx_count': 0,
        'a_count': 2,
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['13.248.169.48', '76.223.54.146'],
            'MX': [],
            'NS': ['ns1.afternic.com', 'ns2.afternic.com']  # Parking nameserver
        }),
        'asn': '16509',
        'asn_org': 'AMAZON-02',
        'country': 'US',
        'registrar': 'Generic Registrar',
        'domain_length': 18,
        'domain_entropy': 3.5
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Nameservers: ns1.afternic.com, ns2.afternic.com")
    print(f"Current:  {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Reason: {result['reason']}")
    print(f"\nExpected: PARKED (early-exit detection)")

    # Validate
    expected_verdict = 'PARKED'
    passed = result['verdict'] == expected_verdict

    print(f"\nValidation:")
    print(f"  Verdict == {expected_verdict}: {result['verdict'] == expected_verdict}")
    print(f"  Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result, passed


def test_inactive_domain():
    """
    Original: Not tested
    Expected: INACTIVE verdict (no A records)
    """
    print("\n" + "="*80)
    print("TEST 5: Inactive Domain Detection (No A records)")
    print("="*80)

    metadata = {
        'registrable': 'forfeather.nl',
        'domain_age_days': None,
        'is_newly_registered': False,
        'mx_count': 1,
        'a_count': 0,  # No A records!
        'ns_count': 2,
        'dns': json.dumps({
            'A': [],  # No A records
            'MX': ['mx.example.com'],
            'NS': ['ns1.example.com', 'ns2.example.com']
        }),
        'asn': None,
        'asn_org': None,
        'country': None,
        'registrar': 'Generic Registrar',
        'domain_length': 13,
        'domain_entropy': 3.2
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"A records: 0 (no resolution)")
    print(f"Current:  {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Reason: {result['reason']}")
    print(f"\nExpected: INACTIVE (early-exit detection)")

    # Validate
    expected_verdict = 'INACTIVE'
    passed = result['verdict'] == expected_verdict

    print(f"\nValidation:")
    print(f"  Verdict == {expected_verdict}: {result['verdict'] == expected_verdict}")
    print(f"  Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result, passed


def test_cse_whitelist():
    """
    Test CSE whitelist protection (priority 1 early-exit)
    """
    print("\n" + "="*80)
    print("TEST 6: CSE Whitelist Protection")
    print("="*80)

    # Create detector with CSE whitelist
    cse_whitelist = {'google.com', 'microsoft.com', 'amazon.com'}
    detector = FallbackDetector(cse_whitelist=cse_whitelist)

    metadata = {
        'registrable': 'google.com',
        'domain_age_days': 5,  # Very new (should be high risk normally)
        'is_newly_registered': True,
        'mx_count': 0,
        'a_count': 1,
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['192.0.2.4'],
            'MX': [],
            'NS': ['ns1.example.com', 'ns2.example.com']
        }),
        'asn': '12345',
        'asn_org': 'Generic Hosting',
        'country': 'US',
        'registrar': 'Generic Registrar',
        'domain_length': 10,
        'domain_entropy': 2.8
    }

    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"CSE Whitelisted: Yes")
    print(f"Current:  {result['verdict']}")
    print(f"Confidence: {result['confidence']}")
    print(f"Reason: {result['reason']}")
    print(f"\nExpected: BENIGN (CSE whitelist overrides all risk factors)")

    # Validate
    expected_verdict = 'BENIGN'
    expected_confidence = 0.98
    passed = result['verdict'] == expected_verdict and result['confidence'] == expected_confidence

    print(f"\nValidation:")
    print(f"  Verdict == {expected_verdict}: {result['verdict'] == expected_verdict}")
    print(f"  Confidence == {expected_confidence}: {result['confidence'] == expected_confidence}")
    print(f"  Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result, passed


def test_established_russian_domain():
    """
    Test context-aware scoring for established domains
    manakovdesign.ru should NOT be marked PHISHING (false positive fix)
    """
    print("\n" + "="*80)
    print("TEST 7: Established Russian Domain (Context-Aware Scoring)")
    print("="*80)

    metadata = {
        'registrable': 'manakovdesign.ru',
        'domain_age_days': 1500,  # 4 years old
        'is_newly_registered': False,
        'mx_count': 2,  # Has email infrastructure
        'a_count': 1,
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['185.146.173.118'],
            'MX': ['mx1.ru', 'mx2.ru'],
            'NS': ['ns1.ru', 'ns2.ru']
        }),
        'asn': '197695',  # REG.RU (high-risk ASN)
        'asn_org': 'REG.RU',
        'country': 'RU',  # High-risk country
        'registrar': 'REG.RU',
        'domain_length': 17,
        'domain_entropy': 3.85
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Age: {metadata['domain_age_days']} days (4 years - established)")
    print(f"Infrastructure: 2 MX records, 1 A record, 2 NS records")
    print(f"Current:  {result['verdict']} (risk {result['risk_score']})")
    print(f"Confidence: {result['confidence']}")
    print(f"Reason: {result['reason']}")
    print(f"\nExpected: BENIGN (context-aware scoring reduces RU penalties)")

    # Validate
    expected_verdict = 'BENIGN'
    expected_max_risk = 25
    passed = result['verdict'] == expected_verdict and result['risk_score'] <= expected_max_risk

    print(f"\nValidation:")
    print(f"  Verdict == {expected_verdict}: {result['verdict'] == expected_verdict}")
    print(f"  Risk <= {expected_max_risk}: {result['risk_score'] <= expected_max_risk} (actual: {result['risk_score']})")
    print(f"  Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result, passed


def test_new_russian_phishing():
    """
    Test that NEW Russian domains still get flagged (context-aware should NOT apply)
    """
    print("\n" + "="*80)
    print("TEST 8: New Russian Phishing Domain (Full Penalties)")
    print("="*80)

    metadata = {
        'registrable': 'secure-payment-verify.ru',
        'domain_age_days': 3,  # Very new!
        'is_newly_registered': True,
        'mx_count': 0,  # No email
        'a_count': 1,
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['185.146.173.200'],
            'MX': [],
            'NS': ['ns1.ru', 'ns2.ru']
        }),
        'asn': '197695',  # REG.RU (high-risk ASN)
        'asn_org': 'REG.RU',
        'country': 'RU',  # High-risk country
        'registrar': 'REG.RU',
        'domain_length': 25,
        'domain_entropy': 3.92
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\nDomain: {result['domain']}")
    print(f"Age: {metadata['domain_age_days']} days (very new!)")
    print(f"Infrastructure: No MX, minimal DNS")
    print(f"Current:  {result['verdict']} (risk {result['risk_score']})")
    print(f"Confidence: {result['confidence']}")
    print(f"Reason: {result['reason']}")
    print(f"\nExpected: PHISHING (risk >= 70) - new domains get full penalties")

    # Validate
    expected_min_risk = 70
    expected_verdict_options = ['PHISHING', 'LIKELY_PHISHING']
    passed = result['risk_score'] >= expected_min_risk and result['verdict'] in expected_verdict_options

    print(f"\nValidation:")
    print(f"  Risk >= {expected_min_risk}: {result['risk_score'] >= expected_min_risk} (actual: {result['risk_score']})")
    print(f"  Verdict in {expected_verdict_options}: {result['verdict'] in expected_verdict_options}")
    print(f"  Status: {'✅ PASS' if passed else '❌ FAIL'}")

    return result, passed


def main():
    """Run all comprehensive tests"""
    print("\n" + "="*80)
    print("COMPREHENSIVE FALLBACK DETECTOR VALIDATION TEST SUITE")
    print("Testing fixes for BENIGN misclassification issues")
    print("="*80)

    tests = [
        ("beadedbylissi.shop (missing age + .shop TLD)", test_beadedbylissi_shop),
        ("tugcelistore.com (missing age, no email)", test_tugcelistore_com),
        ("angelsbreathboutique.shop (legitimate e-commerce)", test_angelsbreathboutique_shop),
        ("Parked domain detection", test_parking_domain),
        ("Inactive domain detection (no A records)", test_inactive_domain),
        ("CSE whitelist protection", test_cse_whitelist),
        ("Established Russian domain (context-aware)", test_established_russian_domain),
        ("New Russian phishing domain (full penalties)", test_new_russian_phishing),
    ]

    results = []
    passed_count = 0
    failed_count = 0

    for test_name, test_func in tests:
        result, passed = test_func()
        results.append((test_name, result, passed))
        if passed:
            passed_count += 1
        else:
            failed_count += 1

    # Final summary
    print("\n" + "="*80)
    print("FINAL TEST SUMMARY")
    print("="*80)

    for test_name, result, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"\n{test_name}:")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Risk Score: {result['risk_score']}/100")
        print(f"  Status: {status}")

    print(f"\n{'='*80}")
    print(f"TOTAL: {passed_count} passed, {failed_count} failed out of {len(tests)} tests")

    if failed_count == 0:
        print("\n✅ All tests passed! Fixes are working correctly.")
        print("\nKey improvements validated:")
        print("  ✓ Missing domain age handled (+20 risk penalty)")
        print("  ✓ Increased DNS penalties (MX: 10→15, minimal: 15→20)")
        print("  ✓ Lower thresholds (benign: 30→20, suspicious: 50→45)")
        print("  ✓ High-risk e-commerce TLDs (.shop, .store) detected")
        print("  ✓ Early-exit checks for PARKED, INACTIVE, CSE whitelist working")
        print("  ✓ Context-aware scoring protects established domains")
        print("  ✓ New suspicious domains still get full penalties")
    else:
        print(f"\n❌ {failed_count} test(s) failed. Review the output above for details.")

    return results, passed_count, failed_count


if __name__ == '__main__':
    import sys
    try:
        results, passed, failed = main()
        sys.exit(0 if failed == 0 else 1)
    except Exception as e:
        print(f"\n❌ Test suite crashed with exception: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
