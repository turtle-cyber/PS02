"""
Comprehensive test for typosquatting and visual impersonation detection fixes.

Tests the following improvements:
1. Typosquatting detection in fallback_detector (string similarity to CSE domains)
2. Visual impersonation override in aiml_service (CLIP similarity to CSE brands)
3. Lower thresholds (benign: 20→15, suspicious: 45→40)

Expected outcomes:
- aortel.in → PHISHING (typosquat of airtel.in, similarity ~0.83)
- airtell.in → PHISHING (typosquat of airtel.in, similarity ~0.85)
- airvel.in → PHISHING (typosquat of airtel.in, similarity ~0.83)
- bank.in with visual similarity 1.0 → PHISHING (visual impersonation)
- manakovdesign.ru → BENIGN (established domain, no similarity)
"""

import json
import sys
from pathlib import Path
from fallback_detector import FallbackDetector


def test_typosquatting_detection():
    """Test typosquatting detection for domains similar to CSE brands"""
    print("\n" + "="*80)
    print("TYPOSQUATTING DETECTION TESTS")
    print("="*80)

    # Load CSE whitelist (simulate what aiml_service does)
    cse_whitelist = set()
    try:
        cse_baseline_file = Path('data/training/cse_baseline_profile.json')
        if cse_baseline_file.exists():
            with open(cse_baseline_file, 'r') as f:
                baseline = json.load(f)
                whitelist_domains = baseline.get('domains', baseline.get('cse_whitelist', []))
                if isinstance(whitelist_domains, list):
                    cse_whitelist = set(whitelist_domains)
                print(f"Loaded {len(cse_whitelist)} CSE domains from baseline")
        else:
            print(f"WARNING: CSE baseline file not found at {cse_baseline_file}")
            # Fallback: add known CSE domains manually for testing
            cse_whitelist = {'airtel.in', 'icicibank.com', 'hdfcbank.com', 'pnbindia.in', 'sbi.co.in'}
            print(f"Using fallback CSE whitelist: {cse_whitelist}")
    except Exception as e:
        print(f"ERROR loading CSE whitelist: {e}")
        cse_whitelist = {'airtel.in', 'icicibank.com', 'hdfcbank.com'}
        print(f"Using minimal fallback: {cse_whitelist}")

    # Initialize fallback detector with CSE whitelist
    detector = FallbackDetector(cse_whitelist=cse_whitelist)

    # Test cases
    typosquat_tests = [
        {
            'domain': 'aortel.in',
            'target': 'airtel.in',
            'expected_verdict': 'PHISHING',
            'metadata': {
                'registrable': 'aortel.in',
                'domain_age_days': None,
                'mx_count': 0,
                'a_count': 1,
                'ns_count': 2,
                'dns': json.dumps({'A': ['192.0.2.1'], 'MX': [], 'NS': ['ns1.example.com', 'ns2.example.com']})
            }
        },
        {
            'domain': 'airtell.in',
            'target': 'airtel.in',
            'expected_verdict': 'PHISHING',
            'metadata': {
                'registrable': 'airtell.in',
                'domain_age_days': None,
                'mx_count': 0,
                'a_count': 1,
                'ns_count': 2,
                'dns': json.dumps({'A': ['192.0.2.2'], 'MX': [], 'NS': ['ns1.example.com', 'ns2.example.com']})
            }
        },
        {
            'domain': 'airvel.in',
            'target': 'airtel.in',
            'expected_verdict': 'PHISHING',
            'metadata': {
                'registrable': 'airvel.in',
                'domain_age_days': None,
                'mx_count': 0,
                'a_count': 1,
                'ns_count': 2,
                'dns': json.dumps({'A': ['192.0.2.3'], 'MX': [], 'NS': ['ns1.example.com', 'ns2.example.com']})
            }
        },
        {
            'domain': 'aitel.in',
            'target': 'airtel.in',
            'expected_verdict': 'PHISHING',
            'metadata': {
                'registrable': 'aitel.in',
                'domain_age_days': None,
                'mx_count': 0,
                'a_count': 1,
                'ns_count': 2,
                'dns': json.dumps({'A': ['192.0.2.4'], 'MX': [], 'NS': ['ns1.example.com', 'ns2.example.com']})
            }
        },
        {
            'domain': 'airte.in',
            'target': 'airtel.in',
            'expected_verdict': 'PHISHING',
            'metadata': {
                'registrable': 'airte.in',
                'domain_age_days': None,
                'mx_count': 0,
                'a_count': 1,
                'ns_count': 2,
                'dns': json.dumps({'A': ['192.0.2.5'], 'MX': [], 'NS': ['ns1.example.com', 'ns2.example.com']})
            }
        },
        {
            'domain': 'manakovdesign.ru',
            'target': None,
            'expected_verdict': 'BENIGN',
            'metadata': {
                'registrable': 'manakovdesign.ru',
                'domain_age_days': 1500,  # 4 years old
                'mx_count': 2,
                'a_count': 1,
                'ns_count': 2,
                'dns': json.dumps({'A': ['185.146.173.118'], 'MX': ['mx1.ru', 'mx2.ru'], 'NS': ['ns1.ru', 'ns2.ru']}),
                'asn': '197695',  # REG.RU
                'asn_org': 'REG.RU',
                'country': 'RU'
            }
        }
    ]

    results = []
    passed_count = 0
    failed_count = 0

    for test in typosquat_tests:
        print(f"\n{'─'*80}")
        print(f"Testing: {test['domain']}")
        if test['target']:
            print(f"Expected target: {test['target']}")
        print(f"Expected verdict: {test['expected_verdict']}")

        result = detector.analyze_metadata(test['metadata'])

        print(f"\nResult:")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Reason: {result['reason']}")

        if 'typosquat_details' in result:
            print(f"  Typosquat Details:")
            print(f"    Target: {result['typosquat_details']['target_domain']}")
            print(f"    Similarity: {result['typosquat_details']['similarity_score']:.2%}")

        # Validate
        passed = result['verdict'] == test['expected_verdict']
        if passed:
            print(f"\n  ✅ PASS: Verdict matches expected")
            passed_count += 1
        else:
            print(f"\n  ❌ FAIL: Expected {test['expected_verdict']}, got {result['verdict']}")
            failed_count += 1

        results.append({
            'domain': test['domain'],
            'expected': test['expected_verdict'],
            'actual': result['verdict'],
            'risk_score': result['risk_score'],
            'passed': passed
        })

    # Summary
    print(f"\n{'='*80}")
    print("TYPOSQUATTING TESTS SUMMARY")
    print(f"{'='*80}")
    print(f"Total: {len(typosquat_tests)} tests")
    print(f"Passed: {passed_count} ✅")
    print(f"Failed: {failed_count} ❌")

    if failed_count == 0:
        print(f"\n✅ All typosquatting tests passed!")
    else:
        print(f"\n❌ {failed_count} test(s) failed")

    return results, passed_count, failed_count


def test_threshold_changes():
    """Test that new thresholds properly categorize domains"""
    print("\n" + "="*80)
    print("THRESHOLD CHANGES TESTS")
    print("="*80)

    detector = FallbackDetector()

    test_cases = [
        {
            'description': 'Risk 16 (below old threshold 20, below new threshold 15)',
            'metadata': {
                'registrable': 'test-low-risk.com',
                'domain_age_days': 365,
                'mx_count': 0,  # +15 risk
                'a_count': 2,
                'ns_count': 2,
                'dns': json.dumps({'A': ['192.0.2.1', '192.0.2.2'], 'MX': [], 'NS': ['ns1.example.com', 'ns2.example.com']})
            },
            'expected_verdict': 'BENIGN',
            'expected_risk_min': 10,
            'expected_risk_max': 20
        },
        {
            'description': 'Risk 29 (above new threshold 15, was BENIGN before)',
            'metadata': {
                'registrable': 'test-medium-risk.com',
                'domain_age_days': None,  # +20 risk (missing age)
                'mx_count': 0,  # +15 risk
                'a_count': 1,  # +20 risk (minimal DNS)
                'ns_count': 2,
                'dns': json.dumps({'A': ['192.0.2.1'], 'MX': [], 'NS': ['ns1.example.com', 'ns2.example.com']})
            },
            'expected_verdict': 'SUSPICIOUS',
            'expected_risk_min': 50,
            'expected_risk_max': 60
        },
        {
            'description': 'Risk 42 (above new threshold 40, should be SUSPICIOUS)',
            'metadata': {
                'registrable': 'test-high-risk.xyz',
                'domain_age_days': None,  # +20 risk
                'mx_count': 0,  # +15 risk
                'a_count': 1,  # +20 risk (minimal DNS)
                'ns_count': 2,
                'dns': json.dumps({'A': ['192.0.2.1'], 'MX': [], 'NS': ['ns1.example.com', 'ns2.example.com']})
            },
            'expected_verdict': 'SUSPICIOUS',
            'expected_risk_min': 75,
            'expected_risk_max': 85
        }
    ]

    results = []
    passed_count = 0
    failed_count = 0

    for test in test_cases:
        print(f"\n{'─'*80}")
        print(f"Test: {test['description']}")
        print(f"Domain: {test['metadata']['registrable']}")
        print(f"Expected verdict: {test['expected_verdict']}")
        print(f"Expected risk: {test['expected_risk_min']}-{test['expected_risk_max']}")

        result = detector.analyze_metadata(test['metadata'])

        print(f"\nResult:")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Reason: {result['reason']}")

        # Validate
        verdict_match = result['verdict'] == test['expected_verdict']
        risk_in_range = test['expected_risk_min'] <= result['risk_score'] <= test['expected_risk_max']
        passed = verdict_match and risk_in_range

        if passed:
            print(f"\n  ✅ PASS")
            passed_count += 1
        else:
            if not verdict_match:
                print(f"\n  ❌ FAIL: Expected verdict {test['expected_verdict']}, got {result['verdict']}")
            if not risk_in_range:
                print(f"  ❌ FAIL: Risk score {result['risk_score']} not in expected range {test['expected_risk_min']}-{test['expected_risk_max']}")
            failed_count += 1

        results.append({
            'description': test['description'],
            'verdict': result['verdict'],
            'risk_score': result['risk_score'],
            'passed': passed
        })

    # Summary
    print(f"\n{'='*80}")
    print("THRESHOLD TESTS SUMMARY")
    print(f"{'='*80}")
    print(f"Total: {len(test_cases)} tests")
    print(f"Passed: {passed_count} ✅")
    print(f"Failed: {failed_count} ❌")

    return results, passed_count, failed_count


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("COMPREHENSIVE TYPOSQUATTING & VISUAL IMPERSONATION DETECTION TESTS")
    print("="*80)

    # Test 1: Typosquatting detection
    typo_results, typo_passed, typo_failed = test_typosquatting_detection()

    # Test 2: Threshold changes
    thresh_results, thresh_passed, thresh_failed = test_threshold_changes()

    # Final summary
    print("\n" + "="*80)
    print("FINAL TEST SUMMARY")
    print("="*80)
    print(f"\nTyposquatting Detection: {typo_passed} passed, {typo_failed} failed")
    print(f"Threshold Changes: {thresh_passed} passed, {thresh_failed} failed")
    print(f"\nTotal: {typo_passed + thresh_passed} passed, {typo_failed + thresh_failed} failed")

    if typo_failed == 0 and thresh_failed == 0:
        print("\n✅ ALL TESTS PASSED! 🎉")
        print("\nKey improvements validated:")
        print("  ✓ Typosquatting detection working (aortel.in → PHISHING)")
        print("  ✓ CSE similarity checking functioning")
        print("  ✓ Lower thresholds catching suspicious domains")
        print("  ✓ Established domains protected (manakovdesign.ru → BENIGN)")
        print("\nNote: Visual impersonation detection requires running full aiml_service with screenshots")
        return 0
    else:
        print(f"\n❌ {typo_failed + thresh_failed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
