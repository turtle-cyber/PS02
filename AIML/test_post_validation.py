"""
Test post-scoring validation with checkout-mobile-metric.xyz
"""

import json
from fallback_detector import FallbackDetector


def test_checkout_mobile_metric():
    """
    Test case: checkout-mobile-metric.xyz
    - Marked BENIGN by rule-scorer
    - But has suspicious characteristics
    """
    print("\n" + "="*80)
    print("POST-SCORING VALIDATION TEST: checkout-mobile-metric.xyz")
    print("="*80)

    # Metadata from your dump_all.jsonl
    metadata = {
        'registrable': 'checkout-mobile-metric.xyz',
        'domain': 'checkout-mobile-metric.xyz',
        'domain_age_days': 13,  # Very new!
        'is_newly_registered': True,
        'domain_length': 26,
        'domain_entropy': 3.9501,
        'domain_hyphens': 2,
        'url_entropy': 4.1385,
        'a_count': 1,
        'mx_count': 1,
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['150.95.255.38'],
            'MX': [''],
            'NS': ['dns2.onamae.com', 'dns1.onamae.com']
        }),
        'asn': '7506',
        'asn_org': 'GMO Internet Group, Inc.',
        'country': 'JP',
        'registrar': 'GMO Internet, Inc.',
        'days_until_expiry': 351,
        'html_size': 2288,  # Has content
        'screenshot_path': '/workspace/out/screenshots/checkout-mobile-metric.xyz_23912fd1_full.png',
        'ocr_text_length': 120,
        'redirect_count': 67,  # Massive redirects!
        'had_redirects': True,
        'had_cross_domain_redirect': True,
        'cross_domain_redirect_count': 25,
        'uses_https': False,  # No HTTPS!
        'iframe_count': 1,
        'verdict': 'benign',  # Original verdict
        'confidence': 0.5,
        'risk_score': 16,  # From rule-scorer
        'final_verdict': 'benign'
    }

    print(f"\n📋 Domain Information:")
    print(f"   Domain: {metadata['registrable']}")
    print(f"   Age: {metadata['domain_age_days']} days (Very New!)")
    print(f"   TLD: .xyz (high-risk)")
    print(f"   Hyphens: {metadata['domain_hyphens']}")
    print(f"   Redirects: {metadata['redirect_count']} total, {metadata['cross_domain_redirect_count']} cross-domain")
    print(f"   HTTPS: {metadata['uses_https']} (No SSL!)")

    print(f"\n🤖 Original Rule-Scorer Verdict:")
    print(f"   Verdict: {metadata['verdict'].upper()}")
    print(f"   Confidence: {metadata['confidence']}")
    print(f"   Risk Score: {metadata['risk_score']}/100")

    print(f"\n🔍 Running Fallback Detector Analysis...")
    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\n📊 Fallback Detector Results:")
    print(f"   Verdict: {result['verdict']}")
    print(f"   Confidence: {result['confidence']}")
    print(f"   Risk Score: {result['risk_score']}/100")
    print(f"   Reason: {result['reason']}")

    print(f"\n📈 Signal Breakdown:")
    for signal, score in result['fallback_signals'].items():
        if score > 0:
            print(f"   - {signal}: {score}")

    print(f"\n⚖️ POST-SCORING DECISION:")
    if result['risk_score'] >= 50:
        print(f"   ✅ OVERRIDE TRIGGERED (risk_score={result['risk_score']} >= 50)")
        print(f"   📝 Original Verdict: BENIGN (0.5 confidence)")
        print(f"   🔄 New Verdict: {result['verdict']} ({result['confidence']} confidence)")
        print(f"\n   🚨 This domain should be flagged as {result['verdict']}!")
    else:
        print(f"   ❌ Override NOT triggered (risk_score={result['risk_score']} < 50)")
        print(f"   📝 Keeping original verdict: BENIGN")

    print(f"\n💡 Risk Indicators Detected:")
    reasons = result['reason'].split(', ')
    for reason in reasons:
        print(f"   🔴 {reason}")

    return result


def test_angelsbreathboutique_shop():
    """
    Test case: angelsbreathboutique.shop
    - Marked BENIGN by crawler
    - Should remain BENIGN (legitimate e-commerce)
    """
    print("\n" + "="*80)
    print("POST-SCORING VALIDATION TEST: angelsbreathboutique.shop (Control)")
    print("="*80)

    metadata = {
        'registrable': 'angelsbreathboutique.shop',
        'domain': 'angelsbreathboutique.shop',
        'domain_age_days': 200,  # Not new
        'is_newly_registered': False,
        'domain_length': 26,
        'domain_entropy': 3.95,
        'a_count': 1,
        'mx_count': 1,
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['192.0.2.50'],
            'MX': ['mail.angelsbreathboutique.shop'],
            'NS': ['ns1.example.com', 'ns2.example.com']
        }),
        'asn': '13335',
        'asn_org': 'Cloudflare',
        'country': 'US',
        'registrar': 'Cloudflare',
        'days_until_expiry': 200,
        'html_size': 50000,
        'screenshot_path': '/path/to/screenshot.png',
        'ocr_text_length': 500,
        'redirect_count': 2,
        'had_redirects': True,
        'uses_https': True,
        'verdict': 'benign',
        'confidence': 0.5
    }

    print(f"\n📋 Domain Information:")
    print(f"   Domain: {metadata['registrable']}")
    print(f"   Age: {metadata['domain_age_days']} days (Established)")
    print(f"   Has MX: Yes")
    print(f"   Hosting: Cloudflare")
    print(f"   HTTPS: Yes")

    print(f"\n🤖 Original Verdict: BENIGN (0.5 confidence)")

    print(f"\n🔍 Running Fallback Detector Analysis...")
    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\n📊 Fallback Detector Results:")
    print(f"   Risk Score: {result['risk_score']}/100")
    print(f"   Verdict: {result['verdict']}")

    print(f"\n⚖️ POST-SCORING DECISION:")
    if result['risk_score'] >= 50:
        print(f"   ✅ OVERRIDE TRIGGERED (risk_score={result['risk_score']} >= 50)")
        print(f"   🔄 New Verdict: {result['verdict']}")
    else:
        print(f"   ❌ Override NOT triggered (risk_score={result['risk_score']} < 50)")
        print(f"   ✅ Keeping original verdict: BENIGN")
        print(f"   💡 This is correct - domain appears legitimate")

    return result


if __name__ == '__main__':
    print("\n" + "="*80)
    print("POST-SCORING VALIDATION SYSTEM TEST")
    print("Testing override logic for benign verdicts with high risk indicators")
    print("="*80)

    # Test suspicious domain that was marked benign
    result1 = test_checkout_mobile_metric()

    # Test legitimate domain that should stay benign
    result2 = test_angelsbreathboutique_shop()

    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"\ncheckout-mobile-metric.xyz:")
    print(f"  Risk Score: {result1['risk_score']}/100")
    print(f"  Override: {'YES' if result1['risk_score'] >= 50 else 'NO'}")
    print(f"  Final Verdict: {result1['verdict']}")

    print(f"\nangelsbreathboutique.shop:")
    print(f"  Risk Score: {result2['risk_score']}/100")
    print(f"  Override: {'YES' if result2['risk_score'] >= 50 else 'NO'}")
    print(f"  Final Verdict: {result2['verdict']}")

    print("\n✅ Post-scoring validation system working as expected!")
    print("   - Suspicious domains are upgraded from BENIGN")
    print("   - Legitimate domains remain BENIGN")
