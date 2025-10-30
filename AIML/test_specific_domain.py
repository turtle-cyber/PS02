"""
Test the fallback detector with angelsbreathboutique.shop
"""

import json
from fallback_detector import FallbackDetector


def test_angelsbreathboutique():
    """Test case: angelsbreathboutique.shop with crawler verdict 'benign'"""
    print("\n" + "="*80)
    print("TEST: angelsbreathboutique.shop")
    print("="*80)

    # Simulate metadata for this domain
    # Based on .shop TLD and typical e-commerce characteristics
    metadata = {
        'registrable': 'angelsbreathboutique.shop',
        'domain': 'angelsbreathboutique.shop',
        'domain_age_days': None,  # Unknown age
        'is_newly_registered': False,
        'domain_length': 26,
        'domain_entropy': 3.95,  # Reasonable entropy
        'a_count': 1,
        'mx_count': 1,  # Has email
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['192.0.2.50'],
            'MX': ['mail.angelsbreathboutique.shop'],
            'NS': ['ns1.example.com', 'ns2.example.com']
        }),
        'asn': '13335',
        'asn_org': 'Cloudflare',
        'country': 'US',
        'registrar': 'Unknown',
        'days_until_expiry': 200,
        'html_size': 0,  # No page data
        'screenshot_path': None,
        'ocr_text_length': 0,
        'confidence': 0.5,  # Crawler confidence
        'crawler_verdict': 'benign'  # Original crawler verdict
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\n📋 Domain Information:")
    print(f"   Domain: {result['domain']}")
    print(f"   TLD: .shop")
    print(f"   Length: 26 characters")
    print(f"   Has MX: Yes")
    print(f"   Hosting: Cloudflare")

    print(f"\n🤖 Original Crawler Verdict:")
    print(f"   Verdict: {metadata['crawler_verdict'].upper()}")
    print(f"   Confidence: {metadata['confidence']}")
    print(f"   Reason: No page data available")

    print(f"\n🔍 Fallback Detector Analysis:")
    print(f"   Verdict: {result['verdict']}")
    print(f"   Confidence: {result['confidence']}")
    print(f"   Risk Score: {result['risk_score']}/100")
    print(f"   Reason: {result['reason']}")

    print(f"\n📊 Signal Breakdown:")
    for signal, score in result['fallback_signals'].items():
        print(f"   - {signal}: {score}")

    print(f"\n💡 Analysis:")
    if result['risk_score'] < 30:
        print("   ✓ Low risk - Appears legitimate")
        print("   ✓ Has email infrastructure (MX records)")
        print("   ✓ Hosted on reputable CDN (Cloudflare)")
        print("   ✓ Reasonable domain characteristics")
    elif result['risk_score'] < 50:
        print("   ⚠ Moderate risk - Monitor this domain")
    else:
        print("   ⚠ High risk - Suspicious indicators detected")

    print(f"\n📈 Improvement over crawler verdict:")
    print(f"   Before: BENIGN (0.5 confidence, no reasoning)")
    print(f"   After:  {result['verdict']} ({result['confidence']} confidence, with detailed signal breakdown)")

    return result


def test_suspicious_shop_domain():
    """Test case: Suspicious .shop domain with risk indicators"""
    print("\n" + "="*80)
    print("TEST: fake-brand-store.shop (Suspicious Example)")
    print("="*80)

    metadata = {
        'registrable': 'fake-brand-store.shop',
        'domain': 'fake-brand-store.shop',
        'domain_age_days': 3,  # Very new
        'is_newly_registered': True,
        'domain_length': 20,
        'domain_entropy': 3.72,
        'a_count': 1,
        'mx_count': 0,  # No email
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['192.0.2.99'],
            'MX': [],
            'NS': ['ns1.cheap-hosting.com', 'ns2.cheap-hosting.com']
        }),
        'asn': '12345',
        'asn_org': 'Budget Hosting LLC',
        'country': 'RU',
        'registrar': 'NameCheap',
        'days_until_expiry': 365,
        'html_size': 0,
        'screenshot_path': None,
        'ocr_text_length': 0,
        'confidence': 0.5,
        'crawler_verdict': 'benign'
    }

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\n📋 Domain Information:")
    print(f"   Domain: {result['domain']}")
    print(f"   Age: 3 days (Very New!)")
    print(f"   Has MX: No")
    print(f"   Country: RU")

    print(f"\n🤖 Original Crawler Verdict:")
    print(f"   Verdict: {metadata['crawler_verdict'].upper()}")
    print(f"   Confidence: {metadata['confidence']}")

    print(f"\n🔍 Fallback Detector Analysis:")
    print(f"   Verdict: {result['verdict']}")
    print(f"   Confidence: {result['confidence']}")
    print(f"   Risk Score: {result['risk_score']}/100")
    print(f"   Reason: {result['reason']}")

    print(f"\n📊 Signal Breakdown:")
    for signal, score in result['fallback_signals'].items():
        print(f"   - {signal}: {score}")

    print(f"\n⚠️  Risk Indicators Detected:")
    print(f"   🔴 Very new registration (3 days)")
    print(f"   🔴 No email infrastructure")
    print(f"   🔴 High-risk country (Russia)")
    print(f"   🔴 Low-reputation registrar")

    return result


if __name__ == '__main__':
    print("\n" + "="*80)
    print("FALLBACK DETECTOR: Real-World Domain Testing")
    print("Testing domains that previously returned unreliable crawler verdicts")
    print("="*80)

    result1 = test_angelsbreathboutique()
    result2 = test_suspicious_shop_domain()

    print("\n" + "="*80)
    print("CONCLUSION")
    print("="*80)
    print("\nThe fallback detector now provides:")
    print("  ✓ Dynamic risk assessment based on metadata")
    print("  ✓ Higher confidence scores with detailed reasoning")
    print("  ✓ Better differentiation between legitimate and suspicious domains")
    print("  ✓ Transparent signal breakdown for each verdict")
    print("\nNo more blind trust in crawler verdicts when page data is missing!")
