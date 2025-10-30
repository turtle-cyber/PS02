"""
Test fallback detector with manakovdesign.ru (legitimate Russian design agency)
"""

import json
from fallback_detector import FallbackDetector


def test_manakovdesign_ru():
    """
    Test case: manakovdesign.ru
    - Legitimate design agency
    - .ru TLD (Russia)
    - Being incorrectly flagged as phishing
    """
    print("\n" + "="*80)
    print("FALSE POSITIVE TEST: manakovdesign.ru")
    print("="*80)

    # Simulate typical metadata for a legitimate Russian design agency
    metadata = {
        'registrable': 'manakovdesign.ru',
        'domain': 'manakovdesign.ru',
        'domain_age_days': 1500,  # ~4 years old (established)
        'is_newly_registered': False,
        'is_very_new': False,
        'domain_length': 17,
        'domain_entropy': 3.85,
        'a_count': 1,
        'mx_count': 2,  # Has email infrastructure
        'ns_count': 2,
        'dns': json.dumps({
            'A': ['185.146.173.118'],
            'MX': ['mx1.example.ru', 'mx2.example.ru'],
            'NS': ['ns1.example.ru', 'ns2.example.ru']
        }),
        'asn': '197695',  # Common Russian hosting ASN
        'asn_org': 'REG.RU',
        'country': 'RU',
        'registrar': 'REG.RU',
        'days_until_expiry': 200,
        'html_size': 45000,  # Has content
        'screenshot_path': '/path/to/screenshot.png',
        'ocr_text_length': 800,
        'redirect_count': 2,
        'had_redirects': False,
        'uses_https': True,
        'external_links': 15,
        'images_count': 20,
        'form_count': 1,  # Contact form
        'password_fields': 0,
        'has_credential_form': False
    }

    print(f"\n📋 Domain Information:")
    print(f"   Domain: {metadata['registrable']}")
    print(f"   Age: {metadata['domain_age_days']} days (~4 years - ESTABLISHED)")
    print(f"   Country: {metadata['country']} (Russia)")
    print(f"   ASN: {metadata['asn']} ({metadata['asn_org']})")
    print(f"   Has MX: Yes (2 records)")
    print(f"   Has Content: Yes (45KB HTML, 800 chars OCR)")
    print(f"   HTTPS: Yes")
    print(f"   Type: Design agency website")

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

    print(f"\n❓ Analysis:")
    if result['verdict'] in ['PHISHING', 'LIKELY_PHISHING', 'SUSPICIOUS']:
        print(f"   ❌ FALSE POSITIVE DETECTED!")
        print(f"   🔴 Domain incorrectly flagged as {result['verdict']}")
        print(f"\n   💡 Why this is wrong:")
        print(f"      ✓ Domain is 4+ years old (established)")
        print(f"      ✓ Has proper email infrastructure (MX records)")
        print(f"      ✓ Has HTTPS")
        print(f"      ✓ Has substantial content (45KB HTML)")
        print(f"      ✓ Legitimate business (design agency)")
        print(f"\n   ⚠️  Issues causing false positive:")
        if metadata['country'] == 'RU':
            print(f"      🔸 Country: RU (Russia) - adds +10 risk")
        if metadata['asn'] == '197695':
            print(f"      🔸 ASN: 197695 (REG.RU) - adds +20 risk (high-risk ASN)")
        if 'reg.ru' in metadata['registrar'].lower():
            print(f"      🔸 Registrar: REG.RU - adds +10 risk (low-rep registrar)")
    else:
        print(f"   ✅ Correctly classified as {result['verdict']}")

    return result


def test_legitimate_russian_ecommerce():
    """
    Test another legitimate Russian domain to verify pattern
    """
    print("\n" + "="*80)
    print("FALSE POSITIVE TEST: example-shop.ru (Legitimate E-commerce)")
    print("="*80)

    metadata = {
        'registrable': 'example-shop.ru',
        'domain': 'example-shop.ru',
        'domain_age_days': 2000,  # ~5.5 years
        'is_newly_registered': False,
        'domain_length': 16,
        'domain_entropy': 3.75,
        'a_count': 2,
        'mx_count': 2,
        'ns_count': 4,
        'dns': json.dumps({
            'A': ['185.146.173.118', '185.146.173.119'],
            'MX': ['mx1.mail.ru', 'mx2.mail.ru'],
            'NS': ['ns1.hosting.ru', 'ns2.hosting.ru', 'ns3.hosting.ru', 'ns4.hosting.ru']
        }),
        'asn': '197695',
        'asn_org': 'REG.RU',
        'country': 'RU',
        'registrar': 'REG.RU',
        'days_until_expiry': 365,
        'html_size': 120000,
        'screenshot_path': '/path/to/screenshot.png',
        'ocr_text_length': 2000,
        'uses_https': True,
        'external_links': 50,
        'images_count': 100
    }

    print(f"\n📋 Domain: {metadata['registrable']}")
    print(f"   Age: {metadata['domain_age_days']} days (~5.5 years)")
    print(f"   Has MX: Yes")
    print(f"   Has Content: Yes (120KB HTML)")

    detector = FallbackDetector()
    result = detector.analyze_metadata(metadata)

    print(f"\n📊 Results:")
    print(f"   Verdict: {result['verdict']}")
    print(f"   Risk Score: {result['risk_score']}/100")

    if result['risk_score'] >= 50:
        print(f"   ❌ FALSE POSITIVE!")
    else:
        print(f"   ✅ Correctly classified")

    return result


if __name__ == '__main__':
    print("\n" + "="*80)
    print("FALSE POSITIVE ANALYSIS: Legitimate Russian Websites")
    print("Testing if fallback detector is too aggressive with .ru domains")
    print("="*80)

    result1 = test_manakovdesign_ru()
    result2 = test_legitimate_russian_ecommerce()

    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    print(f"\nmanakovdesign.ru (Design Agency):")
    print(f"   Risk Score: {result1['risk_score']}/100")
    print(f"   Verdict: {result1['verdict']}")
    print(f"   False Positive: {'YES ❌' if result1['risk_score'] >= 50 else 'NO ✅'}")

    print(f"\nexample-shop.ru (E-commerce):")
    print(f"   Risk Score: {result2['risk_score']}/100")
    print(f"   Verdict: {result2['verdict']}")
    print(f"   False Positive: {'YES ❌' if result2['risk_score'] >= 50 else 'NO ✅'}")

    print("\n" + "="*80)
    print("DIAGNOSIS")
    print("="*80)
    print("\nThe fallback detector is penalizing legitimate Russian sites because:")
    print("   1. Country: RU adds +10 risk points")
    print("   2. ASN: 197695 (REG.RU) adds +20 risk points (marked as high-risk)")
    print("   3. Registrar: REG.RU adds +10 risk points (marked as low-reputation)")
    print("\n   Total penalty: +40 points just for being Russian!")
    print("\n⚠️  This is too aggressive for established domains with proper infrastructure.")
    print("\n💡 Recommendation:")
    print("   - Only apply geographic/ASN penalties for NEW domains (<90 days)")
    print("   - OR reduce penalty weights for established domains")
    print("   - OR whitelist legitimate Russian hosting providers")
