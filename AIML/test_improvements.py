#!/usr/bin/env python3
"""
Test script for AIML improvements
Tests NaN handling, parking detection, and non-CSE threat detection
"""

import sys
from pathlib import Path

# Add AIML directory to path
sys.path.insert(0, str(Path(__file__).parent))

from detect_phishing import UnifiedPhishingDetector


def test_nan_handling():
    """Test that domains with missing features don't crash"""
    print("\n" + "="*70)
    print("TEST 1: NaN Error Handling (fitnessforshapes.com)")
    print("="*70)

    detector = UnifiedPhishingDetector()

    # Simulate domain with minimal features (like fitnessforshapes.com)
    minimal_features = {
        'url_length': 25,
        'domain_age_days': 365,
        'html_size': 5000,
        'mx_count': 0,  # No email
        'form_count': 0,  # No forms
        'document_text': 'parked domain for sale',
        # Most features missing/NaN
    }

    result = detector.detect(
        domain='fitnessforshapes.com',
        features=minimal_features
    )

    print(f"\nResult: {result['verdict']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Signals: {len(result['signals'])}")
    for signal in result['signals']:
        print(f"  - {signal['signal']}: {signal['reason']}")

    assert result['verdict'] != 'ERROR', "Should not return ERROR verdict"
    print("\n✓ TEST PASSED: No NaN error!")


def test_parking_detection():
    """Test enhanced parking detection with OCR"""
    print("\n" + "="*70)
    print("TEST 2: Enhanced Parking Detection")
    print("="*70)

    detector = UnifiedPhishingDetector()

    parking_features = {
        'url_length': 20,
        'domain_age_days': 500,
        'html_size': 3000,
        'mx_count': 0,
        'form_count': 0,
        'document_text': 'this domain is for sale make an offer',
        'ocr_text': 'premium domain available at sedo',
        # Parking indicators
    }

    result = detector.detect(
        domain='test-parking-domain.com',
        features=parking_features
    )

    print(f"\nResult: {result['verdict']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Signals: {len(result['signals'])}")
    for signal in result['signals']:
        print(f"  - {signal['signal']}: {signal['reason']}")

    assert result['verdict'] == 'PARKED', f"Expected PARKED, got {result['verdict']}"
    print("\n✓ TEST PASSED: Parking detected!")


def test_generic_phishing():
    """Test generic phishing detection (non-CSE)"""
    print("\n" + "="*70)
    print("TEST 3: Generic Phishing Detection (PayPal phish)")
    print("="*70)

    detector = UnifiedPhishingDetector()

    phishing_features = {
        'url_length': 45,
        'domain_age_days': 5,  # Very new
        'is_very_new': True,
        'html_size': 8000,
        'form_count': 1,
        'has_credential_form': True,
        'password_fields': 1,
        'email_fields': 1,
        'document_text': 'urgent: your paypal account has been suspended. login now to verify your identity',
        'js_risk_score': 0.6,
    }

    result = detector.detect(
        domain='paypal-secure-verify.tk',  # High-risk TLD
        features=phishing_features
    )

    print(f"\nResult: {result['verdict']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Signals: {len(result['signals'])}")
    for signal in result['signals']:
        print(f"  - {signal['signal']}: {signal['reason']}")

    assert 'PHISHING' in result['verdict'], f"Expected PHISHING, got {result['verdict']}"
    print("\n✓ TEST PASSED: Generic phishing detected!")


def test_gambling_detection():
    """Test gambling site detection"""
    print("\n" + "="*70)
    print("TEST 4: Gambling Site Detection")
    print("="*70)

    detector = UnifiedPhishingDetector()

    gambling_features = {
        'url_length': 30,
        'domain_age_days': 100,
        'html_size': 50000,
        'form_count': 0,
        'document_text': 'online casino betting poker slots jackpot roulette play now best odds',
        'ocr_text': 'win big casino games',
    }

    result = detector.detect(
        domain='online-casino-india.bet',
        features=gambling_features
    )

    print(f"\nResult: {result['verdict']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Signals: {len(result['signals'])}")
    for signal in result['signals']:
        print(f"  - {signal['signal']}: {signal['reason']}")

    assert result['verdict'] == 'GAMBLING', f"Expected GAMBLING, got {result['verdict']}"
    print("\n✓ TEST PASSED: Gambling site detected!")


def test_crypto_scam():
    """Test cryptocurrency scam detection"""
    print("\n" + "="*70)
    print("TEST 5: Cryptocurrency Scam Detection")
    print("="*70)

    detector = UnifiedPhishingDetector()

    crypto_features = {
        'url_length': 35,
        'domain_age_days': 2,
        'is_very_new': True,
        'html_size': 12000,
        'form_count': 1,
        'has_credential_form': True,
        'document_text': 'bitcoin giveaway crypto wallet eth airdrop free tokens ethereum',
        'js_risk_score': 0.8,
    }

    result = detector.detect(
        domain='bitcoin-giveaway-2024.xyz',
        features=crypto_features
    )

    print(f"\nResult: {result['verdict']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Signals: {len(result['signals'])}")
    for signal in result['signals']:
        print(f"  - {signal['signal']}: {signal['reason']}")

    assert 'PHISHING' in result['verdict'] or 'CRYPTO' in result['verdict'], \
        f"Expected PHISHING_CRYPTO, got {result['verdict']}"
    print("\n✓ TEST PASSED: Crypto scam detected!")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("AIML IMPROVEMENT TEST SUITE")
    print("="*70)

    tests = [
        ("NaN Error Handling", test_nan_handling),
        ("Parking Detection", test_parking_detection),
        ("Generic Phishing", test_generic_phishing),
        ("Gambling Detection", test_gambling_detection),
        ("Crypto Scam Detection", test_crypto_scam),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"\n✗ TEST FAILED: {test_name}")
            print(f"  Error: {e}")
            failed += 1
        except Exception as e:
            print(f"\n✗ TEST ERROR: {test_name}")
            print(f"  Exception: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print("\n" + "="*70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("="*70)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
