#!/usr/bin/env python3
"""
Test Anomaly Detector Feature Mismatch Fix

Verifies that the anomaly detector can now handle dump_all.jsonl data
without "feature names unseen at fit time" errors.
"""

import json
import sys
from pathlib import Path

# Add AIML directory to path
sys.path.insert(0, str(Path(__file__).parent))

from unified_detector import UnifiedPhishingDetector


def load_sample_from_dump():
    """Load a sample domain from dump_all.jsonl"""
    dump_file = Path('/home/turtleneck/Desktop/PS02/dump_all.jsonl')

    if not dump_file.exists():
        print(f"Error: {dump_file} not found")
        return None

    # Load first domain
    with open(dump_file, 'r') as f:
        first_line = f.readline()
        data = json.loads(first_line)
        return data.get('metadata', {})


def test_feature_extraction():
    """Test that all 42 features can be extracted without errors"""
    print("="*80)
    print("TEST: Anomaly Detector Feature Extraction (dump_all.jsonl schema)")
    print("="*80)

    # Load sample metadata
    print("\n1. Loading sample domain from dump_all.jsonl...")
    metadata = load_sample_from_dump()

    if metadata is None:
        print("❌ FAILED: Could not load sample data")
        return False

    domain = metadata.get('registrable', 'unknown')
    print(f"   Domain: {domain}")
    print(f"   Total metadata keys: {len(metadata)}")

    # Initialize detector
    print("\n2. Initializing UnifiedPhishingDetector...")
    try:
        detector = UnifiedPhishingDetector()
        detector.load_models()
        print(f"   ✓ Models loaded")
        print(f"   ✓ Expected features: {len(detector.feature_names)}")
    except Exception as e:
        print(f"   ❌ FAILED to load models: {e}")
        return False

    # Test feature extraction
    print("\n3. Testing feature extraction (prepare_features)...")
    try:
        features_df = detector.prepare_features(metadata)

        if features_df is None:
            print("   ❌ FAILED: prepare_features returned None")
            return False

        print(f"   ✓ Features extracted: {len(features_df.columns)} columns")
        print(f"   ✓ Feature names match: {list(features_df.columns) == detector.feature_names}")

        # Show sample features
        print(f"\n   Sample features:")
        for col in list(features_df.columns)[:10]:
            print(f"      {col}: {features_df[col].values[0]}")

    except Exception as e:
        print(f"   ❌ FAILED: Feature extraction error: {e}")
        import traceback
        traceback.print_exc()
        return False

    # Test anomaly detection
    print("\n4. Testing anomaly detection (run_anomaly_detection)...")
    try:
        result = detector.run_anomaly_detection(metadata)

        print(f"   Result:")
        print(f"      Verdict: {result['verdict']}")
        print(f"      Confidence: {result['confidence']:.3f}")
        print(f"      Score: {result.get('score', 'N/A')}")
        print(f"      Reason: {result['reason']}")

        if result['verdict'] == 'ERROR':
            print(f"   ❌ FAILED: Anomaly detection returned ERROR")
            return False

        print(f"   ✓ Anomaly detection succeeded!")

    except Exception as e:
        print(f"   ❌ FAILED: Anomaly detection error: {e}")
        import traceback
        traceback.print_exc()
        return False

    return True


def test_feature_mapping_coverage():
    """Verify that all 42 model features are mapped"""
    print("\n" + "="*80)
    print("TEST: Feature Mapping Coverage")
    print("="*80)

    # Initialize detector
    detector = UnifiedPhishingDetector()
    detector.load_models()

    print(f"\nTotal model features: {len(detector.feature_names)}")
    print(f"Total mapped features: {len(detector.FEATURE_MAPPING)}")

    unmapped_features = []
    for feature_name in detector.feature_names:
        if feature_name not in detector.FEATURE_MAPPING:
            unmapped_features.append(feature_name)

    if unmapped_features:
        print(f"\n❌ WARNING: {len(unmapped_features)} features not in FEATURE_MAPPING:")
        for f in unmapped_features:
            print(f"   - {f}")
        return False
    else:
        print(f"\n✓ All {len(detector.feature_names)} features are mapped!")
        return True


def main():
    """Run all tests"""
    print("\n" + "="*80)
    print("ANOMALY DETECTOR FEATURE MISMATCH FIX - TEST SUITE")
    print("="*80)

    results = []

    # Test 1: Feature mapping coverage
    results.append(("Feature Mapping Coverage", test_feature_mapping_coverage()))

    # Test 2: Feature extraction
    results.append(("Feature Extraction", test_feature_extraction()))

    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {test_name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n✓ All tests passed! Feature mismatch issue is FIXED!")
        return 0
    else:
        print(f"\n✗ {total - passed} test(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
