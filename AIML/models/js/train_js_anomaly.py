#!/usr/bin/env python3
"""
Train JavaScript Behavior Anomaly Detector using One-Class SVM

Uses one-class learning on CSE benign JS patterns to detect malicious JavaScript.
NO phishing labels required - detects deviations from benign JS behavior.
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict
import argparse


def extract_js_features(data: List[Dict]) -> pd.DataFrame:
    """
    Extract JavaScript behavior features

    Features (all already extracted by pipeline):
    - js_obfuscated: boolean
    - js_keylogger: boolean
    - js_form_manipulation: boolean
    - js_eval_usage: boolean
    - js_risk_score: numeric
    - js_obfuscated_count: numeric
    - js_eval_count: numeric
    - js_encoding_count: numeric
    - js_redirect_detected: boolean
    """
    features_list = []

    for item in data:
        metadata = item.get('metadata', {})

        features = {
            # Binary features (convert bool to int)
            'js_obfuscated': int(metadata.get('js_obfuscated', False)),
            'js_keylogger': int(metadata.get('js_keylogger', False)),
            'js_form_manipulation': int(metadata.get('js_form_manipulation', False)),
            'js_eval_usage': int(metadata.get('js_eval_usage', False)),
            'js_redirect_detected': int(metadata.get('js_redirect_detected', False)),

            # Numeric features
            'js_risk_score': metadata.get('js_risk_score', 0),
            'js_obfuscated_count': metadata.get('js_obfuscated_count', 0),
            'js_eval_count': metadata.get('js_eval_count', 0),
            'js_encoding_count': metadata.get('js_encoding_count', 0),

            # Related features (provide context)
            'external_scripts': metadata.get('external_scripts', 0),
            'form_count': metadata.get('form_count', 0),
            'has_credential_form': int(metadata.get('has_credential_form', False)),
        }

        features_list.append(features)

    return pd.DataFrame(features_list)


def main():
    parser = argparse.ArgumentParser(description='Train JavaScript behavior anomaly detector')
    parser.add_argument('--input', required=True,
                       help='Path to dump_all.jsonl or training data')
    parser.add_argument('--outdir', default='models/js/js_anomaly',
                       help='Output directory for model')
    parser.add_argument('--nu', type=float, default=0.05,
                       help='One-Class SVM nu parameter (expected anomaly rate)')
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("="*70)
    print("JAVASCRIPT BEHAVIOR ANOMALY DETECTOR TRAINING")
    print("="*70)
    print(f"Output: {outdir}")
    print(f"Nu (anomaly rate): {args.nu}")
    print()

    # Import dependencies
    try:
        from sklearn.svm import OneClassSVM
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
        import joblib
    except ImportError:
        print("ERROR: Missing dependencies")
        print("Install: pip install scikit-learn joblib")
        return

    # Load CSE benign data
    print("1. Loading CSE benign data...")
    data = []

    with open(args.input, 'r') as f:
        for line in f:
            data.append(json.loads(line))

    print(f"   Loaded {len(data)} CSE samples")

    if len(data) < 10:
        print("ERROR: Not enough data. Need at least 10 samples.")
        return

    # Extract JS features
    print("\n2. Extracting JavaScript features...")
    features_df = extract_js_features(data)
    print(f"   Extracted {features_df.shape[1]} features")
    print(f"   Features: {list(features_df.columns)}")

    # Show feature statistics
    print("\n   CSE Benign JS Baseline Statistics:")
    print(f"     Obfuscated scripts: {features_df['js_obfuscated'].sum()}/{len(data)}")
    print(f"     Keylogger detected: {features_df['js_keylogger'].sum()}/{len(data)}")
    print(f"     Form manipulation: {features_df['js_form_manipulation'].sum()}/{len(data)}")
    print(f"     Eval usage: {features_df['js_eval_usage'].sum()}/{len(data)}")
    print(f"     Mean risk score: {features_df['js_risk_score'].mean():.2f}")

    # Train One-Class SVM
    print("\n3. Training One-Class SVM...")

    model = Pipeline([
        ('scaler', StandardScaler()),
        ('detector', OneClassSVM(
            nu=args.nu,
            kernel='rbf',
            gamma='scale'
        ))
    ])

    model.fit(features_df)
    print("   ✓ Model trained")

    # Evaluate on training data
    print("\n4. Evaluating on training data...")
    scores = model.decision_function(features_df)
    predictions = model.predict(features_df)

    n_anomalies = (predictions == -1).sum()
    print(f"   Anomalies in training set: {n_anomalies}/{len(data)} ({100*n_anomalies/len(data):.1f}%)")
    print(f"   Score range: [{scores.min():.3f}, {scores.max():.3f}]")
    print(f"   Mean score: {scores.mean():.3f}")

    # Identify most anomalous CSE samples (potential outliers)
    if n_anomalies > 0:
        anomaly_indices = np.where(predictions == -1)[0]
        print(f"\n   Most anomalous CSE domains (check for data quality):")
        for idx in anomaly_indices[:5]:
            domain = data[idx].get('metadata', {}).get('registrable', 'unknown')
            score = scores[idx]
            print(f"     - {domain}: score={score:.3f}")

    # Save model
    print("\n5. Saving model...")

    joblib.dump(model, outdir / 'js_anomaly_detector.joblib')
    print(f"   ✓ Saved model: {outdir / 'js_anomaly_detector.joblib'}")

    # Save feature names
    (outdir / 'feature_names.txt').write_text('\n'.join(features_df.columns))
    print(f"   ✓ Saved features: {outdir / 'feature_names.txt'}")

    # Save metadata
    metadata_output = {
        'model_type': 'OneClassSVM',
        'n_samples': len(data),
        'n_features': features_df.shape[1],
        'feature_names': list(features_df.columns),
        'nu': args.nu,
        'kernel': 'rbf',
        'n_anomalies_in_training': int(n_anomalies),
        'score_mean': float(scores.mean()),
        'score_std': float(scores.std()),
        'score_min': float(scores.min()),
        'score_max': float(scores.max()),
        'baseline_stats': {
            'obfuscated_rate': float(features_df['js_obfuscated'].mean()),
            'keylogger_rate': float(features_df['js_keylogger'].mean()),
            'form_manipulation_rate': float(features_df['js_form_manipulation'].mean()),
            'eval_usage_rate': float(features_df['js_eval_usage'].mean()),
            'mean_risk_score': float(features_df['js_risk_score'].mean()),
        }
    }

    (outdir / 'model_metadata.json').write_text(json.dumps(metadata_output, indent=2))
    print(f"   ✓ Saved metadata: {outdir / 'model_metadata.json'}")

    # Summary
    print("\n" + "="*70)
    print("✓ JS BEHAVIOR ANOMALY DETECTOR TRAINED SUCCESSFULLY")
    print("="*70)
    print(f"CSE samples: {len(data)}")
    print(f"Features: {features_df.shape[1]}")
    print(f"Anomaly threshold: {scores.mean():.3f} ± {scores.std():.3f}")
    print()
    print("CSE Benign JS Profile:")
    print(f"  - Obfuscation: {100*features_df['js_obfuscated'].mean():.1f}%")
    print(f"  - Keyloggers: {100*features_df['js_keylogger'].mean():.1f}%")
    print(f"  - Form manipulation: {100*features_df['js_form_manipulation'].mean():.1f}%")
    print(f"  - Mean risk: {features_df['js_risk_score'].mean():.2f}/100")
    print()
    print("USAGE:")
    print("  1. Extract JS features from unknown domain")
    print("  2. Run model.predict(features)")
    print("  3. If prediction == -1 => ANOMALY (malicious JS)")
    print("  4. Use decision_function() for risk score")
    print("="*70)


if __name__ == '__main__':
    main()
