#!/usr/bin/env python3
"""
Train URL Anomaly Detector using Isolation Forest

Uses one-class learning on CSE benign URLs to detect phishing via URL pattern analysis.
NO phishing labels required - detects deviations from benign URL structures.
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict
from collections import Counter
import argparse
import re


def extract_url_ngrams(url: str, n: int = 3) -> Counter:
    """Extract character n-grams from URL"""
    url_lower = url.lower()
    ngrams = Counter()

    for i in range(len(url_lower) - n + 1):
        ngram = url_lower[i:i+n]
        ngrams[ngram] += 1

    return ngrams


def extract_url_features(url_data: List[Dict]) -> pd.DataFrame:
    """
    Extract comprehensive URL features for anomaly detection

    Args:
        url_data: List of dicts with URL and metadata

    Returns:
        DataFrame with URL features
    """
    features_list = []

    # Build vocabulary of common trigrams from all URLs
    all_trigrams = Counter()
    for item in url_data:
        url = item.get('url', '')
        trigrams = extract_url_ngrams(url, n=3)
        all_trigrams.update(trigrams)

    # Keep top 50 most common trigrams
    top_trigrams = [tri for tri, _ in all_trigrams.most_common(50)]

    print(f"   Top 10 trigrams: {top_trigrams[:10]}")

    for item in url_data:
        url = item.get('url', '')
        metadata = item.get('metadata', {})

        # Basic features (already extracted)
        features = {
            'url_length': metadata.get('url_length', 0),
            'url_entropy': metadata.get('url_entropy', 0.0),
            'domain_length': metadata.get('domain_length', 0),
            'domain_entropy': metadata.get('domain_entropy', 0.0),
            'num_subdomains': metadata.get('num_subdomains', 0),
            'subdomain_entropy': metadata.get('subdomain_entropy', 0.0),
            'path_length': metadata.get('path_length', 0),
            'num_hyphens': metadata.get('num_hyphens', 0),
            'num_underscores': metadata.get('num_underscores', 0),
            'num_dots': metadata.get('num_dots', 0),
            'num_slashes': metadata.get('num_slashes', 0),
            'has_repeated_digits': int(metadata.get('has_repeated_digits', False)),
            'is_idn': int(metadata.get('is_idn', False)),
            'mixed_script': int(metadata.get('mixed_script', False)),
        }

        # NEW: URL pattern features
        url_lower = url.lower()

        # Special character ratios
        special_chars = '?&=@#%'
        features['special_char_ratio'] = sum(1 for c in url if c in special_chars) / max(1, len(url))

        # Digit ratio
        features['digit_ratio'] = sum(1 for c in url if c.isdigit()) / max(1, len(url))

        # Suspicious keyword presence (binary features)
        suspicious_words = ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'bank']
        for word in suspicious_words:
            features[f'has_{word}'] = int(word in url_lower)

        # Trigram features (frequency of top trigrams)
        url_trigrams = extract_url_ngrams(url, n=3)
        for trigram in top_trigrams:
            features[f'trigram_{trigram}'] = url_trigrams.get(trigram, 0)

        features_list.append(features)

    return pd.DataFrame(features_list)


def main():
    parser = argparse.ArgumentParser(description='Train URL anomaly detector')
    parser.add_argument('--input', required=True,
                       help='Path to dump_all.jsonl or training data')
    parser.add_argument('--outdir', default='models/url/url_anomaly',
                       help='Output directory for model')
    parser.add_argument('--contamination', type=float, default=0.05,
                       help='Expected contamination rate (default: 0.05)')
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("="*70)
    print("URL ANOMALY DETECTOR TRAINING")
    print("="*70)
    print(f"Output: {outdir}")
    print(f"Contamination: {args.contamination}")
    print()

    # Import dependencies
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
        import joblib
    except ImportError:
        print("ERROR: Missing dependencies")
        print("Install: pip install scikit-learn joblib")
        return

    # Load CSE benign data
    print("1. Loading CSE benign URLs...")
    url_data = []

    with open(args.input, 'r') as f:
        for line in f:
            data = json.loads(line)
            metadata = data.get('metadata', {})
            url = metadata.get('url', '')

            if url:
                url_data.append({
                    'url': url,
                    'metadata': metadata
                })

    print(f"   Loaded {len(url_data)} CSE URLs")

    if len(url_data) < 10:
        print("ERROR: Not enough URL data. Need at least 10 samples.")
        return

    # Extract URL features
    print("\n2. Extracting URL features...")
    features_df = extract_url_features(url_data)
    print(f"   Extracted {features_df.shape[1]} features")
    print(f"   Feature columns: {list(features_df.columns[:10])}...")

    # Train Isolation Forest
    print("\n3. Training Isolation Forest...")

    model = Pipeline([
        ('scaler', StandardScaler()),
        ('detector', IsolationForest(
            contamination=args.contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1
        ))
    ])

    model.fit(features_df)
    print("   ✓ Model trained")

    # Evaluate on training data
    print("\n4. Evaluating on training data...")
    scores = model.decision_function(features_df)
    predictions = model.predict(features_df)

    n_anomalies = (predictions == -1).sum()
    print(f"   Anomalies in training set: {n_anomalies}/{len(url_data)} ({100*n_anomalies/len(url_data):.1f}%)")
    print(f"   Score range: [{scores.min():.3f}, {scores.max():.3f}]")
    print(f"   Mean score: {scores.mean():.3f}")

    # Save model
    print("\n5. Saving model...")

    joblib.dump(model, outdir / 'url_anomaly_detector.joblib')
    print(f"   ✓ Saved model: {outdir / 'url_anomaly_detector.joblib'}")

    # Save feature names
    (outdir / 'feature_names.txt').write_text('\n'.join(features_df.columns))
    print(f"   ✓ Saved features: {outdir / 'feature_names.txt'}")

    # Save metadata
    metadata_output = {
        'model_type': 'IsolationForest',
        'n_samples': len(url_data),
        'n_features': features_df.shape[1],
        'feature_names': list(features_df.columns),
        'contamination': args.contamination,
        'n_anomalies_in_training': int(n_anomalies),
        'score_mean': float(scores.mean()),
        'score_std': float(scores.std()),
        'score_min': float(scores.min()),
        'score_max': float(scores.max()),
    }

    (outdir / 'model_metadata.json').write_text(json.dumps(metadata_output, indent=2))
    print(f"   ✓ Saved metadata: {outdir / 'model_metadata.json'}")

    # Summary
    print("\n" + "="*70)
    print("✓ URL ANOMALY DETECTOR TRAINED SUCCESSFULLY")
    print("="*70)
    print(f"CSE URLs: {len(url_data)}")
    print(f"Features: {features_df.shape[1]}")
    print(f"Anomaly threshold: {scores.mean():.3f} ± {scores.std():.3f}")
    print()
    print("USAGE:")
    print("  1. Extract URL features from unknown domain")
    print("  2. Run model.predict(features)")
    print("  3. If prediction == -1 => ANOMALY (suspicious URL)")
    print("  4. Use decision_function() for risk score")
    print("="*70)


if __name__ == '__main__':
    main()
