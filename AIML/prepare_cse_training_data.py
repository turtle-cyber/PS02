#!/usr/bin/env python3
"""
Prepare training data from dump_all.jsonl for AIML model training

Extracts:
1. Tabular features for anomaly detection
2. CSE baseline profile with statistics
3. Screenshot paths for visual models
4. Feature names and metadata
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Dict, List
import argparse


def load_dump_jsonl(filepath: str) -> List[Dict]:
    """Load dump_all.jsonl data"""
    data = []
    with open(filepath, 'r') as f:
        for line in f:
            data.append(json.loads(line))
    return data


def extract_tabular_features(data: List[Dict]) -> pd.DataFrame:
    """
    Extract numeric tabular features for anomaly detection

    Features used by unified_detector.py
    """
    features_list = []

    # Define feature columns to extract (from unified_detector.py feature extraction)
    feature_columns = [
        # URL features
        'url_length', 'url_entropy', 'num_subdomains', 'is_idn',
        'has_repeated_digits', 'mixed_script',

        # Domain/WHOIS features
        'domain_age_days', 'is_newly_registered', 'is_very_new',
        'days_until_expiry',

        # Certificate features
        'is_self_signed', 'cert_age_days',

        # Form features
        'has_credential_form', 'form_count', 'password_fields',
        'email_fields', 'has_suspicious_forms', 'suspicious_form_count',

        # HTML features
        'html_size', 'external_links', 'iframe_count',

        # JavaScript features
        'js_obfuscated', 'js_keylogger', 'js_form_manipulation',
        'js_eval_usage', 'js_risk_score',

        # Redirect features
        'redirect_count', 'had_redirects',

        # DNS features
        'a_count', 'mx_count', 'ns_count',

        # Document/OCR features
        'doc_has_verdict', 'doc_risk_score', 'doc_form_count',
        'doc_has_login_keywords', 'doc_has_verify_keywords',
        'doc_has_password_keywords', 'doc_has_credential_keywords',
        'doc_length', 'ocr_length', 'ocr_has_login_keywords',
        'ocr_has_verify_keywords',
    ]

    for item in data:
        metadata = item['metadata']

        # Extract features
        features = {
            'registrable': metadata.get('registrable', ''),
            'url': metadata.get('url', ''),
        }

        for col in feature_columns:
            val = metadata.get(col)

            # Handle boolean conversion
            if isinstance(val, bool):
                features[col] = int(val)
            # Handle None/missing
            elif val is None:
                features[col] = 0
            # Handle numeric
            elif isinstance(val, (int, float)):
                # Replace NaN/inf with 0
                if pd.isna(val) or np.isinf(val):
                    features[col] = 0
                else:
                    features[col] = val
            else:
                # Non-numeric, convert or default to 0
                try:
                    features[col] = float(val)
                except:
                    features[col] = 0

        features_list.append(features)

    df = pd.DataFrame(features_list)

    # Ensure all feature columns are numeric
    for col in feature_columns:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    return df


def generate_baseline_profile(df: pd.DataFrame, data: List[Dict]) -> Dict:
    """Generate CSE baseline profile with statistics"""

    # Extract domain list (whitelist)
    domains = df['registrable'].unique().tolist()

    # Compute feature statistics
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    feature_stats = {}

    for col in numeric_cols:
        feature_stats[col] = {
            'mean': float(df[col].mean()),
            'std': float(df[col].std()),
            'min': float(df[col].min()),
            'max': float(df[col].max()),
            'median': float(df[col].median()),
            'q25': float(df[col].quantile(0.25)),
            'q75': float(df[col].quantile(0.75))
        }

    # Extract screenshot and favicon info
    screenshots = {}
    favicons = {}

    for item in data:
        metadata = item['metadata']
        registrable = metadata.get('registrable', '')

        if registrable:
            # Screenshot info
            screenshot_path = metadata.get('screenshot_path', '')
            screenshot_phash = metadata.get('screenshot_phash', '')

            if screenshot_path or screenshot_phash:
                screenshots[registrable] = {
                    'path': screenshot_path,
                    'phash': screenshot_phash
                }

            # Favicon info
            favicon_md5 = metadata.get('favicon_md5', '')
            favicon_sha256 = metadata.get('favicon_sha256', '')

            if favicon_md5 or favicon_sha256:
                favicons[registrable] = {
                    'md5': favicon_md5,
                    'sha256': favicon_sha256
                }

    baseline_profile = {
        'version': '2.0',
        'source': 'dump_all.jsonl',
        'n_domains': len(domains),
        'domains': domains,
        'feature_statistics': feature_stats,
        'screenshots': screenshots,
        'favicons': favicons,
        'metadata': {
            'total_samples': len(df),
            'label': 'benign',
            'cse_ids': list(set([item['metadata'].get('cse_id', '') for item in data]))
        }
    }

    return baseline_profile


def extract_screenshot_paths(data: List[Dict]) -> List[Dict]:
    """Extract screenshot paths and metadata for visual model training"""
    screenshots = []

    for item in data:
        metadata = item['metadata']
        screenshot_path = metadata.get('screenshot_path', '')

        if screenshot_path:
            screenshots.append({
                'registrable': metadata.get('registrable', ''),
                'url': metadata.get('url', ''),
                'screenshot_path': screenshot_path,
                'cse_id': metadata.get('cse_id', ''),
                'verdict': metadata.get('verdict', 'benign')
            })

    return screenshots


def main():
    parser = argparse.ArgumentParser(description='Prepare CSE training data from dump_all.jsonl')
    parser.add_argument('--input', default='/home/turtleneck/Desktop/PS02/dump_all.jsonl',
                       help='Path to dump_all.jsonl')
    parser.add_argument('--outdir', default='/home/turtleneck/Desktop/PS02/AIML/data/training',
                       help='Output directory for training data')
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("="*70)
    print("CSE TRAINING DATA PREPARATION")
    print("="*70)

    # Load data
    print(f"\n1. Loading data from {args.input}...")
    data = load_dump_jsonl(args.input)
    print(f"   Loaded {len(data)} CSE samples")

    # Extract tabular features
    print(f"\n2. Extracting tabular features...")
    features_df = extract_tabular_features(data)
    print(f"   Extracted {features_df.shape[1]} features")
    print(f"   Feature columns: {list(features_df.columns)}")

    # Save features CSV
    features_csv_path = outdir / 'cse_features.csv'
    features_df.to_csv(features_csv_path, index=False)
    print(f"   ✓ Saved features to {features_csv_path}")

    # Save feature names
    feature_names = [col for col in features_df.columns if col not in ['registrable', 'url']]
    feature_names_path = outdir / 'feature_names.txt'
    with open(feature_names_path, 'w') as f:
        f.write('\n'.join(feature_names))
    print(f"   ✓ Saved feature names to {feature_names_path}")

    # Generate baseline profile
    print(f"\n3. Generating CSE baseline profile...")
    baseline_profile = generate_baseline_profile(features_df, data)
    baseline_path = outdir / 'cse_baseline_profile.json'
    with open(baseline_path, 'w') as f:
        json.dump(baseline_profile, f, indent=2)
    print(f"   ✓ Baseline profile saved to {baseline_path}")
    print(f"   - {baseline_profile['n_domains']} unique domains")
    print(f"   - {len(baseline_profile['screenshots'])} with screenshots")
    print(f"   - {len(baseline_profile['favicons'])} with favicons")

    # Extract screenshot paths
    print(f"\n4. Extracting screenshot metadata...")
    screenshots = extract_screenshot_paths(data)
    screenshots_path = outdir / 'screenshot_metadata.json'
    with open(screenshots_path, 'w') as f:
        json.dump(screenshots, f, indent=2)
    print(f"   ✓ Saved screenshot metadata to {screenshots_path}")
    print(f"   - {len(screenshots)} screenshots available")

    # Generate summary
    print(f"\n{'='*70}")
    print("SUMMARY")
    print(f"{'='*70}")
    print(f"Input: {args.input}")
    print(f"Output directory: {outdir}")
    print(f"\nFiles created:")
    print(f"  1. {features_csv_path.name} - Tabular features ({features_df.shape[0]} rows x {features_df.shape[1]-2} features)")
    print(f"  2. {feature_names_path.name} - Feature names ({len(feature_names)} features)")
    print(f"  3. {baseline_path.name} - CSE baseline profile")
    print(f"  4. {screenshots_path.name} - Screenshot metadata")
    print(f"\nNext steps:")
    print(f"  1. Train anomaly detector: python AIML/models/tabular/train_anomaly.py")
    print(f"  2. Build CLIP index: python AIML/models/vision/build_cse_index.py")
    print(f"  3. Train autoencoder: python AIML/models/vision/train_cse_autoencoder.py")
    print(f"{'='*70}\n")


if __name__ == '__main__':
    main()
