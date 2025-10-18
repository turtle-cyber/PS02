#!/usr/bin/env python3
"""
Prepare Training Dataset for Phishing Detection Model

Converts complete_features.jsonl into training-ready format:
- Separates features from labels
- Handles missing values
- Creates feature vectors for ML models
- Splits into train/validation sets (if needed)
"""

import json
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Tuple
import argparse


class TrainingDataPreparer:
    """Prepare training data from enriched features"""

    def __init__(self):
        # Features to exclude from training (metadata, not predictive)
        self.exclude_features = {
            'id', 'document', 'registrable', 'seed_registrable',
            'cse_id', 'first_seen', 'record_type', 'stage',
            'enrichment_level', 'monitoring_reasons', 'reasons',
            'inactive_reason', 'verdict', 'final_verdict',
            'doc_verdict', 'has_verdict', 'doc_has_verdict',
            'confidence', 'risk_score', 'doc_risk_score',
            'document_text', 'ocr_text', 'doc_submit_buttons',
            'tld', 'screenshot_phash', 'crawl_failed',
            'is_original_seed', 'had_redirects'
        }

        # Categorical features that need encoding
        self.categorical_features = {
            'inactive_status'
        }

    def load_data(self, jsonl_path: str) -> List[Dict]:
        """Load data from JSONL"""
        data = []
        with open(jsonl_path, 'r') as f:
            for line in f:
                data.append(json.loads(line))
        return data

    def extract_features(self, data: List[Dict]) -> Tuple[pd.DataFrame, List[str]]:
        """
        Extract feature vectors from domain data

        Returns:
            (features_df, domain_ids)
        """
        feature_rows = []
        domain_ids = []

        for item in data:
            domain_id = item['id']
            metadata = item['metadata']

            # Extract all features except excluded ones
            features = {}
            for key, value in metadata.items():
                if key not in self.exclude_features:
                    # Convert boolean to int
                    if isinstance(value, bool):
                        features[key] = int(value)
                    # Keep numeric values
                    elif isinstance(value, (int, float)):
                        features[key] = value
                    # Encode categorical
                    elif key in self.categorical_features:
                        features[key] = self._encode_categorical(key, value)
                    # Skip string features (except encoded ones)
                    elif isinstance(value, str):
                        continue
                    else:
                        features[key] = value

            feature_rows.append(features)
            domain_ids.append(domain_id)

        # Create DataFrame
        df = pd.DataFrame(feature_rows)

        return df, domain_ids

    def _encode_categorical(self, feature_name: str, value: str) -> int:
        """Encode categorical features"""
        if feature_name == 'inactive_status':
            status_map = {
                'active': 0,
                'parked': 1,
                'down': 2,
                'error': 3,
                'unknown': 4
            }
            return status_map.get(value, 4)
        return 0

    def get_labels(self, data: List[Dict]) -> pd.Series:
        """
        Extract labels from data

        Since all current data is benign CSE, returns all 0s (benign)
        In production, this would extract actual phishing labels
        """
        labels = []
        for item in data:
            metadata = item['metadata']
            # Check if marked as phishing
            verdict = metadata.get('verdict', 'benign')
            is_phishing = 1 if verdict in ['phishing', 'suspicious'] else 0
            labels.append(is_phishing)

        return pd.Series(labels, name='is_phishing')

    def save_training_data(self, features_df: pd.DataFrame, labels: pd.Series,
                          domain_ids: List[str], output_dir: str):
        """Save training data in multiple formats"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save features as CSV
        features_csv = output_path / 'features.csv'
        features_df.to_csv(features_csv, index=False)
        print(f"✓ Saved features to {features_csv}")

        # Save labels as CSV
        labels_csv = output_path / 'labels.csv'
        labels.to_csv(labels_csv, index=False, header=True)
        print(f"✓ Saved labels to {labels_csv}")

        # Save domain IDs
        ids_csv = output_path / 'domain_ids.csv'
        pd.Series(domain_ids, name='domain_id').to_csv(ids_csv, index=False)
        print(f"✓ Saved domain IDs to {ids_csv}")

        # Save feature names
        feature_names_txt = output_path / 'feature_names.txt'
        with open(feature_names_txt, 'w') as f:
            for col in features_df.columns:
                f.write(f"{col}\n")
        print(f"✓ Saved feature names to {feature_names_txt}")

        # Save summary statistics
        stats_csv = output_path / 'feature_stats.csv'
        stats = features_df.describe()
        stats.to_csv(stats_csv)
        print(f"✓ Saved feature statistics to {stats_csv}")

        # Save metadata JSON
        metadata = {
            'total_samples': len(features_df),
            'total_features': len(features_df.columns),
            'feature_names': list(features_df.columns),
            'label_distribution': {
                'benign': int((labels == 0).sum()),
                'phishing': int((labels == 1).sum())
            },
            'missing_values': features_df.isnull().sum().to_dict()
        }

        metadata_json = output_path / 'metadata.json'
        with open(metadata_json, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Saved metadata to {metadata_json}")

    def create_baseline_profile(self, features_df: pd.DataFrame, domain_ids: List[str],
                               data: List[Dict], output_dir: str):
        """
        Create CSE baseline profile for anomaly detection

        Saves statistics and patterns of benign CSE domains
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Statistical profile
        profile = {
            'feature_means': features_df.mean().to_dict(),
            'feature_stds': features_df.std().to_dict(),
            'feature_medians': features_df.median().to_dict(),
            'feature_mins': features_df.min().to_dict(),
            'feature_maxs': features_df.max().to_dict(),
        }

        # Extract registrable domains for whitelist
        registrables = [item['metadata'].get('registrable', '') for item in data]
        profile['cse_whitelist'] = [r for r in registrables if r]

        # Extract screenshot hashes for visual baseline
        phashes = [item['metadata'].get('screenshot_phash', '') for item in data]
        profile['cse_visual_hashes'] = [h for h in phashes if h]

        # Save profile
        profile_json = output_path / 'cse_baseline_profile.json'
        with open(profile_json, 'w') as f:
            json.dump(profile, f, indent=2)

        print(f"✓ Created CSE baseline profile: {profile_json}")
        print(f"  - Baseline domains: {len(profile['cse_whitelist'])}")
        print(f"  - Visual hashes: {len(profile['cse_visual_hashes'])}")


def main():
    parser = argparse.ArgumentParser(description='Prepare training dataset from features')
    parser.add_argument('--input', default='AIML/data/complete_features.jsonl',
                       help='Input JSONL with complete features')
    parser.add_argument('--output', default='AIML/data/training',
                       help='Output directory for training data')
    args = parser.parse_args()

    preparer = TrainingDataPreparer()

    print("="*70)
    print("TRAINING DATA PREPARATION")
    print("="*70)
    print(f"Input: {args.input}")
    print(f"Output: {args.output}")
    print()

    # Load data
    print("Loading data...")
    data = preparer.load_data(args.input)
    print(f"Loaded {len(data)} domains")

    # Extract features and labels
    print("\nExtracting features...")
    features_df, domain_ids = preparer.extract_features(data)
    labels = preparer.get_labels(data)

    print(f"  Features: {features_df.shape[1]}")
    print(f"  Samples: {features_df.shape[0]}")
    print(f"  Labels: Benign={int((labels == 0).sum())}, Phishing={int((labels == 1).sum())}")

    # Handle missing values
    print("\nHandling missing values...")
    missing_before = features_df.isnull().sum().sum()
    # Fill missing values with 0 (or median for some features)
    features_df = features_df.fillna(0)
    print(f"  Filled {missing_before} missing values")

    # Save training data
    print("\nSaving training data...")
    preparer.save_training_data(features_df, labels, domain_ids, args.output)

    # Create CSE baseline profile
    print("\nCreating CSE baseline profile...")
    preparer.create_baseline_profile(features_df, domain_ids, data, args.output)

    print()
    print("="*70)
    print("✓ Training data preparation complete!")
    print(f"  Output directory: {args.output}")
    print("="*70)
    print("\nNext steps:")
    print("  1. Review feature statistics in feature_stats.csv")
    print("  2. Train anomaly detection model on CSE baseline")
    print("  3. Build multi-modal detection modules")
    print("="*70)


if __name__ == "__main__":
    main()
