#!/usr/bin/env python3
"""
Train Anomaly Detection Model for Phishing Detection

Since we only have benign CSE examples, we use anomaly detection:
- Train on benign CSE baseline
- Detect deviations as potential phishing
- Use Isolation Forest algorithm
"""

import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
import argparse


class AnomalyDetectorTrainer:
    """Train anomaly detection model on CSE baseline"""

    def __init__(self, contamination=0.05, random_state=42):
        """
        Args:
            contamination: Expected proportion of anomalies (default 5%)
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.feature_names = None

    def create_pipeline(self):
        """Create ML pipeline with preprocessing and model"""
        return Pipeline([
            ('imputer', SimpleImputer(strategy='constant', fill_value=0)),
            ('scaler', StandardScaler()),
            ('detector', IsolationForest(
                contamination=self.contamination,
                random_state=self.random_state,
                n_estimators=100,
                max_samples='auto',
                max_features=1.0,
                bootstrap=False,
                n_jobs=-1,
                verbose=0
            ))
        ])

    def load_training_data(self, data_dir: str):
        """Load training data"""
        data_path = Path(data_dir)

        # Load features
        features_csv = data_path / 'features.csv'
        features_df = pd.read_csv(features_csv)

        # Load feature names
        feature_names_txt = data_path / 'feature_names.txt'
        with open(feature_names_txt, 'r') as f:
            feature_names = [line.strip() for line in f]

        self.feature_names = feature_names

        print(f"Loaded {len(features_df)} samples with {len(feature_names)} features")

        return features_df

    def train(self, features_df: pd.DataFrame):
        """Train the anomaly detection model"""
        print("\nTraining Isolation Forest model...")

        # Create pipeline
        self.model = self.create_pipeline()

        # Train on all benign data
        self.model.fit(features_df)

        # Get anomaly scores for training data
        scores = self.model.decision_function(features_df)
        predictions = self.model.predict(features_df)

        # Statistics
        anomalies_in_train = (predictions == -1).sum()
        print(f"\nTraining complete!")
        print(f"  Detected {anomalies_in_train} anomalies in training set ({anomalies_in_train/len(features_df)*100:.1f}%)")
        print(f"  Score range: [{scores.min():.3f}, {scores.max():.3f}]")
        print(f"  Mean score: {scores.mean():.3f}")
        print(f"  Std score: {scores.std():.3f}")

        return scores, predictions

    def save_model(self, output_dir: str):
        """Save trained model and metadata"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        # Save model
        model_file = output_path / 'anomaly_detector.pkl'
        with open(model_file, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"\n✓ Saved model to {model_file}")

        # Save feature names
        feature_names_file = output_path / 'feature_names.txt'
        with open(feature_names_file, 'w') as f:
            for name in self.feature_names:
                f.write(f"{name}\n")
        print(f"✓ Saved feature names to {feature_names_file}")

        # Save metadata
        metadata = {
            'model_type': 'IsolationForest',
            'n_features': len(self.feature_names),
            'feature_names': self.feature_names,
            'contamination': self.contamination,
            'random_state': self.random_state,
        }

        metadata_file = output_path / 'model_metadata.json'
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"✓ Saved metadata to {metadata_file}")

    def evaluate_on_baseline(self, features_df: pd.DataFrame, domain_ids: pd.Series):
        """Evaluate model on CSE baseline to understand normal behavior"""
        print("\nEvaluating on CSE baseline...")

        scores = self.model.decision_function(features_df)
        predictions = self.model.predict(features_df)

        # Find most anomalous CSE domains (potential outliers)
        anomaly_indices = np.where(predictions == -1)[0]

        if len(anomaly_indices) > 0:
            print(f"\nMost anomalous CSE domains (potential data quality issues):")
            for idx in anomaly_indices[:5]:
                print(f"  - {domain_ids.iloc[idx]}: score={scores[idx]:.3f}")
        else:
            print("\nNo anomalies detected in baseline (good!)")

        # Score distribution
        print(f"\nScore distribution:")
        print(f"  10th percentile: {np.percentile(scores, 10):.3f}")
        print(f"  25th percentile: {np.percentile(scores, 25):.3f}")
        print(f"  50th percentile: {np.percentile(scores, 50):.3f}")
        print(f"  75th percentile: {np.percentile(scores, 75):.3f}")
        print(f"  90th percentile: {np.percentile(scores, 90):.3f}")


def main():
    parser = argparse.ArgumentParser(description='Train anomaly detection model')
    parser.add_argument('--data-dir', default='AIML/data/training',
                       help='Directory with training data')
    parser.add_argument('--output-dir', default='AIML/models/anomaly',
                       help='Directory to save trained model')
    parser.add_argument('--contamination', type=float, default=0.05,
                       help='Expected proportion of anomalies (default: 0.05)')
    args = parser.parse_args()

    print("="*70)
    print("ANOMALY DETECTION MODEL TRAINING")
    print("="*70)
    print(f"Data directory: {args.data_dir}")
    print(f"Output directory: {args.output_dir}")
    print(f"Contamination: {args.contamination}")
    print()

    # Create trainer
    trainer = AnomalyDetectorTrainer(contamination=args.contamination)

    # Load data
    print("Loading training data...")
    features_df = trainer.load_training_data(args.data_dir)

    # Load domain IDs for evaluation
    domain_ids = pd.read_csv(Path(args.data_dir) / 'domain_ids.csv')['domain_id']

    # Train model
    scores, predictions = trainer.train(features_df)

    # Evaluate on baseline
    trainer.evaluate_on_baseline(features_df, domain_ids)

    # Save model
    trainer.save_model(args.output_dir)

    print()
    print("="*70)
    print("✓ Model training complete!")
    print(f"  Model saved to: {args.output_dir}")
    print("="*70)
    print("\nNext steps:")
    print("  1. Test model on new domains")
    print("  2. Build visual similarity detector")
    print("  3. Create unified detection engine")
    print("="*70)


if __name__ == "__main__":
    main()
