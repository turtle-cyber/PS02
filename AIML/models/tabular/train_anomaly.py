"""Train anomaly detector on CSE benign data only"""
import argparse
import json
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

def main():
    ap = argparse.ArgumentParser(description="Train anomaly detector on CSE benign features")
    ap.add_argument("--csv", default="data/cse_benign.csv", help="Path to CSE benign features CSV")
    ap.add_argument("--outdir", default="models/tabular/anomaly", help="Output directory")
    ap.add_argument("--contamination", type=float, default=0.05,
                    help="Expected proportion of outliers (0.01-0.1)")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Load CSE benign features
    df = pd.read_csv(args.csv)
    print(f"Loaded {len(df)} CSE benign samples")

    # Drop non-numeric columns
    drop_cols = [c for c in ['url', 'registrable'] if c in df.columns]
    X = df.drop(columns=drop_cols)

    # Convert any remaining non-numeric
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):
            X[c] = X[c].astype('category').cat.codes

    print(f"Training on {X.shape[1]} features")
    print(f"Features: {list(X.columns)}")

    # Train IsolationForest
    # Score: -1 = anomaly (phishing), 1 = normal (benign)
    model = Pipeline([
        ('scaler', StandardScaler()),
        ('detector', IsolationForest(
            n_estimators=200,
            contamination=args.contamination,
            random_state=42,
            n_jobs=-1
        ))
    ])

    model.fit(X.values)
    print(f"\nTrained IsolationForest with contamination={args.contamination}")

    # Test on training data (should be mostly inliers)
    scores = model.decision_function(X.values)
    predictions = model.predict(X.values)

    n_outliers = (predictions == -1).sum()
    print(f"\nOutliers detected in training set: {n_outliers}/{len(df)} ({100*n_outliers/len(df):.1f}%)")
    print(f"Score range: [{scores.min():.3f}, {scores.max():.3f}]")
    print(f"Mean score: {scores.mean():.3f}, Std: {scores.std():.3f}")

    # Save model
    joblib.dump(model, outdir / "anomaly_detector.joblib")

    # Save metadata
    metadata = {
        "model_type": "IsolationForest",
        "n_samples": len(df),
        "n_features": X.shape[1],
        "features": list(X.columns),
        "contamination": args.contamination,
        "n_outliers_in_training": int(n_outliers),
        "score_mean": float(scores.mean()),
        "score_std": float(scores.std()),
        "score_min": float(scores.min()),
        "score_max": float(scores.max())
    }

    (outdir / "metadata.json").write_text(json.dumps(metadata, indent=2))

    print(f"\nSaved model to {outdir / 'anomaly_detector.joblib'}")
    print(f"Saved metadata to {outdir / 'metadata.json'}")

    # Usage info
    print("\n" + "="*60)
    print("USAGE:")
    print("  score = model.decision_function(features)")
    print("  prediction = model.predict(features)")
    print("")
    print("  prediction == -1  =>  ANOMALY (potential phishing)")
    print("  prediction == 1   =>  NORMAL (similar to CSE sites)")
    print("")
    print("  Lower scores = more anomalous")
    print("  Higher scores = more similar to CSE baseline")
    print("="*60)

if __name__ == "__main__":
    main()
