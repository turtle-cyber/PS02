"""
SHAP Explainability for Phishing Detection

Generates SHAP explanations for individual predictions and global feature importance.
Helps security analysts understand WHY a page was flagged as phishing.
"""

import argparse
import json
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
import matplotlib.pyplot as plt
import shap
import warnings
warnings.filterwarnings('ignore')


def load_model_and_data(model_path, data_csv):
    """Load trained model and data"""
    model = joblib.load(model_path)

    df = pd.read_csv(data_csv)

    # Drop string/meta columns
    drop_cols = [c for c in ['original_url', 'url_norm', 'hostname',
                              'registered_domain', 'domain', 'subdomain', 'tld', 'label']
                 if c in df.columns]

    X = df.drop(columns=drop_cols, errors='ignore').copy()

    # Convert non-numeric columns
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):
            X[c] = X[c].astype('category').cat.codes

    # Get labels if they exist
    y = df['label'].map({'benign': 0, 'phishing': 1}).astype(int) if 'label' in df.columns else None

    return model, X, y, df


def plot_global_feature_importance(shap_values, features, save_path, top_n=20):
    """
    Plot global feature importance using mean absolute SHAP values

    Args:
        shap_values: SHAP values array
        features: DataFrame with feature names
        save_path: Where to save plot
        top_n: Number of top features to show
    """
    # Compute mean absolute SHAP value for each feature
    mean_abs_shap = np.abs(shap_values).mean(axis=0)

    # Get top features
    top_indices = np.argsort(mean_abs_shap)[-top_n:]
    top_features = features.columns[top_indices]
    top_values = mean_abs_shap[top_indices]

    # Plot
    fig, ax = plt.subplots(figsize=(10, max(8, top_n * 0.4)))
    y_pos = np.arange(len(top_features))

    ax.barh(y_pos, top_values, color='steelblue', alpha=0.7)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(top_features, fontsize=10)
    ax.set_xlabel('Mean |SHAP Value| (Average Impact on Model Output)', fontsize=12)
    ax.set_title(f'Top {top_n} Most Important Features', fontsize=14, fontweight='bold')
    ax.grid(True, alpha=0.3, axis='x')

    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"✓ Saved global feature importance to {save_path}")


def plot_summary_plot(shap_values, features, save_path, top_n=20):
    """
    SHAP summary plot showing feature importance and value distribution

    Args:
        shap_values: SHAP values array
        features: DataFrame with feature values
        save_path: Where to save plot
        top_n: Number of features to show
    """
    plt.figure(figsize=(12, max(8, top_n * 0.4)))

    shap.summary_plot(
        shap_values,
        features,
        max_display=top_n,
        show=False,
        plot_size=(12, max(8, top_n * 0.4))
    )

    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"✓ Saved SHAP summary plot to {save_path}")


def explain_prediction(shap_values, features, sample_idx, base_value, prediction,
                      save_path, top_n=10):
    """
    Generate explanation for a single prediction

    Args:
        shap_values: SHAP values for this sample
        features: Feature DataFrame
        sample_idx: Index of sample
        base_value: Base/expected value
        prediction: Model prediction
        save_path: Where to save plot
        top_n: Number of top features to show
    """
    # Get SHAP values for this sample
    sample_shap = shap_values[sample_idx]
    sample_features = features.iloc[sample_idx]

    # Sort by absolute SHAP value
    sorted_indices = np.argsort(np.abs(sample_shap))[-top_n:][::-1]

    # Create explanation text
    explanation = []
    explanation.append(f"Prediction: {prediction:.4f} (Phishing Probability)")
    explanation.append(f"Base Value: {base_value:.4f}")
    explanation.append(f"\nTop {top_n} Contributing Features:\n")

    for i, idx in enumerate(sorted_indices, 1):
        feature_name = features.columns[idx]
        feature_value = sample_features.iloc[idx]
        shap_value = sample_shap[idx]
        direction = "↑ Increases" if shap_value > 0 else "↓ Decreases"

        explanation.append(
            f"{i:2d}. {feature_name:<30s} = {feature_value:>10.4f} | "
            f"SHAP: {shap_value:>+8.4f} {direction} phishing score"
        )

    # Create waterfall plot
    plt.figure(figsize=(10, max(6, top_n * 0.5)))

    shap.waterfall_plot(
        shap.Explanation(
            values=sample_shap,
            base_values=base_value,
            data=sample_features.values,
            feature_names=features.columns.tolist()
        ),
        max_display=top_n,
        show=False
    )

    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    return "\n".join(explanation)


def main():
    parser = argparse.ArgumentParser(description="Generate SHAP explanations")

    parser.add_argument("--model_path", type=Path, required=True,
                       help="Path to trained model (.joblib)")
    parser.add_argument("--data_csv", type=Path, required=True,
                       help="Data CSV for explanation")
    parser.add_argument("--outdir", type=Path, required=True,
                       help="Output directory")

    # Analysis options
    parser.add_argument("--sample_size", type=int, default=100,
                       help="Sample size for SHAP computation (smaller = faster)")
    parser.add_argument("--explain_samples", type=int, default=5,
                       help="Number of individual samples to explain")
    parser.add_argument("--top_features", type=int, default=20,
                       help="Number of top features to show in plots")

    # Advanced options
    parser.add_argument("--background_samples", type=int, default=100,
                       help="Background samples for SHAP TreeExplainer")

    args = parser.parse_args()

    # Create output directory
    args.outdir.mkdir(parents=True, exist_ok=True)

    print("="*60)
    print("SHAP EXPLAINABILITY ANALYSIS")
    print("="*60)

    # Load model and data
    print(f"\nLoading model from {args.model_path}...")
    model, X, y, df_original = load_model_and_data(args.model_path, args.data_csv)

    print(f"Loaded {len(X)} samples with {X.shape[1]} features")

    # Sample data if needed (for performance)
    if len(X) > args.sample_size:
        print(f"Sampling {args.sample_size} rows for SHAP analysis...")
        sample_indices = np.random.choice(len(X), args.sample_size, replace=False)
        X_sample = X.iloc[sample_indices]
        y_sample = y.iloc[sample_indices] if y is not None else None
    else:
        X_sample = X
        y_sample = y
        sample_indices = np.arange(len(X))

    # Get model predictions
    print("\nGenerating predictions...")

    # Handle sklearn Pipeline
    if hasattr(model, 'predict_proba'):
        predictions = model.predict_proba(X_sample.values)[:, 1]
    else:
        raise ValueError("Model must have predict_proba method")

    # Create SHAP explainer
    print("\nInitializing SHAP explainer...")
    print("(This may take a few minutes for large models...)")

    # Use TreeExplainer for tree-based models (XGBoost, RF, etc.)
    # Extract the final estimator from pipeline if needed
    if hasattr(model, 'named_steps'):
        final_estimator = model.named_steps['clf']
    else:
        final_estimator = model

    # Sample background data for faster computation
    if len(X_sample) > args.background_samples:
        background = X_sample.sample(n=args.background_samples, random_state=42)
    else:
        background = X_sample

    explainer = shap.TreeExplainer(
        final_estimator,
        data=background.values,
        feature_names=X_sample.columns.tolist()
    )

    # Compute SHAP values
    print("\nComputing SHAP values...")

    # Transform data through pipeline if needed (e.g., imputation)
    if hasattr(model, 'named_steps'):
        X_transformed = model[:-1].transform(X_sample.values)  # All steps except classifier
    else:
        X_transformed = X_sample.values

    shap_values = explainer.shap_values(X_transformed)

    # Handle multi-class output (take phishing class)
    if isinstance(shap_values, list):
        shap_values = shap_values[1]  # Phishing class

    print(f"✓ Computed SHAP values shape: {shap_values.shape}")

    # Generate global explanations
    print("\n" + "="*60)
    print("GLOBAL FEATURE IMPORTANCE")
    print("="*60)

    plot_global_feature_importance(
        shap_values, X_sample,
        args.outdir / "global_feature_importance.png",
        top_n=args.top_features
    )

    plot_summary_plot(
        shap_values, X_sample,
        args.outdir / "shap_summary_plot.png",
        top_n=args.top_features
    )

    # Compute feature importance ranking
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    feature_importance = pd.DataFrame({
        'feature': X_sample.columns,
        'mean_abs_shap': mean_abs_shap
    }).sort_values('mean_abs_shap', ascending=False)

    feature_importance.to_csv(
        args.outdir / "feature_importance.csv", index=False
    )

    print("\nTop 10 Most Important Features:")
    for i, row in feature_importance.head(10).iterrows():
        print(f"  {row['feature']:<30s}: {row['mean_abs_shap']:.6f}")

    # Explain individual samples
    print("\n" + "="*60)
    print("INDIVIDUAL SAMPLE EXPLANATIONS")
    print("="*60)

    # Choose interesting samples to explain
    # Explain: highest phishing prob, lowest, and some in between
    sorted_indices = np.argsort(predictions)

    samples_to_explain = []

    # Highest phishing probability
    samples_to_explain.append(('highest_phishing', sorted_indices[-1]))

    # Lowest phishing probability
    samples_to_explain.append(('lowest_phishing', sorted_indices[0]))

    # Middle samples
    if args.explain_samples > 2:
        n_middle = args.explain_samples - 2
        middle_indices = np.linspace(0, len(sorted_indices)-1, n_middle+2, dtype=int)[1:-1]
        for i, idx in enumerate(middle_indices):
            samples_to_explain.append((f'middle_{i+1}', sorted_indices[idx]))

    explanations_summary = []

    for label, sample_idx in samples_to_explain:
        print(f"\nExplaining sample: {label} (index {sample_idx})")

        pred = predictions[sample_idx]
        base_value = explainer.expected_value

        if isinstance(base_value, np.ndarray):
            base_value = base_value[1]  # Phishing class

        explanation_text = explain_prediction(
            shap_values, X_sample, sample_idx, base_value, pred,
            args.outdir / f"explanation_{label}.png",
            top_n=10
        )

        print(explanation_text)

        explanations_summary.append({
            'label': label,
            'sample_idx': int(sample_indices[sample_idx]),
            'prediction': float(pred),
            'true_label': int(y_sample.iloc[sample_idx]) if y_sample is not None else None,
            'explanation': explanation_text
        })

    # Save explanations
    with open(args.outdir / "individual_explanations.json", 'w') as f:
        json.dump(explanations_summary, f, indent=2)

    # Summary statistics
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)

    print(f"\n✓ Analysis complete!")
    print(f"\nGenerated files:")
    print(f"  - global_feature_importance.png (bar chart)")
    print(f"  - shap_summary_plot.png (detailed summary)")
    print(f"  - feature_importance.csv (ranked features)")
    print(f"  - explanation_*.png ({len(samples_to_explain)} waterfall plots)")
    print(f"  - individual_explanations.json (text explanations)")

    print(f"\nAll results saved to: {args.outdir}")


if __name__ == "__main__":
    main()
