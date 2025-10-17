"""
Ensemble Weight Optimization

Performs grid search to find optimal weights for multi-modal ensemble:
- w1: Tabular model weight
- w2: Text model weight
- w3: Vision model weight
- alpha: Brand similarity weight
- beta: Layout similarity weight

Constraint: w1 + w2 + w3 + alpha + beta <= 1.0

Optimizes for F1-score on validation set.
"""

import argparse
import json
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score, roc_auc_score
from itertools import product
import joblib
from tqdm import tqdm


def load_calibrators(cal_dir):
    """Load isotonic calibrators"""
    cal_dir = Path(cal_dir)
    calibrators = {}

    for head in ["p_urltab", "p_text", "p_vis"]:
        cal_path = cal_dir / f"cal_{head}.joblib"
        if cal_path.exists():
            calibrators[head] = joblib.load(cal_path)
        else:
            print(f"Warning: Calibrator not found for {head}, will use uncalibrated probabilities")
            calibrators[head] = None

    return calibrators


def calibrate_probs(p, calibrator):
    """Apply calibration if calibrator exists"""
    if calibrator is None:
        return p
    try:
        return calibrator.predict(p.reshape(-1, 1).flatten())
    except:
        return p


def compute_ensemble_score(row, weights, calibrators):
    """
    Compute final ensemble score for a single sample

    Args:
        row: DataFrame row with p_urltab, p_text, p_vis, brandSim, layoutSim
        weights: dict with keys w1, w2, w3, alpha, beta
        calibrators: dict of calibrators

    Returns:
        score: Final ensemble score (0-1)
    """
    # Calibrate probabilities
    p_urltab = calibrate_probs(np.array([row['p_urltab']]), calibrators['p_urltab'])[0]
    p_text = calibrate_probs(np.array([row.get('p_text', 0.0)]), calibrators['p_text'])[0] if 'p_text' in row else 0.0
    p_vis = calibrate_probs(np.array([row.get('p_vis', 0.0)]), calibrators['p_vis'])[0] if 'p_vis' in row else 0.0

    # Get similarity scores
    brandSim = row.get('brandSim', 0.0)
    layoutSim = row.get('layoutSim', 0.0)

    # Compute weighted ensemble
    score = (weights['w1'] * p_urltab +
             weights['w2'] * p_text +
             weights['w3'] * p_vis +
             weights['alpha'] * brandSim +
             weights['beta'] * layoutSim)

    return score


def evaluate_weights(df, weights, calibrators, tau_low=0.30, tau_high=0.70):
    """
    Evaluate ensemble performance with given weights

    Returns:
        metrics: dict with accuracy, precision, recall, f1, auc
        predictions: array of predicted labels
        scores: array of ensemble scores
    """
    # Compute scores for all samples
    scores = df.apply(lambda row: compute_ensemble_score(row, weights, calibrators), axis=1).values

    # Apply thresholds
    predictions = np.where(scores >= tau_high, 1,
                          np.where(scores <= tau_low, 0, -1))

    # For metric computation, treat "suspected" (-1) as phishing (conservative)
    preds_binary = np.where(predictions == -1, 1, predictions)

    # Compute metrics
    y_true = df['y_true'].values

    # Only compute metrics on non-suspected samples for fair comparison
    mask = predictions != -1
    if mask.sum() == 0:
        return {
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1': 0.0,
            'auc_roc': 0.0,
            'coverage': 0.0
        }, predictions, scores

    metrics = {
        'accuracy': accuracy_score(y_true[mask], predictions[mask]),
        'precision': precision_score(y_true[mask], predictions[mask], zero_division=0),
        'recall': recall_score(y_true[mask], predictions[mask], zero_division=0),
        'f1': f1_score(y_true[mask], predictions[mask], zero_division=0),
        'auc_roc': roc_auc_score(y_true, scores) if len(np.unique(y_true)) > 1 else 0.0,
        'coverage': mask.mean()  # Proportion of samples with confident predictions
    }

    return metrics, predictions, scores


def grid_search_weights(df, calibrators, param_grid, tau_low=0.30, tau_high=0.70,
                       metric='f1', verbose=True):
    """
    Grid search over weight combinations

    Args:
        df: DataFrame with columns y_true, p_urltab, p_text, p_vis, brandSim, layoutSim
        calibrators: dict of calibrators
        param_grid: dict with lists of values for w1, w2, w3, alpha, beta
        tau_low: Lower threshold for benign classification
        tau_high: Upper threshold for phishing classification
        metric: Metric to optimize ('f1', 'precision', 'recall', 'accuracy')
        verbose: Print progress

    Returns:
        best_weights: dict with optimal weights
        best_metrics: dict with metrics at optimal weights
        results: list of all evaluated combinations
    """
    # Generate all combinations
    keys = ['w1', 'w2', 'w3', 'alpha', 'beta']
    combinations = list(product(*[param_grid[k] for k in keys]))

    if verbose:
        print(f"Evaluating {len(combinations)} weight combinations...")

    results = []
    best_score = -1
    best_weights = None
    best_metrics = None

    for combo in tqdm(combinations, disable=not verbose):
        weights = dict(zip(keys, combo))

        # Check constraint: sum <= 1.0
        weight_sum = sum(weights.values())
        if weight_sum > 1.0:
            continue

        # Evaluate
        metrics, preds, scores = evaluate_weights(df, weights, calibrators, tau_low, tau_high)

        # Store results
        result = {
            **weights,
            'weight_sum': weight_sum,
            **metrics
        }
        results.append(result)

        # Track best
        if metrics[metric] > best_score:
            best_score = metrics[metric]
            best_weights = weights.copy()
            best_metrics = metrics.copy()

    if verbose:
        print(f"\n{'='*60}")
        print(f"Best {metric.upper()}: {best_score:.4f}")
        print(f"{'='*60}")
        print("Optimal Weights:")
        for k, v in best_weights.items():
            print(f"  {k}: {v:.3f}")
        print(f"\nWeight Sum: {sum(best_weights.values()):.3f}")
        print("\nBest Metrics:")
        for k, v in best_metrics.items():
            print(f"  {k}: {v:.4f}")

    return best_weights, best_metrics, results


def main():
    parser = argparse.ArgumentParser(description="Optimize ensemble weights")

    parser.add_argument("--val_csv", type=Path, required=True,
                       help="Validation set CSV with columns: y_true, p_urltab, p_text, p_vis, brandSim, layoutSim")
    parser.add_argument("--cal_dir", type=Path, required=True,
                       help="Directory containing calibrators")
    parser.add_argument("--outdir", type=Path, required=True,
                       help="Output directory")

    # Grid search parameters
    parser.add_argument("--w1_grid", default="0.3,0.4,0.5,0.6",
                       help="Comma-separated values for w1 (tabular)")
    parser.add_argument("--w2_grid", default="0.2,0.3,0.4",
                       help="Comma-separated values for w2 (text)")
    parser.add_argument("--w3_grid", default="0.05,0.1,0.15",
                       help="Comma-separated values for w3 (vision)")
    parser.add_argument("--alpha_grid", default="0.1,0.15,0.2",
                       help="Comma-separated values for alpha (brand similarity)")
    parser.add_argument("--beta_grid", default="0.1,0.15,0.2",
                       help="Comma-separated values for beta (layout similarity)")

    # Thresholds
    parser.add_argument("--tau_low", type=float, default=0.30,
                       help="Lower threshold for benign classification")
    parser.add_argument("--tau_high", type=float, default=0.70,
                       help="Upper threshold for phishing classification")

    # Optimization target
    parser.add_argument("--metric", default="f1", choices=['f1', 'precision', 'recall', 'accuracy'],
                       help="Metric to optimize")

    args = parser.parse_args()

    # Create output directory
    args.outdir.mkdir(parents=True, exist_ok=True)

    # Load data
    print(f"Loading validation data from {args.val_csv}...")
    df = pd.read_csv(args.val_csv)

    # Validate required columns
    required_cols = ['y_true', 'p_urltab']
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")

    print(f"Loaded {len(df)} samples")
    print(f"  Phishing: {(df['y_true'] == 1).sum()}")
    print(f"  Benign: {(df['y_true'] == 0).sum()}")

    # Load calibrators
    print(f"\nLoading calibrators from {args.cal_dir}...")
    calibrators = load_calibrators(args.cal_dir)

    # Parse grid
    param_grid = {
        'w1': [float(x) for x in args.w1_grid.split(',')],
        'w2': [float(x) for x in args.w2_grid.split(',')],
        'w3': [float(x) for x in args.w3_grid.split(',')],
        'alpha': [float(x) for x in args.alpha_grid.split(',')],
        'beta': [float(x) for x in args.beta_grid.split(',')],
    }

    print(f"\nGrid Search Configuration:")
    for k, v in param_grid.items():
        print(f"  {k}: {v}")

    # Run grid search
    print(f"\nOptimizing for: {args.metric.upper()}")
    print(f"Thresholds: tau_low={args.tau_low}, tau_high={args.tau_high}\n")

    best_weights, best_metrics, results = grid_search_weights(
        df, calibrators, param_grid,
        tau_low=args.tau_low,
        tau_high=args.tau_high,
        metric=args.metric,
        verbose=True
    )

    # Save results
    with open(args.outdir / "optimal_weights.json", 'w') as f:
        json.dump({
            'weights': best_weights,
            'metrics': best_metrics,
            'thresholds': {'tau_low': args.tau_low, 'tau_high': args.tau_high},
            'optimization_metric': args.metric
        }, f, indent=2)

    # Save all results as CSV
    results_df = pd.DataFrame(results)
    results_df = results_df.sort_values(args.metric, ascending=False)
    results_df.to_csv(args.outdir / "grid_search_results.csv", index=False)

    # Print top 10 configurations
    print(f"\n{'='*60}")
    print(f"Top 10 Configurations by {args.metric.upper()}:")
    print(f"{'='*60}")
    print(results_df.head(10).to_string(index=False))

    print(f"\n✓ Results saved to {args.outdir}")
    print(f"  - optimal_weights.json")
    print(f"  - grid_search_results.csv")


if __name__ == "__main__":
    main()
