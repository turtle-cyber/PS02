"""
Calibration Validation - Reliability Diagrams

Validates isotonic regression calibration by checking:
1. Reliability (calibration) curves
2. Expected Calibration Error (ECE)
3. Brier score
4. Calibration across probability bins

Generates visualizations to assess calibration quality.
"""

import argparse
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.calibration import calibration_curve
from sklearn.metrics import brier_score_loss, log_loss
import seaborn as sns
import joblib


def compute_ece(y_true, y_prob, n_bins=10):
    """
    Compute Expected Calibration Error (ECE)

    ECE = sum of |accuracy - confidence| weighted by bin size

    Args:
        y_true: True labels
        y_prob: Predicted probabilities
        n_bins: Number of bins

    Returns:
        ece: Expected Calibration Error
        bin_stats: dict with per-bin statistics
    """
    bin_boundaries = np.linspace(0, 1, n_bins + 1)
    bin_lowers = bin_boundaries[:-1]
    bin_uppers = bin_boundaries[1:]

    ece = 0.0
    bin_stats = []

    for bin_lower, bin_upper in zip(bin_lowers, bin_uppers):
        # Find samples in this bin
        in_bin = np.logical_and(y_prob > bin_lower, y_prob <= bin_upper)

        if in_bin.sum() == 0:
            bin_stats.append({
                'bin_lower': float(bin_lower),
                'bin_upper': float(bin_upper),
                'count': 0,
                'accuracy': 0.0,
                'confidence': 0.0,
                'difference': 0.0
            })
            continue

        # Compute accuracy and confidence in this bin
        bin_acc = y_true[in_bin].mean()
        bin_conf = y_prob[in_bin].mean()
        bin_count = in_bin.sum()

        # Add to ECE (weighted by proportion of samples in bin)
        ece += (bin_count / len(y_true)) * np.abs(bin_acc - bin_conf)

        bin_stats.append({
            'bin_lower': float(bin_lower),
            'bin_upper': float(bin_upper),
            'count': int(bin_count),
            'accuracy': float(bin_acc),
            'confidence': float(bin_conf),
            'difference': float(np.abs(bin_acc - bin_conf))
        })

    return ece, bin_stats


def plot_reliability_curve(y_true, y_prob_uncal, y_prob_cal, save_path,
                          title="Reliability Diagram", n_bins=10):
    """
    Plot reliability (calibration) curve

    Shows how well predicted probabilities match actual outcomes.
    Perfect calibration = diagonal line.
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Compute calibration curves
    prob_true_uncal, prob_pred_uncal = calibration_curve(
        y_true, y_prob_uncal, n_bins=n_bins, strategy='uniform'
    )
    prob_true_cal, prob_pred_cal = calibration_curve(
        y_true, y_prob_cal, n_bins=n_bins, strategy='uniform'
    )

    # Plot uncalibrated
    ax1.plot([0, 1], [0, 1], 'k--', linewidth=2, label='Perfect Calibration')
    ax1.plot(prob_pred_uncal, prob_true_uncal, 's-', linewidth=2,
            label=f'Uncalibrated', markersize=8)
    ax1.set_xlabel('Predicted Probability', fontsize=12)
    ax1.set_ylabel('Actual Probability', fontsize=12)
    ax1.set_title('Before Calibration', fontsize=14)
    ax1.legend(fontsize=11)
    ax1.grid(True, alpha=0.3)
    ax1.set_xlim([0, 1])
    ax1.set_ylim([0, 1])

    # Plot calibrated
    ax2.plot([0, 1], [0, 1], 'k--', linewidth=2, label='Perfect Calibration')
    ax2.plot(prob_pred_cal, prob_true_cal, 's-', linewidth=2,
            label=f'Calibrated', color='green', markersize=8)
    ax2.set_xlabel('Predicted Probability', fontsize=12)
    ax2.set_ylabel('Actual Probability', fontsize=12)
    ax2.set_title('After Calibration', fontsize=14)
    ax2.legend(fontsize=11)
    ax2.grid(True, alpha=0.3)
    ax2.set_xlim([0, 1])
    ax2.set_ylim([0, 1])

    plt.suptitle(title, fontsize=16, y=1.02)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_ece_comparison(ece_uncal, ece_cal, bin_stats_uncal, bin_stats_cal, save_path):
    """Plot ECE comparison and per-bin calibration errors"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Bar chart: ECE comparison
    ax1.bar(['Uncalibrated', 'Calibrated'], [ece_uncal, ece_cal],
           color=['orange', 'green'], alpha=0.7)
    ax1.set_ylabel('Expected Calibration Error', fontsize=12)
    ax1.set_title('ECE Comparison', fontsize=14)
    ax1.grid(True, alpha=0.3, axis='y')

    # Add values on bars
    for i, (label, ece) in enumerate([('Uncalibrated', ece_uncal), ('Calibrated', ece_cal)]):
        ax1.text(i, ece + 0.005, f'{ece:.4f}', ha='center', fontsize=11)

    # Per-bin calibration error
    bins_uncal = [f"{b['bin_lower']:.1f}-{b['bin_upper']:.1f}"
                  for b in bin_stats_uncal if b['count'] > 0]
    diffs_uncal = [b['difference'] for b in bin_stats_uncal if b['count'] > 0]
    diffs_cal = [b['difference'] for b in bin_stats_cal if b['count'] > 0]

    x = np.arange(len(bins_uncal))
    width = 0.35

    ax2.bar(x - width/2, diffs_uncal, width, label='Uncalibrated',
           color='orange', alpha=0.7)
    ax2.bar(x + width/2, diffs_cal, width, label='Calibrated',
           color='green', alpha=0.7)

    ax2.set_xlabel('Probability Bin', fontsize=12)
    ax2.set_ylabel('|Accuracy - Confidence|', fontsize=12)
    ax2.set_title('Per-Bin Calibration Error', fontsize=14)
    ax2.set_xticks(x)
    ax2.set_xticklabels(bins_uncal, rotation=45, ha='right')
    ax2.legend(fontsize=11)
    ax2.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()


def plot_probability_distributions(y_true, y_prob_uncal, y_prob_cal, save_path):
    """Plot probability distributions for phishing vs benign classes"""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # Uncalibrated - Phishing
    axes[0, 0].hist(y_prob_uncal[y_true == 1], bins=30, color='red',
                   alpha=0.7, edgecolor='black')
    axes[0, 0].set_xlabel('Predicted Probability', fontsize=11)
    axes[0, 0].set_ylabel('Count', fontsize=11)
    axes[0, 0].set_title('Uncalibrated - Phishing Class', fontsize=12)
    axes[0, 0].axvline(0.5, color='k', linestyle='--', alpha=0.5)
    axes[0, 0].grid(True, alpha=0.3)

    # Uncalibrated - Benign
    axes[0, 1].hist(y_prob_uncal[y_true == 0], bins=30, color='blue',
                   alpha=0.7, edgecolor='black')
    axes[0, 1].set_xlabel('Predicted Probability', fontsize=11)
    axes[0, 1].set_ylabel('Count', fontsize=11)
    axes[0, 1].set_title('Uncalibrated - Benign Class', fontsize=12)
    axes[0, 1].axvline(0.5, color='k', linestyle='--', alpha=0.5)
    axes[0, 1].grid(True, alpha=0.3)

    # Calibrated - Phishing
    axes[1, 0].hist(y_prob_cal[y_true == 1], bins=30, color='red',
                   alpha=0.7, edgecolor='black')
    axes[1, 0].set_xlabel('Predicted Probability', fontsize=11)
    axes[1, 0].set_ylabel('Count', fontsize=11)
    axes[1, 0].set_title('Calibrated - Phishing Class', fontsize=12)
    axes[1, 0].axvline(0.5, color='k', linestyle='--', alpha=0.5)
    axes[1, 0].grid(True, alpha=0.3)

    # Calibrated - Benign
    axes[1, 1].hist(y_prob_cal[y_true == 0], bins=30, color='blue',
                   alpha=0.7, edgecolor='black')
    axes[1, 1].set_xlabel('Predicted Probability', fontsize=11)
    axes[1, 1].set_ylabel('Count', fontsize=11)
    axes[1, 1].set_title('Calibrated - Benign Class', fontsize=12)
    axes[1, 1].axvline(0.5, color='k', linestyle='--', alpha=0.5)
    axes[1, 1].grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()


def main():
    parser = argparse.ArgumentParser(description="Validate calibration quality")

    parser.add_argument("--val_csv", type=Path, required=True,
                       help="Validation CSV with columns: y_true, p_uncalibrated, p_calibrated")
    parser.add_argument("--outdir", type=Path, required=True,
                       help="Output directory")
    parser.add_argument("--n_bins", type=int, default=10,
                       help="Number of bins for calibration analysis")

    args = parser.parse_args()

    # Create output directory
    args.outdir.mkdir(parents=True, exist_ok=True)

    # Load data
    print(f"Loading validation data from {args.val_csv}...")
    df = pd.read_csv(args.val_csv)

    required_cols = ['y_true', 'p_uncalibrated', 'p_calibrated']
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")

    y_true = df['y_true'].values
    y_prob_uncal = df['p_uncalibrated'].values
    y_prob_cal = df['p_calibrated'].values

    print(f"Loaded {len(df)} samples")
    print(f"  Phishing: {(y_true == 1).sum()}")
    print(f"  Benign: {(y_true == 0).sum()}")

    # Compute ECE
    print("\n" + "="*60)
    print("CALIBRATION METRICS")
    print("="*60)

    ece_uncal, bin_stats_uncal = compute_ece(y_true, y_prob_uncal, n_bins=args.n_bins)
    ece_cal, bin_stats_cal = compute_ece(y_true, y_prob_cal, n_bins=args.n_bins)

    print(f"\nExpected Calibration Error (ECE):")
    print(f"  Uncalibrated: {ece_uncal:.4f}")
    print(f"  Calibrated:   {ece_cal:.4f}")
    print(f"  Improvement:  {(ece_uncal - ece_cal):.4f} ({(1 - ece_cal/ece_uncal)*100:.1f}% reduction)")

    # Compute Brier score
    brier_uncal = brier_score_loss(y_true, y_prob_uncal)
    brier_cal = brier_score_loss(y_true, y_prob_cal)

    print(f"\nBrier Score:")
    print(f"  Uncalibrated: {brier_uncal:.4f}")
    print(f"  Calibrated:   {brier_cal:.4f}")
    print(f"  Improvement:  {(brier_uncal - brier_cal):.4f}")

    # Compute log loss
    logloss_uncal = log_loss(y_true, y_prob_uncal)
    logloss_cal = log_loss(y_true, y_prob_cal)

    print(f"\nLog Loss:")
    print(f"  Uncalibrated: {logloss_uncal:.4f}")
    print(f"  Calibrated:   {logloss_cal:.4f}")
    print(f"  Improvement:  {(logloss_uncal - logloss_cal):.4f}")

    # Print per-bin statistics
    print(f"\n{'='*60}")
    print(f"PER-BIN CALIBRATION (Calibrated Probabilities)")
    print(f"{'='*60}")
    print(f"{'Bin':<12} {'Count':<8} {'Accuracy':<10} {'Confidence':<10} {'|Diff|':<10}")
    print("-" * 60)

    for stats in bin_stats_cal:
        if stats['count'] > 0:
            bin_range = f"{stats['bin_lower']:.1f}-{stats['bin_upper']:.1f}"
            print(f"{bin_range:<12} {stats['count']:<8} "
                  f"{stats['accuracy']:<10.4f} {stats['confidence']:<10.4f} "
                  f"{stats['difference']:<10.4f}")

    # Generate plots
    print(f"\n{'='*60}")
    print(f"GENERATING PLOTS")
    print(f"{'='*60}")

    print("Generating reliability curves...")
    plot_reliability_curve(
        y_true, y_prob_uncal, y_prob_cal,
        args.outdir / "reliability_diagram.png",
        n_bins=args.n_bins
    )

    print("Generating ECE comparison...")
    plot_ece_comparison(
        ece_uncal, ece_cal, bin_stats_uncal, bin_stats_cal,
        args.outdir / "ece_comparison.png"
    )

    print("Generating probability distributions...")
    plot_probability_distributions(
        y_true, y_prob_uncal, y_prob_cal,
        args.outdir / "probability_distributions.png"
    )

    # Save metrics
    results = {
        'ece': {
            'uncalibrated': float(ece_uncal),
            'calibrated': float(ece_cal),
            'improvement': float(ece_uncal - ece_cal),
            'improvement_pct': float((1 - ece_cal/ece_uncal) * 100)
        },
        'brier_score': {
            'uncalibrated': float(brier_uncal),
            'calibrated': float(brier_cal),
            'improvement': float(brier_uncal - brier_cal)
        },
        'log_loss': {
            'uncalibrated': float(logloss_uncal),
            'calibrated': float(logloss_cal),
            'improvement': float(logloss_uncal - logloss_cal)
        },
        'bin_statistics': {
            'uncalibrated': bin_stats_uncal,
            'calibrated': bin_stats_cal
        }
    }

    with open(args.outdir / "calibration_metrics.json", 'w') as f:
        json.dump(results, f, indent=2)

    # Assessment
    print(f"\n{'='*60}")
    print(f"CALIBRATION ASSESSMENT")
    print(f"{'='*60}")

    if ece_cal < 0.05:
        quality = "EXCELLENT"
        color = "✓"
    elif ece_cal < 0.10:
        quality = "GOOD"
        color = "✓"
    elif ece_cal < 0.15:
        quality = "ACCEPTABLE"
        color = "⚠"
    else:
        quality = "POOR"
        color = "✗"

    print(f"\n{color} Calibration Quality: {quality}")
    print(f"  ECE = {ece_cal:.4f}")
    print(f"  (Lower is better: <0.05 = excellent, <0.10 = good, <0.15 = acceptable)")

    if ece_cal >= ece_uncal:
        print(f"\n⚠ WARNING: Calibration did not improve ECE!")
        print(f"  This suggests the calibrator may be overfitting or using insufficient data.")

    print(f"\n✓ Results saved to {args.outdir}")
    print(f"  - calibration_metrics.json")
    print(f"  - reliability_diagram.png")
    print(f"  - ece_comparison.png")
    print(f"  - probability_distributions.png")


if __name__ == "__main__":
    main()
