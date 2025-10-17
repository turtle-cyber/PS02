"""
Threshold Optimization Using Precision-Recall Curves

Finds optimal thresholds (tau_low, tau_high) for three-class decision:
- Phishing: score >= tau_high (high precision required)
- Suspected: tau_low < score < tau_high (for manual review)
- Benign: score <= tau_low (high recall required)

Strategy:
- tau_high: Choose threshold where precision >= target_precision (e.g., 0.95)
- tau_low: Choose threshold where recall >= target_recall (e.g., 0.98)
"""

import argparse
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.metrics import (precision_recall_curve, roc_curve, auc,
                            f1_score, precision_score, recall_score,
                            confusion_matrix, classification_report)
import seaborn as sns


def plot_precision_recall_curve(y_true, scores, save_path, title="Precision-Recall Curve"):
    """Plot precision-recall curve"""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)

    plt.figure(figsize=(10, 6))
    plt.plot(recall, precision, 'b-', linewidth=2, label=f'PR Curve (AUC={auc(recall, precision):.3f})')
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title(title, fontsize=14)
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=11)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    return precision, recall, thresholds


def plot_roc_curve(y_true, scores, save_path, title="ROC Curve"):
    """Plot ROC curve"""
    fpr, tpr, thresholds = roc_curve(y_true, scores)
    roc_auc = auc(fpr, tpr)

    plt.figure(figsize=(10, 6))
    plt.plot(fpr, tpr, 'b-', linewidth=2, label=f'ROC Curve (AUC={roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], 'r--', linewidth=2, label='Random Classifier')
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title(title, fontsize=14)
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=11)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    return fpr, tpr, thresholds


def plot_threshold_metrics(y_true, scores, save_path, title="Metrics vs Threshold"):
    """Plot precision, recall, F1 vs threshold"""
    precision, recall, thresholds = precision_recall_curve(y_true, scores)

    # Compute F1 scores
    f1_scores = 2 * (precision[:-1] * recall[:-1]) / (precision[:-1] + recall[:-1] + 1e-8)

    plt.figure(figsize=(12, 6))
    plt.plot(thresholds, precision[:-1], 'b-', linewidth=2, label='Precision')
    plt.plot(thresholds, recall[:-1], 'r-', linewidth=2, label='Recall')
    plt.plot(thresholds, f1_scores, 'g-', linewidth=2, label='F1 Score')
    plt.xlabel('Threshold', fontsize=12)
    plt.ylabel('Score', fontsize=12)
    plt.title(title, fontsize=14)
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=11)
    plt.xlim([0, 1])
    plt.ylim([0, 1])
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    return precision, recall, f1_scores, thresholds


def plot_confusion_matrix(y_true, y_pred, save_path, labels=['Benign', 'Phishing'],
                         title="Confusion Matrix"):
    """Plot confusion matrix"""
    cm = confusion_matrix(y_true, y_pred)

    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=True,
                xticklabels=labels, yticklabels=labels)
    plt.xlabel('Predicted Label', fontsize=12)
    plt.ylabel('True Label', fontsize=12)
    plt.title(title, fontsize=14)
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

    return cm


def find_optimal_threshold_precision(precision, recall, thresholds, target_precision):
    """
    Find threshold where precision >= target_precision

    Returns highest threshold that achieves target precision
    """
    # precision array has one more element than thresholds
    precision = precision[:-1]
    recall = recall[:-1]

    valid_indices = np.where(precision >= target_precision)[0]

    if len(valid_indices) == 0:
        print(f"Warning: Cannot achieve precision >= {target_precision}")
        print(f"         Max precision: {precision.max():.4f}")
        # Return threshold at max precision
        return thresholds[np.argmax(precision)], precision.max()

    # Choose highest threshold (most conservative)
    idx = valid_indices[-1]
    return thresholds[idx], precision[idx]


def find_optimal_threshold_recall(precision, recall, thresholds, target_recall):
    """
    Find threshold where recall >= target_recall

    Returns lowest threshold that achieves target recall
    """
    # precision/recall arrays have one more element than thresholds
    precision = precision[:-1]
    recall = recall[:-1]

    valid_indices = np.where(recall >= target_recall)[0]

    if len(valid_indices) == 0:
        print(f"Warning: Cannot achieve recall >= {target_recall}")
        print(f"         Max recall: {recall.max():.4f}")
        # Return threshold at max recall
        return thresholds[np.argmax(recall)], recall.max()

    # Choose lowest threshold (most conservative for catching phishing)
    idx = valid_indices[0]
    return thresholds[idx], recall[idx]


def evaluate_three_class(y_true, scores, tau_low, tau_high):
    """
    Evaluate three-class classification

    Returns:
        metrics: dict with metrics
        predictions: array with values {0: benign, 1: phishing, -1: suspected}
    """
    # Make predictions
    predictions = np.where(scores >= tau_high, 1,
                          np.where(scores <= tau_low, 0, -1))

    # Count predictions
    n_benign = (predictions == 0).sum()
    n_phishing = (predictions == 1).sum()
    n_suspected = (predictions == -1).sum()

    # For binary metrics, treat "suspected" as phishing (conservative)
    preds_binary = np.where(predictions == -1, 1, predictions)

    # Compute metrics on confident predictions only
    confident_mask = (predictions != -1)

    if confident_mask.sum() == 0:
        return {
            'tau_low': tau_low,
            'tau_high': tau_high,
            'n_benign': int(n_benign),
            'n_phishing': int(n_phishing),
            'n_suspected': int(n_suspected),
            'coverage': 0.0,
            'accuracy': 0.0,
            'precision': 0.0,
            'recall': 0.0,
            'f1': 0.0
        }, predictions

    metrics = {
        'tau_low': tau_low,
        'tau_high': tau_high,
        'n_benign': int(n_benign),
        'n_phishing': int(n_phishing),
        'n_suspected': int(n_suspected),
        'coverage': float(confident_mask.mean()),
        'accuracy': float(precision_score(y_true[confident_mask],
                                          predictions[confident_mask],
                                          zero_division=0)),
        'precision': float(precision_score(y_true[confident_mask],
                                           predictions[confident_mask],
                                           zero_division=0)),
        'recall': float(recall_score(y_true[confident_mask],
                                     predictions[confident_mask],
                                     zero_division=0)),
        'f1': float(f1_score(y_true[confident_mask],
                            predictions[confident_mask],
                            zero_division=0))
    }

    return metrics, predictions


def main():
    parser = argparse.ArgumentParser(description="Optimize thresholds using PR curves")

    parser.add_argument("--val_csv", type=Path, required=True,
                       help="Validation CSV with columns: y_true, ensemble_score")
    parser.add_argument("--outdir", type=Path, required=True,
                       help="Output directory")

    # Target metrics for threshold selection
    parser.add_argument("--target_precision", type=float, default=0.95,
                       help="Target precision for tau_high (e.g., 0.95 = 95%% precision)")
    parser.add_argument("--target_recall", type=float, default=0.98,
                       help="Target recall for tau_low (e.g., 0.98 = catch 98%% of phishing)")

    # Alternative: specify thresholds directly
    parser.add_argument("--tau_low", type=float, default=None,
                       help="Manually specify tau_low (overrides target_recall)")
    parser.add_argument("--tau_high", type=float, default=None,
                       help="Manually specify tau_high (overrides target_precision)")

    args = parser.parse_args()

    # Create output directory
    args.outdir.mkdir(parents=True, exist_ok=True)

    # Load data
    print(f"Loading validation data from {args.val_csv}...")
    df = pd.read_csv(args.val_csv)

    required_cols = ['y_true', 'ensemble_score']
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}")

    y_true = df['y_true'].values
    scores = df['ensemble_score'].values

    print(f"Loaded {len(df)} samples")
    print(f"  Phishing: {(y_true == 1).sum()}")
    print(f"  Benign: {(y_true == 0).sum()}")
    print(f"  Score range: [{scores.min():.4f}, {scores.max():.4f}]")

    # Generate plots
    print("\nGenerating plots...")

    precision, recall, thresholds_pr = plot_precision_recall_curve(
        y_true, scores, args.outdir / "precision_recall_curve.png"
    )

    fpr, tpr, thresholds_roc = plot_roc_curve(
        y_true, scores, args.outdir / "roc_curve.png"
    )

    prec_thresh, rec_thresh, f1_thresh, thresholds_f1 = plot_threshold_metrics(
        y_true, scores, args.outdir / "threshold_metrics.png"
    )

    # Find optimal thresholds
    print("\n" + "="*60)
    print("THRESHOLD OPTIMIZATION")
    print("="*60)

    if args.tau_high is not None:
        tau_high = args.tau_high
        print(f"\nUsing manually specified tau_high: {tau_high:.4f}")
    else:
        tau_high, achieved_precision = find_optimal_threshold_precision(
            precision, recall, thresholds_pr, args.target_precision
        )
        print(f"\nFinding tau_high (for high precision):")
        print(f"  Target precision: {args.target_precision:.4f}")
        print(f"  Optimal tau_high: {tau_high:.4f}")
        print(f"  Achieved precision: {achieved_precision:.4f}")

    if args.tau_low is not None:
        tau_low = args.tau_low
        print(f"\nUsing manually specified tau_low: {tau_low:.4f}")
    else:
        tau_low, achieved_recall = find_optimal_threshold_recall(
            precision, recall, thresholds_pr, args.target_recall
        )
        print(f"\nFinding tau_low (for high recall):")
        print(f"  Target recall: {args.target_recall:.4f}")
        print(f"  Optimal tau_low: {tau_low:.4f}")
        print(f"  Achieved recall: {achieved_recall:.4f}")

    # Evaluate three-class performance
    print("\n" + "="*60)
    print("THREE-CLASS EVALUATION")
    print("="*60)

    metrics, predictions = evaluate_three_class(y_true, scores, tau_low, tau_high)

    print(f"\nThresholds:")
    print(f"  tau_low:  {metrics['tau_low']:.4f}")
    print(f"  tau_high: {metrics['tau_high']:.4f}")

    print(f"\nPrediction Distribution:")
    print(f"  Benign:    {metrics['n_benign']:5d} ({metrics['n_benign']/len(df)*100:.1f}%)")
    print(f"  Phishing:  {metrics['n_phishing']:5d} ({metrics['n_phishing']/len(df)*100:.1f}%)")
    print(f"  Suspected: {metrics['n_suspected']:5d} ({metrics['n_suspected']/len(df)*100:.1f}%)")

    print(f"\nPerformance (on confident predictions):")
    print(f"  Coverage:  {metrics['coverage']:.4f}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1 Score:  {metrics['f1']:.4f}")

    # Confusion matrix (excluding suspected)
    confident_mask = (predictions != -1)
    if confident_mask.sum() > 0:
        cm = plot_confusion_matrix(
            y_true[confident_mask],
            predictions[confident_mask],
            args.outdir / "confusion_matrix.png",
            labels=['Benign', 'Phishing'],
            title=f"Confusion Matrix (Confident Predictions Only)"
        )

        print(f"\nConfusion Matrix:")
        print(f"                Predicted")
        print(f"           Benign  Phishing")
        print(f"Actual")
        print(f"Benign     {cm[0,0]:5d}    {cm[0,1]:5d}")
        print(f"Phishing   {cm[1,0]:5d}    {cm[1,1]:5d}")

    # Save results
    results = {
        'thresholds': {
            'tau_low': float(tau_low),
            'tau_high': float(tau_high)
        },
        'targets': {
            'target_precision': args.target_precision,
            'target_recall': args.target_recall
        },
        'metrics': metrics
    }

    with open(args.outdir / "optimal_thresholds.json", 'w') as f:
        json.dump(results, f, indent=2)

    # Save predictions
    df['predicted_label'] = predictions
    df['predicted_class'] = np.where(predictions == 1, 'phishing',
                                     np.where(predictions == 0, 'benign', 'suspected'))
    df.to_csv(args.outdir / "predictions_with_thresholds.csv", index=False)

    print(f"\n✓ Results saved to {args.outdir}")
    print(f"  - optimal_thresholds.json")
    print(f"  - predictions_with_thresholds.csv")
    print(f"  - precision_recall_curve.png")
    print(f"  - roc_curve.png")
    print(f"  - threshold_metrics.png")
    print(f"  - confusion_matrix.png")


if __name__ == "__main__":
    main()
