"""
XGBoost Hyperparameter Tuning

Uses RandomizedSearchCV with cross-validation to find optimal hyperparameters.
Optimizes for F1-score on validation set.
"""

import argparse
import json
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import make_scorer, f1_score, precision_score, recall_score, accuracy_score, roc_auc_score
from xgboost import XGBClassifier
from scipy.stats import uniform, randint


def load_xy(csv_path: Path):
    """Load features and labels from CSV"""
    df = pd.read_csv(csv_path)

    # Drop string/meta columns
    drop_cols = [c for c in ['original_url', 'url_norm', 'hostname',
                              'registered_domain', 'domain', 'subdomain', 'tld']
                 if c in df.columns]

    y = df['label'].map({'benign': 0, 'phishing': 1}).astype(int)
    X = df.drop(columns=drop_cols + ['label']).copy()

    # Convert non-numeric columns to category codes
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):
            X[c] = X[c].astype('category').cat.codes

    return X, y


def get_param_distributions(search_space='wide'):
    """
    Get parameter distributions for RandomizedSearchCV

    Args:
        search_space: 'wide' for broad search, 'narrow' for focused search

    Returns:
        param_distributions: dict of parameter distributions
    """
    if search_space == 'wide':
        # Broad search space
        param_distributions = {
            'clf__n_estimators': randint(200, 800),
            'clf__max_depth': randint(3, 10),
            'clf__learning_rate': uniform(0.01, 0.09),  # 0.01 to 0.10
            'clf__subsample': uniform(0.6, 0.35),  # 0.6 to 0.95
            'clf__colsample_bytree': uniform(0.6, 0.35),  # 0.6 to 0.95
            'clf__reg_lambda': uniform(0.1, 4.9),  # 0.1 to 5.0
            'clf__reg_alpha': uniform(0.0, 2.0),  # 0.0 to 2.0
            'clf__gamma': uniform(0.0, 5.0),  # 0.0 to 5.0
            'clf__min_child_weight': randint(1, 10),
        }
    else:  # narrow
        # Focused search around reasonable defaults
        param_distributions = {
            'clf__n_estimators': randint(400, 700),
            'clf__max_depth': randint(4, 8),
            'clf__learning_rate': uniform(0.03, 0.05),  # 0.03 to 0.08
            'clf__subsample': uniform(0.7, 0.2),  # 0.7 to 0.9
            'clf__colsample_bytree': uniform(0.7, 0.2),  # 0.7 to 0.9
            'clf__reg_lambda': uniform(0.5, 2.5),  # 0.5 to 3.0
            'clf__reg_alpha': uniform(0.0, 1.0),  # 0.0 to 1.0
            'clf__gamma': uniform(0.0, 2.0),  # 0.0 to 2.0
            'clf__min_child_weight': randint(1, 5),
        }

    return param_distributions


def evaluate_model(model, X_val, y_val):
    """
    Evaluate model on validation set

    Returns:
        metrics: dict with comprehensive metrics
    """
    y_pred = model.predict(X_val)
    y_proba = model.predict_proba(X_val)[:, 1]

    metrics = {
        'accuracy': float(accuracy_score(y_val, y_pred)),
        'precision': float(precision_score(y_val, y_pred, zero_division=0)),
        'recall': float(recall_score(y_val, y_pred, zero_division=0)),
        'f1': float(f1_score(y_val, y_pred, zero_division=0)),
        'auc_roc': float(roc_auc_score(y_val, y_proba))
    }

    return metrics


def main():
    parser = argparse.ArgumentParser(description="Tune XGBoost hyperparameters")

    parser.add_argument("--train_csv", type=Path, required=True,
                       help="Training data CSV")
    parser.add_argument("--val_csv", type=Path, default=None,
                       help="Validation data CSV (optional, for final evaluation)")
    parser.add_argument("--outdir", type=Path, required=True,
                       help="Output directory")

    # Tuning parameters
    parser.add_argument("--n_iter", type=int, default=100,
                       help="Number of parameter combinations to try")
    parser.add_argument("--cv_folds", type=int, default=5,
                       help="Number of cross-validation folds")
    parser.add_argument("--search_space", choices=['wide', 'narrow'], default='wide',
                       help="Search space: 'wide' for broad search, 'narrow' for focused")
    parser.add_argument("--metric", default='f1',
                       choices=['f1', 'precision', 'recall', 'roc_auc'],
                       help="Metric to optimize")
    parser.add_argument("--n_jobs", type=int, default=4,
                       help="Number of parallel jobs")

    # XGBoost fixed parameters
    parser.add_argument("--objective", default="binary:logistic",
                       help="XGBoost objective")
    parser.add_argument("--eval_metric", default="logloss",
                       help="XGBoost evaluation metric")

    args = parser.parse_args()

    # Create output directory
    args.outdir.mkdir(parents=True, exist_ok=True)

    # Load training data
    print(f"Loading training data from {args.train_csv}...")
    X_train, y_train = load_xy(args.train_csv)

    print(f"Training set: {len(X_train)} samples")
    print(f"  Features: {X_train.shape[1]}")
    print(f"  Phishing: {(y_train == 1).sum()}")
    print(f"  Benign: {(y_train == 0).sum()}")

    # Load validation data if provided
    if args.val_csv:
        print(f"\nLoading validation data from {args.val_csv}...")
        X_val, y_val = load_xy(args.val_csv)
        print(f"Validation set: {len(X_val)} samples")
        print(f"  Phishing: {(y_val == 1).sum()}")
        print(f"  Benign: {(y_val == 0).sum()}")
    else:
        X_val, y_val = None, None

    # Build pipeline
    imputer = SimpleImputer(strategy="median")
    clf = XGBClassifier(
        objective=args.objective,
        eval_metric=args.eval_metric,
        random_state=42,
        n_jobs=1,  # Set to 1 to allow parallelization at CV level
        tree_method='hist',  # Faster training
        class_weight='balanced'  # Handle class imbalance
    )

    pipeline = Pipeline([
        ('imputer', imputer),
        ('clf', clf)
    ])

    # Get parameter distributions
    param_distributions = get_param_distributions(args.search_space)

    print(f"\n{'='*60}")
    print(f"HYPERPARAMETER TUNING")
    print(f"{'='*60}")
    print(f"Search space: {args.search_space}")
    print(f"Iterations: {args.n_iter}")
    print(f"CV folds: {args.cv_folds}")
    print(f"Optimization metric: {args.metric}")
    print(f"Parallel jobs: {args.n_jobs}")

    # Setup cross-validation
    cv = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=42)

    # Setup scoring
    scoring = {
        'accuracy': make_scorer(accuracy_score),
        'precision': make_scorer(precision_score, zero_division=0),
        'recall': make_scorer(recall_score, zero_division=0),
        'f1': make_scorer(f1_score, zero_division=0),
        'roc_auc': make_scorer(roc_auc_score, needs_proba=True)
    }

    # Run RandomizedSearchCV
    print(f"\nStarting randomized search...\n")

    random_search = RandomizedSearchCV(
        pipeline,
        param_distributions=param_distributions,
        n_iter=args.n_iter,
        scoring=scoring,
        refit=args.metric,  # Refit using best params for this metric
        cv=cv,
        random_state=42,
        n_jobs=args.n_jobs,
        verbose=2,
        return_train_score=True
    )

    random_search.fit(X_train.values, y_train.values)

    # Get best parameters
    best_params = random_search.best_params_
    best_score = random_search.best_score_

    print(f"\n{'='*60}")
    print(f"BEST PARAMETERS")
    print(f"{'='*60}")
    print(f"Best {args.metric} score (CV): {best_score:.4f}\n")
    print("Best hyperparameters:")
    for param, value in best_params.items():
        param_name = param.replace('clf__', '')
        if isinstance(value, float):
            print(f"  {param_name}: {value:.4f}")
        else:
            print(f"  {param_name}: {value}")

    # Get CV results for best model
    best_index = random_search.best_index_
    cv_results = random_search.cv_results_

    print(f"\nCross-Validation Metrics (Best Model):")
    for metric in ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']:
        mean_score = cv_results[f'mean_test_{metric}'][best_index]
        std_score = cv_results[f'std_test_{metric}'][best_index]
        print(f"  {metric}: {mean_score:.4f} (+/- {std_score:.4f})")

    # Evaluate on validation set if provided
    if X_val is not None:
        print(f"\n{'='*60}")
        print(f"VALIDATION SET EVALUATION")
        print(f"{'='*60}")

        val_metrics = evaluate_model(random_search.best_estimator_, X_val, y_val)

        print("Validation Metrics:")
        for metric, value in val_metrics.items():
            print(f"  {metric}: {value:.4f}")

    # Save best model
    joblib.dump(random_search.best_estimator_, args.outdir / "XGBoost_tuned.joblib")
    print(f"\n✓ Saved tuned model to {args.outdir / 'XGBoost_tuned.joblib'}")

    # Save best parameters
    # Convert parameter names (remove 'clf__' prefix)
    clean_params = {k.replace('clf__', ''): v for k, v in best_params.items()}

    results = {
        'best_params': clean_params,
        'best_score': float(best_score),
        'optimization_metric': args.metric,
        'cv_metrics': {
            metric: {
                'mean': float(cv_results[f'mean_test_{metric}'][best_index]),
                'std': float(cv_results[f'std_test_{metric}'][best_index])
            }
            for metric in ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']
        }
    }

    if X_val is not None:
        results['val_metrics'] = val_metrics

    with open(args.outdir / "tuning_results.json", 'w') as f:
        json.dump(results, f, indent=2)

    # Save all CV results as CSV
    results_df = pd.DataFrame(cv_results)
    results_df = results_df.sort_values(f'rank_test_{args.metric}')

    # Save top 20 configurations
    cols_to_save = ['params', 'rank_test_f1'] + \
                   [f'mean_test_{m}' for m in ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']] + \
                   [f'std_test_{m}' for m in ['accuracy', 'precision', 'recall', 'f1', 'roc_auc']]

    results_df[cols_to_save].head(20).to_csv(
        args.outdir / "top_20_configurations.csv", index=False
    )

    print(f"\n✓ Results saved to {args.outdir}")
    print(f"  - XGBoost_tuned.joblib (best model)")
    print(f"  - tuning_results.json (best parameters and metrics)")
    print(f"  - top_20_configurations.csv (top configurations)")

    # Print top 5 configurations
    print(f"\n{'='*60}")
    print(f"TOP 5 CONFIGURATIONS")
    print(f"{'='*60}\n")

    for i in range(min(5, len(results_df))):
        idx = results_df.index[i]
        params = results_df.loc[idx, 'params']
        f1_score = results_df.loc[idx, 'mean_test_f1']

        print(f"Rank {i+1}: F1 = {f1_score:.4f}")
        for k, v in params.items():
            k_clean = k.replace('clf__', '')
            if isinstance(v, float):
                print(f"  {k_clean}: {v:.4f}")
            else:
                print(f"  {k_clean}: {v}")
        print()


if __name__ == "__main__":
    main()
