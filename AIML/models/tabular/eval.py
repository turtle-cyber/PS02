import json, argparse, numpy as np, pandas as pd, joblib
from pathlib import Path
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import make_scorer, accuracy_score, f1_score, recall_score

def load_xy(csv_path: Path):
    df = pd.read_csv(csv_path)
    # drop string/meta cols not for tabular learning
    drop_cols = [c for c in ['original_url','url_norm','hostname','registered_domain','domain','subdomain','tld'] if c in df.columns]
    y = df['label'].map({'benign':0,'phishing':1}).astype(int)
    X = df.drop(columns=drop_cols+['label']).copy()
    # coerce non-numerics → category codes
    for c in X.columns:
        if not pd.api.types.is_numeric_dtype(X[c]):
            X[c] = X[c].astype('category').cat.codes
    return X, y

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", type=Path, required=True)
    ap.add_argument("--outdir", type=Path, required=True)
    args = ap.parse_args()

    X, y = load_xy(args.csv)
    args.outdir.mkdir(parents=True, exist_ok=True)

    imputer = SimpleImputer(strategy="median")
    scaler = StandardScaler(with_mean=False)
    scoring = {
        'accuracy': make_scorer(accuracy_score),
        'f1': make_scorer(f1_score, pos_label=1),
        'recall': make_scorer(recall_score, pos_label=1)
    }
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    models = {
      "LogisticRegression": Pipeline([("imputer", imputer), ("scaler", scaler),
                                      ("clf", LogisticRegression(max_iter=1000, class_weight="balanced"))]),
      "RandomForest": Pipeline([("imputer", imputer),
                                ("clf", RandomForestClassifier(n_estimators=400, class_weight="balanced", random_state=42))]),
      "XGBoost": Pipeline([("imputer", imputer),
                           ("clf", XGBClassifier(n_estimators=600, max_depth=6, learning_rate=0.05,
                                                 subsample=0.8, colsample_bytree=0.8, reg_lambda=1.0,
                                                 objective="binary:logistic", eval_metric="logloss", n_jobs=4,
                                                 random_state=42))]),
    }

    metrics = {}
    for name, model in models.items():
        cvres = cross_validate(model, X.values, y.values, cv=cv, scoring=scoring, n_jobs=4)
        metrics[name] = {k: float(np.mean(v)) for k, v in {
            "accuracy": cvres["test_accuracy"],
            "f1": cvres["test_f1"],
            "recall": cvres["test_recall"],
        }.items()}
        # fit on full data and persist
        model.fit(X.values, y.values)
        joblib.dump(model, args.outdir / f"{name}.joblib")

    (args.outdir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    main()
