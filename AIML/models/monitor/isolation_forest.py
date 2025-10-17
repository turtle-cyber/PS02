import argparse, json, numpy as np, pandas as pd
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--time_series_csv", required=True)  # rows: timepoints per domain, cols: same Annexure vector
    ap.add_argument("--out_json", required=True)
    args = ap.parse_args()

    df = pd.read_csv(args.time_series_csv)  # must include: domain, ts, <features...>
    features = df.drop(columns=[c for c in ["domain","ts"] if c in df.columns])
    X = StandardScaler(with_mean=False).fit_transform(features.fillna(features.median()))
    iso = IsolationForest(contamination=0.05, random_state=42).fit(X)
    scores = -iso.decision_function(X)  # higher = more anomalous
    out = [{"domain": d, "ts": t, "drift_score": float(s)} for d, t, s in zip(df["domain"], df["ts"], scores)]
    Path(args.out_json).write_text(json.dumps(out, indent=2))

if __name__ == "__main__":
    main()
