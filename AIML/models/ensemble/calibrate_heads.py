import argparse, json, numpy as np, pandas as pd
from pathlib import Path
from sklearn.isotonic import IsotonicRegression
from sklearn.calibration import CalibratedClassifierCV
import joblib

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oof_csv", required=True)  # columns: url_id, y_true, p_urltab, p_text, p_vis, brandSim, layoutSim
    ap.add_argument("--outdir", required=True)
    args = ap.parse_args()
    out = Path(args.outdir); out.mkdir(exist_ok=True, parents=True)

    df = pd.read_csv(args.oof_csv)
    # simple isotonic calibration per head against y_true
    calibs = {}
    for head in ["p_urltab","p_text","p_vis"]:
        iso = IsotonicRegression(out_of_bounds="clip")
        iso.fit(df[head].values, df["y_true"].values)
        joblib.dump(iso, out / f"cal_{head}.joblib")
        calibs[head] = {"type":"isotonic"}
    (out / "calibration.json").write_text(json.dumps(calibs, indent=2))

if __name__ == "__main__":
    main()
