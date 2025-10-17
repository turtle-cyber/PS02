import argparse, json, numpy as np, pandas as pd, joblib
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--probs_csv", required=True)  # columns: url_id, p_urltab, p_text, p_vis, brandSim, layoutSim
    ap.add_argument("--cal_dir", required=True)
    ap.add_argument("--weights", default="0.5,0.4,0.1")   # w_urltab,w_text,w_vis
    ap.add_argument("--alphabeta", default="0.2,0.2")     # alpha,beta
    ap.add_argument("--thresholds", default="0.30,0.70")  # tau_low,tau_high
    ap.add_argument("--out_json", required=True)
    args = ap.parse_args()

    w1,w2,w3 = map(float, args.weights.split(","))
    alpha,beta = map(float, args.alphabeta.split(","))
    tau_low, tau_high = map(float, args.thresholds.split(","))

    df = pd.read_csv(args.probs_csv)
    def cal(name, x):
        iso = joblib.load(Path(args.cal_dir)/f"cal_{name}.joblib")
        return iso.predict(x)

    p_urltab = cal("p_urltab", df["p_urltab"].values)
    p_text   = cal("p_text",   df["p_text"].values) if "p_text" in df else 0.0
    p_vis    = cal("p_vis",    df["p_vis"].values) if "p_vis" in df else 0.0
    brand    = df.get("brandSim", pd.Series(0.0, index=df.index)).values
    layout   = df.get("layoutSim", pd.Series(0.0, index=df.index)).values

    p_final = w1*p_urltab + w2*p_text + w3*p_vis + alpha*brand + beta*layout
    label = np.where(p_final >= tau_high, "phishing",
            np.where(p_final <= tau_low, "benign", "suspected"))

    out = [{"url_id": u, "P_final": float(p), "label": l} for u,p,l in zip(df["url_id"], p_final, label)]
    Path(args.out_json).write_text(json.dumps(out, indent=2))
    print(f"Wrote {len(out)} decisions → {args.out_json}")

if __name__ == "__main__":
    main()
