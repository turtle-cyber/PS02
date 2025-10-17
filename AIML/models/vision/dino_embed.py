import argparse, json, torch
from pathlib import Path
from PIL import Image
import numpy as np
from transformers import AutoImageProcessor, AutoModel

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gallery_dir", required=True)
    ap.add_argument("--pages_dir", required=True)
    ap.add_argument("--out_json", required=True)
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    proc = AutoImageProcessor.from_pretrained("facebook/dinov2-base")
    model = AutoModel.from_pretrained("facebook/dinov2-base").to(device).eval()

    def embed(imgp):
        im = Image.open(imgp).convert("RGB")
        px = proc(images=im, return_tensors="pt").to(device)
        with torch.no_grad():
            v = model(**px).last_hidden_state.mean(1)  # pooled
            v = v / v.norm(dim=-1, keepdim=True)
        return v.cpu().numpy()

    gal = [(p, embed(p)) for p in Path(args.gallery_dir).rglob("*.jpg")]
    G = np.vstack([v for _, v in gal])
    P, ids = [], []
    for p in Path(args.pages_dir).glob("*.jpg"):
        P.append(embed(p)); ids.append(p.name)
    P = np.vstack(P)

    sims = (P @ G.T).max(1)
    out = {pid: float(s) for pid, s in zip(ids, sims)}
    Path(args.out_json).write_text(json.dumps({"layoutSim": out}, indent=2))

if __name__ == "__main__":
    main()
