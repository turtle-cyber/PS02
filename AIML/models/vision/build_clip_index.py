import argparse, json, torch
from pathlib import Path
from PIL import Image
import open_clip
import numpy as np

def embed_images(model, preprocess, paths):
    vecs, ids = [], []
    for p in paths:
        try:
            img = preprocess(Image.open(p).convert("RGB")).unsqueeze(0).to(model.device)
            with torch.no_grad():
                v = model.encode_image(img)
                v = v / v.norm(dim=-1, keepdim=True)
            vecs.append(v.cpu().numpy())
            ids.append(p.name)
        except Exception:
            continue
    return np.vstack(vecs), ids

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gallery_dir", required=True)   # legit_gallery/{cse}/.jpg
    ap.add_argument("--pages_dir", required=True)     # pages/{url_id}.jpg
    ap.add_argument("--out_json", required=True)
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model, _, preprocess = open_clip.create_model_and_transforms("ViT-L-14", pretrained="openai")
    model = model.to(device).eval()

    gal_paths = list(Path(args.gallery_dir).rglob("*.jpg"))
    pg_paths  = list(Path(args.pages_dir).glob("*.jpg"))

    gal_vecs, gal_ids = embed_images(model, preprocess, gal_paths)
    pg_vecs,  pg_ids  = embed_images(model, preprocess, pg_paths)

    # cosine similarity top-1 vs gallery
    sims = (pg_vecs @ gal_vecs.T)
    top = sims.max(axis=1)
    out = {pid: float(s) for pid, s in zip(pg_ids, top)}
    Path(args.out_json).write_text(json.dumps({"brandSim": out}, indent=2))
    print(f"Wrote BrandSim for {len(out)} pages → {args.out_json}")

if __name__ == "__main__":
    main()
