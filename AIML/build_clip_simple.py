"""Build CLIP index - memory-efficient version"""
import torch
import numpy as np
import json
from pathlib import Path
from PIL import Image
import open_clip

print("Loading CLIP model...")
model, _, preprocess = open_clip.create_model_and_transforms('ViT-B-32', pretrained='laion2b_s34b_b79k')
model.eval()
device = torch.device('cpu')  # Use CPU to avoid memory issues
model = model.to(device)

screenshot_dir = Path("Pipeline/out/screenshots")
screenshots = list(screenshot_dir.glob("*.png")) + list(screenshot_dir.glob("*.jpg"))

print(f"Found {len(screenshots)} screenshots")

embeddings = []
metadata = []

for i, img_path in enumerate(screenshots):
    if i % 10 == 0:
        print(f"Processing {i}/{len(screenshots)}...")

    try:
        img = Image.open(img_path).convert('RGB')
        img_tensor = preprocess(img).unsqueeze(0).to(device)

        with torch.no_grad():
            embedding = model.encode_image(img_tensor)
            embedding = embedding / embedding.norm(dim=-1, keepdim=True)

        embeddings.append(embedding.cpu().numpy().flatten())

        # Extract domain from filename (e.g., bankofbaroda.in_e8d308eb_full.png -> bankofbaroda.in)
        stem = img_path.stem
        if stem.endswith("_full"):
            stem = stem[:-5]
        parts = stem.rsplit('_', 1)
        domain = parts[0] if len(parts) == 2 else stem

        metadata.append({
            'filename': img_path.name,
            'path': str(img_path),
            'domain': domain
        })
    except Exception as e:
        print(f"Error processing {img_path}: {e}")

embeddings = np.array(embeddings)

print(f"\nEmbedded {len(embeddings)} screenshots (dim: {embeddings.shape[1]})")

# Save
outdir = Path("AIML/models/vision/cse_index")
outdir.mkdir(parents=True, exist_ok=True)

np.save(outdir / "cse_embeddings.npy", embeddings)
with open(outdir / "cse_metadata.json", 'w') as f:
    json.dump(metadata, f, indent=2)

# Stats
similarities = embeddings @ embeddings.T
avg_sim = (similarities.sum() - len(embeddings)) / (len(embeddings) * (len(embeddings) - 1))

stats = {
    "n_screenshots": len(embeddings),
    "embedding_dim": int(embeddings.shape[1]),
    "model_name": "ViT-B-32",
    "avg_pairwise_similarity": float(avg_sim),
    "similarity_min": float(similarities.min()),
    "similarity_max": float(similarities.max())
}

with open(outdir / "index_stats.json", 'w') as f:
    json.dump(stats, f, indent=2)

print(f"\nSaved to {outdir}")
print(f"Avg similarity: {avg_sim:.3f}")
