"""Build visual similarity index for CSE screenshots using CLIP"""
import argparse
import torch
import numpy as np
import json
from pathlib import Path
from PIL import Image
import open_clip
from tqdm import tqdm

def load_model(model_name='ViT-B-32', pretrained='laion2b_s34b_b79k'):
    """Load CLIP model"""
    model, _, preprocess = open_clip.create_model_and_transforms(model_name, pretrained=pretrained)
    model.eval()
    if torch.cuda.is_available():
        model = model.cuda()
    return model, preprocess

def embed_images(img_dir, model, preprocess, device):
    """Embed all images in directory"""
    img_paths = list(Path(img_dir).glob("*.png")) + list(Path(img_dir).glob("*.jpg"))

    embeddings = []
    metadata = []

    print(f"Found {len(img_paths)} screenshots")

    for img_path in tqdm(img_paths, desc="Embedding screenshots"):
        try:
            img = Image.open(img_path).convert('RGB')
            img_tensor = preprocess(img).unsqueeze(0)

            if device.type == 'cuda':
                img_tensor = img_tensor.cuda()

            with torch.no_grad():
                embedding = model.encode_image(img_tensor)
                embedding = embedding / embedding.norm(dim=-1, keepdim=True)  # Normalize

            embeddings.append(embedding.cpu().numpy().flatten())
            metadata.append({
                'filename': img_path.name,
                'path': str(img_path),
                'domain': img_path.stem.rsplit('_', 1)[0]  # Extract domain from filename
            })
        except Exception as e:
            print(f"Error processing {img_path}: {e}")

    return np.array(embeddings), metadata

def main():
    ap = argparse.ArgumentParser(description="Build CLIP index for CSE screenshots")
    ap.add_argument("--img_dir", default="CSE/out/screenshots", help="Directory with CSE screenshots")
    ap.add_argument("--outdir", default="models/vision/cse_index", help="Output directory")
    ap.add_argument("--model", default="ViT-B-32", help="CLIP model name")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    # Load CLIP model
    print(f"Loading CLIP model: {args.model}")
    model, preprocess = load_model(args.model)

    # Embed all CSE screenshots
    embeddings, metadata = embed_images(args.img_dir, model, preprocess, device)

    if len(embeddings) == 0:
        print(f"ERROR: No images found in {args.img_dir}")
        return

    print(f"\nEmbedded {len(embeddings)} screenshots")
    print(f"Embedding dimension: {embeddings.shape[1]}")

    # Save embeddings and metadata
    np.save(outdir / "cse_embeddings.npy", embeddings)
    (outdir / "cse_metadata.json").write_text(json.dumps(metadata, indent=2))

    # Compute pairwise similarities (for validation)
    similarities = embeddings @ embeddings.T
    avg_similarity = (similarities.sum() - len(embeddings)) / (len(embeddings) * (len(embeddings) - 1))

    stats = {
        "n_screenshots": len(embeddings),
        "embedding_dim": int(embeddings.shape[1]),
        "model_name": args.model,
        "avg_pairwise_similarity": float(avg_similarity),
        "similarity_min": float(similarities.min()),
        "similarity_max": float(similarities.max())
    }

    (outdir / "index_stats.json").write_text(json.dumps(stats, indent=2))

    print(f"\nSaved:")
    print(f"  - Embeddings: {outdir / 'cse_embeddings.npy'}")
    print(f"  - Metadata: {outdir / 'cse_metadata.json'}")
    print(f"  - Stats: {outdir / 'index_stats.json'}")
    print(f"\nStats:")
    print(f"  Avg pairwise similarity: {avg_similarity:.3f}")
    print(f"  Similarity range: [{similarities.min():.3f}, {similarities.max():.3f}]")

    print("\n" + "="*60)
    print("USAGE:")
    print("  1. Load index: embeddings = np.load('cse_embeddings.npy')")
    print("  2. Embed query screenshot with same CLIP model")
    print("  3. Compute similarity: scores = query_emb @ embeddings.T")
    print("  4. Find most similar: idx = scores.argmax()")
    print("  5. If max_score > 0.85 and domain mismatch => phishing")
    print("="*60)

if __name__ == "__main__":
    main()
