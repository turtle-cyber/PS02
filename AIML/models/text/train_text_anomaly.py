#!/usr/bin/env python3
"""
Train Text Semantic Anomaly Detector using Sentence-BERT

Uses one-class learning on CSE benign text to detect phishing via semantic distance.
NO phishing labels required - detects deviations from benign text patterns.
"""

import json
import numpy as np
from pathlib import Path
from typing import List, Dict
import argparse


def main():
    parser = argparse.ArgumentParser(description='Train text semantic anomaly detector')
    parser.add_argument('--input', required=True,
                       help='Path to dump_all.jsonl or training data')
    parser.add_argument('--outdir', default='models/text/semantic_anomaly',
                       help='Output directory for model')
    parser.add_argument('--model_name', default='all-MiniLM-L6-v2',
                       help='Sentence-BERT model name')
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    print("="*70)
    print("TEXT SEMANTIC ANOMALY DETECTOR TRAINING")
    print("="*70)
    print(f"Model: {args.model_name}")
    print(f"Output: {outdir}")
    print()

    # Import sentence-transformers
    try:
        from sentence_transformers import SentenceTransformer
        from sklearn.neighbors import NearestNeighbors
        from sklearn.preprocessing import StandardScaler
        import joblib
    except ImportError:
        print("ERROR: Missing dependencies")
        print("Install: pip install sentence-transformers scikit-learn joblib")
        return

    # Load CSE benign data
    print("1. Loading CSE benign data...")
    texts = []
    domains = []

    with open(args.input, 'r') as f:
        for line in f:
            data = json.loads(line)
            metadata = data.get('metadata', {})
            document = data.get('document', '')

            # Extract text content
            domain = metadata.get('registrable', '')
            ocr_text = metadata.get('ocr_text_excerpt', '')

            # Combine document + OCR text
            combined_text = f"{document} {ocr_text}".strip()

            if combined_text and domain:
                texts.append(combined_text)
                domains.append(domain)

    print(f"   Loaded {len(texts)} CSE text samples")

    if len(texts) < 10:
        print("ERROR: Not enough text data. Need at least 10 samples.")
        return

    # Load Sentence-BERT model
    print(f"\n2. Loading Sentence-BERT model: {args.model_name}...")
    sbert_model = SentenceTransformer(args.model_name)
    print(f"   Model loaded. Embedding dimension: {sbert_model.get_sentence_embedding_dimension()}")

    # Embed all CSE texts
    print(f"\n3. Embedding {len(texts)} CSE texts...")
    embeddings = sbert_model.encode(
        texts,
        show_progress_bar=True,
        batch_size=32,
        convert_to_numpy=True
    )
    print(f"   Embeddings shape: {embeddings.shape}")

    # Build baseline statistics
    print("\n4. Building CSE baseline statistics...")

    # Approach 1: Statistical baseline (mean + std)
    cse_mean = embeddings.mean(axis=0)
    cse_std = embeddings.std(axis=0)

    # Approach 2: K-Nearest Neighbors for density estimation
    # Find optimal k (sqrt of n samples)
    k_neighbors = min(10, int(np.sqrt(len(embeddings))))
    print(f"   Building KNN index (k={k_neighbors})...")

    knn = NearestNeighbors(n_neighbors=k_neighbors, metric='cosine')
    knn.fit(embeddings)

    # Compute baseline distances (average distance to k nearest neighbors)
    distances, _ = knn.kneighbors(embeddings)
    avg_distances = distances.mean(axis=1)

    baseline_distance_mean = avg_distances.mean()
    baseline_distance_std = avg_distances.std()
    baseline_distance_max = np.percentile(avg_distances, 95)  # 95th percentile

    print(f"   CSE baseline stats:")
    print(f"     Mean distance to neighbors: {baseline_distance_mean:.4f}")
    print(f"     Std distance: {baseline_distance_std:.4f}")
    print(f"     95th percentile: {baseline_distance_max:.4f}")

    # Set anomaly threshold (3 std deviations from mean)
    anomaly_threshold = baseline_distance_mean + 3 * baseline_distance_std

    print(f"   Anomaly threshold: {anomaly_threshold:.4f}")

    # Save model and baseline
    print("\n5. Saving model and baseline...")

    # Save Sentence-BERT model name (for loading later)
    model_config = {
        'model_name': args.model_name,
        'embedding_dim': sbert_model.get_sentence_embedding_dimension(),
        'n_samples': len(texts),
        'k_neighbors': k_neighbors,
    }

    # Save baseline statistics
    baseline_stats = {
        'cse_mean': cse_mean.tolist(),
        'cse_std': cse_std.tolist(),
        'baseline_distance_mean': float(baseline_distance_mean),
        'baseline_distance_std': float(baseline_distance_std),
        'baseline_distance_max': float(baseline_distance_max),
        'anomaly_threshold': float(anomaly_threshold),
    }

    # Save metadata
    metadata_output = {
        **model_config,
        **baseline_stats,
        'sample_domains': domains[:10]  # Save first 10 for reference
    }

    (outdir / 'model_config.json').write_text(json.dumps(metadata_output, indent=2))
    print(f"   ✓ Saved config: {outdir / 'model_config.json'}")

    # Save KNN model
    joblib.dump(knn, outdir / 'knn_model.joblib')
    print(f"   ✓ Saved KNN model: {outdir / 'knn_model.joblib'}")

    # Save CSE embeddings (for reference/debugging)
    np.save(outdir / 'cse_embeddings.npy', embeddings)
    print(f"   ✓ Saved embeddings: {outdir / 'cse_embeddings.npy'}")

    # Save domain list
    (outdir / 'cse_domains.json').write_text(json.dumps(domains, indent=2))
    print(f"   ✓ Saved domains: {outdir / 'cse_domains.json'}")

    # Test on training data
    print("\n6. Validating on training data...")
    test_embedding = embeddings[0:1]  # First sample
    test_distances, _ = knn.kneighbors(test_embedding)
    test_avg_distance = test_distances.mean()

    print(f"   Test sample distance: {test_avg_distance:.4f}")
    print(f"   Is anomaly? {test_avg_distance > anomaly_threshold}")

    # Summary
    print("\n" + "="*70)
    print("✓ TEXT SEMANTIC ANOMALY DETECTOR TRAINED SUCCESSFULLY")
    print("="*70)
    print(f"Model: {args.model_name}")
    print(f"CSE samples: {len(texts)}")
    print(f"Embedding dim: {embeddings.shape[1]}")
    print(f"Anomaly threshold: {anomaly_threshold:.4f}")
    print()
    print("USAGE:")
    print("  1. Load Sentence-BERT model")
    print("  2. Embed unknown text")
    print("  3. Find k-nearest neighbors in CSE baseline")
    print("  4. Calculate average distance")
    print("  5. If distance > threshold => ANOMALY (potential phishing)")
    print("="*70)


if __name__ == '__main__':
    main()
