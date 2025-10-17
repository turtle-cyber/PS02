"""Similarity-based phishing detection using CSE baseline comparison"""
import argparse
import json
import numpy as np
import pandas as pd
import joblib
import torch
from pathlib import Path
from PIL import Image
import open_clip

class CSESimilarityDetector:
    """Detect phishing by comparing against legitimate CSE baseline"""

    def __init__(self, anomaly_model_path, visual_index_dir, clip_model='ViT-B-32'):
        # Load anomaly detector (tabular)
        self.anomaly_detector = joblib.load(anomaly_model_path)
        print(f"Loaded anomaly detector from {anomaly_model_path}")

        # Load visual index
        self.cse_embeddings = np.load(Path(visual_index_dir) / "cse_embeddings.npy")
        with open(Path(visual_index_dir) / "cse_metadata.json") as f:
            self.cse_metadata = json.load(f)
        print(f"Loaded {len(self.cse_embeddings)} CSE visual embeddings")

        # Load CLIP model for visual similarity
        self.clip_model, self.clip_preprocess = self._load_clip(clip_model)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    def _load_clip(self, model_name):
        model, _, preprocess = open_clip.create_model_and_transforms(model_name, pretrained='laion2b_s34b_b79k')
        model.eval()
        if torch.cuda.is_available():
            model = model.cuda()
        return model, preprocess

    def _embed_image(self, img_path):
        """Embed single image using CLIP"""
        img = Image.open(img_path).convert('RGB')
        img_tensor = self.clip_preprocess(img).unsqueeze(0)

        if self.device.type == 'cuda':
            img_tensor = img_tensor.cuda()

        with torch.no_grad():
            embedding = self.clip_model.encode_image(img_tensor)
            embedding = embedding / embedding.norm(dim=-1, keepdim=True)

        return embedding.cpu().numpy().flatten()

    def detect_tabular_anomaly(self, features):
        """
        Check if features deviate from CSE baseline
        Returns: (anomaly_score, is_anomaly)
        """
        # Convert dict to DataFrame if needed
        if isinstance(features, dict):
            features = pd.DataFrame([features])

        # Drop non-numeric columns
        drop_cols = [c for c in ['url', 'registrable', 'domain'] if c in features.columns]
        X = features.drop(columns=drop_cols, errors='ignore')

        # Get anomaly score (lower = more anomalous)
        score = self.anomaly_detector.decision_function(X.values)[0]
        prediction = self.anomaly_detector.predict(X.values)[0]

        is_anomaly = (prediction == -1)

        return float(score), is_anomaly

    def detect_visual_similarity(self, screenshot_path, query_domain):
        """
        Compare screenshot against CSE baseline
        Returns: (max_similarity, matched_domain, is_suspicious)
        """
        # Embed query screenshot
        query_emb = self._embed_image(screenshot_path)

        # Compute similarities to all CSE screenshots
        similarities = query_emb @ self.cse_embeddings.T

        # Find most similar CSE screenshot
        max_idx = similarities.argmax()
        max_similarity = similarities[max_idx]
        matched_meta = self.cse_metadata[max_idx]
        matched_domain = matched_meta['domain']

        # Suspicious if: high visual similarity BUT different domain
        is_suspicious = (max_similarity > 0.80 and query_domain != matched_domain)

        return float(max_similarity), matched_domain, is_suspicious

    def predict(self, features, screenshot_path=None, domain=None):
        """
        Full detection pipeline
        Args:
            features: dict or DataFrame with tabular features
            screenshot_path: path to screenshot (optional)
            domain: domain name for comparison (required if screenshot provided)

        Returns:
            dict with verdict, confidence, and explanations
        """
        result = {
            'verdict': 'benign',
            'confidence': 0.5,
            'tabular_anomaly_score': None,
            'visual_similarity': None,
            'matched_cse_domain': None,
            'reasons': []
        }

        # 1. Tabular anomaly detection
        anomaly_score, is_anomaly = self.detect_tabular_anomaly(features)
        result['tabular_anomaly_score'] = anomaly_score

        if is_anomaly:
            result['verdict'] = 'suspicious'
            result['confidence'] = 0.65
            result['reasons'].append(f"Tabular features deviate from CSE baseline (score={anomaly_score:.3f})")

        # 2. Visual similarity (if screenshot provided)
        if screenshot_path and domain:
            visual_sim, matched_domain, is_visually_suspicious = self.detect_visual_similarity(
                screenshot_path, domain
            )
            result['visual_similarity'] = visual_sim
            result['matched_cse_domain'] = matched_domain

            if is_visually_suspicious:
                result['verdict'] = 'phishing'
                result['confidence'] = 0.90
                result['reasons'].append(
                    f"High visual similarity to {matched_domain} (sim={visual_sim:.3f}) but domain mismatch"
                )

        # 3. Combine signals
        if result['verdict'] == 'phishing':
            # Strong signal: visual mimicry detected
            pass
        elif is_anomaly and result['visual_similarity'] and result['visual_similarity'] > 0.70:
            # Moderate signal: anomalous features + some visual similarity
            result['verdict'] = 'suspicious'
            result['confidence'] = 0.75
        elif not is_anomaly and (not result['visual_similarity'] or result['visual_similarity'] < 0.70):
            # No anomalies detected
            result['verdict'] = 'benign'
            result['confidence'] = 0.85

        result['reasons'] = '; '.join(result['reasons']) if result['reasons'] else 'No anomalies detected'

        return result

def main():
    """CLI for testing detector"""
    ap = argparse.ArgumentParser()
    ap.add_argument("--anomaly_model", default="models/tabular/anomaly/anomaly_detector.joblib")
    ap.add_argument("--visual_index", default="models/vision/cse_index")
    ap.add_argument("--features_csv", required=True, help="CSV with features to test")
    ap.add_argument("--screenshot", help="Screenshot to test (optional)")
    ap.add_argument("--domain", help="Domain name (required if --screenshot provided)")
    args = ap.parse_args()

    # Load detector
    detector = CSESimilarityDetector(
        anomaly_model_path=args.anomaly_model,
        visual_index_dir=args.visual_index,
    )

    # Load features
    df = pd.read_csv(args.features_csv)
    print(f"\nTesting on {len(df)} samples")

    # Test each sample
    for idx, row in df.iterrows():
        features = row.to_dict()
        result = detector.predict(
            features=features,
            screenshot_path=args.screenshot if idx == 0 else None,  # Only test first one
            domain=args.domain
        )

        print(f"\n[Sample {idx+1}] Domain: {features.get('registrable', 'unknown')}")
        print(f"  Verdict: {result['verdict']} (confidence: {result['confidence']:.2f})")
        print(f"  Tabular anomaly score: {result['tabular_anomaly_score']:.3f}")
        if result['visual_similarity']:
            print(f"  Visual similarity: {result['visual_similarity']:.3f} (matched: {result['matched_cse_domain']})")
        print(f"  Reasons: {result['reasons']}")

        if idx == 0:  # Only show first sample in detail
            break

if __name__ == "__main__":
    main()
