#!/usr/bin/env python3
"""
CLIP-Enhanced Visual Similarity Detector

Detects phishing attempts using semantic visual understanding via CLIP:
- Uses pre-trained CLIP ViT-B-32 model
- Compares screenshots semantically (not just pixel-level)
- Falls back to perceptual hash if CLIP unavailable
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import imagehash
from PIL import Image


class CLIPVisualDetector:
    """Detect visual impersonation using CLIP embeddings"""

    def __init__(self, cse_index_path: str, cse_baseline_path: str = None,
                 clip_model_name: str = 'ViT-B-32', use_clip: bool = True):
        """
        Initialize CLIP-based visual detector

        Args:
            cse_index_path: Path to CSE CLIP index directory
            cse_baseline_path: Path to CSE baseline profile (for whitelist)
            clip_model_name: CLIP model variant
            use_clip: Whether to use CLIP (True) or fall back to phash (False)
        """
        self.use_clip = use_clip
        self.clip_model = None
        self.clip_preprocess = None
        self.cse_embeddings = None
        self.cse_metadata = []
        self.cse_domains = []  # Clean domain names from CLIP index
        self.cse_whitelist = []  # Registrable domains from baseline

        # Thresholds
        self.clip_similarity_threshold = 0.80  # From existing code
        self.phash_distance_threshold = 10

        # Load CSE index
        self.load_cse_index(cse_index_path)

        # Load CSE whitelist if provided
        if cse_baseline_path:
            self.load_cse_whitelist(cse_baseline_path)

        # Load CLIP model if requested
        if use_clip:
            try:
                self._load_clip_model(clip_model_name)
            except Exception as e:
                print(f"WARNING: Failed to load CLIP model: {e}")
                print("Falling back to phash-only mode")
                self.use_clip = False

    def load_cse_index(self, index_path: str):
        """Load CSE baseline embeddings and metadata"""
        index_dir = Path(index_path)

        # Load CLIP embeddings
        emb_file = index_dir / "cse_embeddings.npy"
        if emb_file.exists():
            self.cse_embeddings = np.load(emb_file)
            print(f"Loaded {len(self.cse_embeddings)} CSE CLIP embeddings")

        # Load metadata
        meta_file = index_dir / "cse_metadata.json"
        if meta_file.exists():
            with open(meta_file, 'r') as f:
                self.cse_metadata = json.load(f)

            # Extract domain list (clean up domain names by removing hash suffix)
            self.cse_domains = []
            for m in self.cse_metadata:
                domain = m['domain']
                # Remove hash suffix (e.g., sbi.co.in_c0feeec6 → sbi.co.in)
                clean_domain = domain.rsplit('_', 1)[0] if '_' in domain else domain
                self.cse_domains.append(clean_domain)

            print(f"Loaded metadata for {len(self.cse_domains)} CSE domains")

    def load_cse_whitelist(self, baseline_path: str):
        """Load CSE whitelist from baseline profile"""
        try:
            with open(baseline_path, 'r') as f:
                baseline = json.load(f)
            self.cse_whitelist = baseline.get('cse_whitelist', [])
            print(f"Loaded CSE whitelist: {len(self.cse_whitelist)} domains")
        except Exception as e:
            print(f"Warning: Could not load CSE whitelist: {e}")

    def _load_clip_model(self, model_name: str):
        """Load CLIP model"""
        try:
            import torch
            import open_clip

            device = 'cuda' if torch.cuda.is_available() else 'cpu'
            print(f"Loading CLIP model {model_name} on {device}...")

            model, _, preprocess = open_clip.create_model_and_transforms(
                model_name,
                pretrained='laion2b_s34b_b79k'
            )
            model = model.to(device).eval()

            self.clip_model = model
            self.clip_preprocess = preprocess
            self.device = device

            print(f"✓ CLIP model loaded successfully")

        except ImportError as e:
            raise ImportError(f"CLIP dependencies not installed: {e}")

    def embed_screenshot_clip(self, screenshot_path: str) -> Optional[np.ndarray]:
        """
        Embed screenshot using CLIP

        Args:
            screenshot_path: Path to screenshot image

        Returns:
            512-dim embedding vector or None if error
        """
        if not self.use_clip or self.clip_model is None:
            return None

        try:
            import torch

            img = Image.open(screenshot_path).convert('RGB')
            img_tensor = self.clip_preprocess(img).unsqueeze(0)

            if self.device == 'cuda':
                img_tensor = img_tensor.cuda()

            with torch.no_grad():
                embedding = self.clip_model.encode_image(img_tensor)
                embedding = embedding / embedding.norm(dim=-1, keepdim=True)  # Normalize

            return embedding.cpu().numpy().flatten()

        except Exception as e:
            print(f"Error embedding screenshot with CLIP: {e}")
            return None

    def compute_phash(self, image_path: str) -> Optional[str]:
        """Compute perceptual hash (fallback method)"""
        try:
            img = Image.open(image_path)
            phash = imagehash.phash(img)
            return str(phash)
        except Exception as e:
            print(f"Error computing phash from {image_path}: {e}")
            return None

    def find_similar_cse_clip(self, query_embedding: np.ndarray) -> Tuple[float, int, str]:
        """
        Find most similar CSE domain using CLIP similarity

        Args:
            query_embedding: Query screenshot CLIP embedding

        Returns:
            (max_similarity, best_match_idx, matched_domain)
        """
        if self.cse_embeddings is None or len(self.cse_embeddings) == 0:
            return 0.0, -1, ''

        # Compute cosine similarities
        similarities = query_embedding @ self.cse_embeddings.T

        # Find best match
        best_idx = int(np.argmax(similarities))
        max_similarity = float(similarities[best_idx])
        matched_domain = self.cse_metadata[best_idx]['domain'] if best_idx < len(self.cse_metadata) else ''

        return max_similarity, best_idx, matched_domain

    def find_similar_cse_phash(self, query_phash: str) -> Tuple[int, Optional[str]]:
        """
        Find most similar CSE using phash hamming distance

        Args:
            query_phash: Query screenshot phash

        Returns:
            (min_distance, closest_cse_domain)
        """
        # This would require storing phashes in CSE index
        # For now, return no match
        return 999, None

    def detect_with_clip(self, screenshot_path: str, domain: str, registrable: str) -> Dict:
        """
        Detect phishing using CLIP semantic similarity

        Args:
            screenshot_path: Path to screenshot
            domain: Full domain name
            registrable: Registrable domain

        Returns:
            Detection result dictionary
        """
        # Check if domain is whitelisted (check both whitelist and CLIP index domains)
        is_whitelisted = (registrable in self.cse_whitelist or
                         registrable in self.cse_domains)

        # Embed screenshot
        query_emb = self.embed_screenshot_clip(screenshot_path)

        if query_emb is None:
            return {
                'verdict': 'UNKNOWN',
                'confidence': 0.0,
                'reason': 'Failed to embed screenshot',
                'method': 'clip',
                'details': {}
            }

        # Find most similar CSE
        max_sim, best_idx, matched_domain = self.find_similar_cse_clip(query_emb)

        # Determine verdict
        if is_whitelisted:
            verdict = 'BENIGN'
            confidence = 0.95
            reason = f'Domain in CSE whitelist (similarity={max_sim:.3f})'
        elif max_sim >= self.clip_similarity_threshold:
            # High visual similarity but NOT in whitelist → Phishing
            verdict = 'PHISHING'
            confidence = 0.7 + min(0.25, (max_sim - 0.80) * 1.25)  # 0.70-0.95
            reason = f'Visually impersonates {matched_domain} (similarity={max_sim:.3f})'
        else:
            # Not similar to any CSE
            verdict = 'UNKNOWN'
            confidence = 0.0
            reason = f'Not visually similar to CSE sites (max={max_sim:.3f})'

        return {
            'verdict': verdict,
            'confidence': confidence,
            'reason': reason,
            'method': 'clip',
            'details': {
                'is_whitelisted': is_whitelisted,
                'clip_similarity': max_sim,
                'matched_cse_domain': matched_domain,
                'matched_cse_idx': best_idx,
                'threshold': self.clip_similarity_threshold
            }
        }

    def detect_with_phash(self, phash: str, registrable: str) -> Dict:
        """
        Detect phishing using perceptual hash (fallback)

        Args:
            phash: Perceptual hash string
            registrable: Registrable domain

        Returns:
            Detection result dictionary
        """
        is_whitelisted = registrable in self.cse_domains

        if is_whitelisted:
            return {
                'verdict': 'BENIGN',
                'confidence': 0.85,
                'reason': 'Domain in CSE whitelist',
                'method': 'phash',
                'details': {'is_whitelisted': True}
            }
        else:
            # Can't do visual comparison without phash index
            return {
                'verdict': 'UNKNOWN',
                'confidence': 0.0,
                'reason': 'No visual comparison available (phash-only mode)',
                'method': 'phash',
                'details': {'is_whitelisted': False}
            }

    def detect(self, screenshot_path: str = None, phash: str = None,
               domain: str = '', registrable: str = '') -> Dict:
        """
        Main detection method - tries CLIP, falls back to phash

        Args:
            screenshot_path: Path to screenshot (for CLIP)
            phash: Perceptual hash (fallback)
            domain: Full domain name
            registrable: Registrable domain

        Returns:
            Detection result dictionary
        """
        # Try CLIP if available
        if self.use_clip and screenshot_path:
            return self.detect_with_clip(screenshot_path, domain, registrable)

        # Fall back to phash
        elif phash:
            return self.detect_with_phash(phash, registrable)

        # No visual data available
        else:
            return {
                'verdict': 'UNKNOWN',
                'confidence': 0.0,
                'reason': 'No screenshot or phash available',
                'method': 'none',
                'details': {}
            }


def main():
    """Test CLIP detector"""
    import argparse

    parser = argparse.ArgumentParser(description='CLIP visual similarity detector')
    parser.add_argument('--index', default='AIML/models/vision/cse_index_updated',
                       help='CSE CLIP index directory')
    parser.add_argument('--baseline', default='AIML/data/training/cse_baseline_profile.json',
                       help='CSE baseline profile (for whitelist)')
    parser.add_argument('--screenshot', help='Screenshot to test')
    parser.add_argument('--domain', help='Domain name')
    parser.add_argument('--registrable', help='Registrable domain')
    args = parser.parse_args()

    # Initialize detector
    print("Initializing CLIP Visual Detector...")
    detector = CLIPVisualDetector(
        cse_index_path=args.index,
        cse_baseline_path=args.baseline
    )

    if args.screenshot and args.registrable:
        # Test detection
        print(f"\nTesting screenshot: {args.screenshot}")
        print(f"Domain: {args.registrable}")

        result = detector.detect(
            screenshot_path=args.screenshot,
            domain=args.domain or args.registrable,
            registrable=args.registrable
        )

        print(f"\nResult:")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Confidence: {result['confidence']:.2f}")
        print(f"  Reason: {result['reason']}")
        print(f"  Method: {result['method']}")
        if result['details']:
            print(f"  Details: {json.dumps(result['details'], indent=4)}")

    else:
        print("\nDemo mode: Detector initialized successfully")
        print(f"  CSE domains in index: {len(detector.cse_domains)}")
        print(f"  CLIP embeddings: {len(detector.cse_embeddings) if detector.cse_embeddings is not None else 0}")
        print(f"  CLIP enabled: {detector.use_clip}")


if __name__ == "__main__":
    main()
