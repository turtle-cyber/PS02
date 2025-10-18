#!/usr/bin/env python3
"""
Visual Similarity Detector

Detects phishing attempts that visually impersonate CSE websites using:
- Screenshot perceptual hash (phash) comparison
- Hamming distance calculation for similarity scoring
- CSE baseline matching
"""

import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import imagehash
from PIL import Image


class VisualSimilarityDetector:
    """Detect visual impersonation using perceptual hashing"""

    def __init__(self, cse_baseline_path: str = None):
        """
        Initialize with CSE baseline profile

        Args:
            cse_baseline_path: Path to CSE baseline profile JSON
        """
        self.cse_phashes = []
        self.cse_domains = []
        self.phash_threshold = 10  # Hamming distance threshold for similarity

        if cse_baseline_path:
            self.load_cse_baseline(cse_baseline_path)

    def load_cse_baseline(self, baseline_path: str):
        """Load CSE baseline visual hashes"""
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)

        self.cse_phashes = baseline.get('cse_visual_hashes', [])
        self.cse_domains = baseline.get('cse_whitelist', [])

        print(f"Loaded CSE baseline: {len(self.cse_phashes)} visual hashes, {len(self.cse_domains)} domains")

    def hamming_distance(self, hash1: str, hash2: str) -> int:
        """
        Calculate Hamming distance between two perceptual hashes

        Args:
            hash1, hash2: Hex string representations of phash

        Returns:
            Hamming distance (0 = identical, higher = more different)
        """
        if not hash1 or not hash2:
            return 999  # Max distance for missing hashes

        try:
            # Convert hex strings to imagehash objects
            h1 = imagehash.hex_to_hash(hash1)
            h2 = imagehash.hex_to_hash(hash2)
            return h1 - h2  # Hamming distance
        except Exception as e:
            print(f"Error calculating hamming distance: {e}")
            return 999

    def find_closest_cse_match(self, target_phash: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Find the closest matching CSE domain by visual similarity

        Args:
            target_phash: Perceptual hash of target domain

        Returns:
            (min_distance, closest_cse_hash) or (None, None) if no baseline
        """
        if not self.cse_phashes or not target_phash:
            return None, None

        min_distance = 999
        closest_hash = None

        for cse_hash in self.cse_phashes:
            distance = self.hamming_distance(target_phash, cse_hash)
            if distance < min_distance:
                min_distance = distance
                closest_hash = cse_hash

        return min_distance, closest_hash

    def compute_phash_from_image(self, image_path: str) -> Optional[str]:
        """
        Compute perceptual hash from image file

        Args:
            image_path: Path to screenshot image

        Returns:
            Hex string representation of phash
        """
        try:
            img = Image.open(image_path)
            phash = imagehash.phash(img)
            return str(phash)
        except Exception as e:
            print(f"Error computing phash from {image_path}: {e}")
            return None

    def is_visually_similar_to_cse(self, target_phash: str) -> Tuple[bool, Dict]:
        """
        Check if target domain is visually similar to any CSE domain

        Args:
            target_phash: Perceptual hash of target domain

        Returns:
            (is_similar, details_dict)
        """
        min_distance, closest_hash = self.find_closest_cse_match(target_phash)

        if min_distance is None:
            return False, {
                'verdict': 'UNKNOWN',
                'reason': 'No CSE baseline available',
                'distance': None,
                'threshold': self.phash_threshold
            }

        is_similar = min_distance <= self.phash_threshold

        return is_similar, {
            'verdict': 'SIMILAR' if is_similar else 'DISSIMILAR',
            'distance': min_distance,
            'threshold': self.phash_threshold,
            'closest_cse_hash': closest_hash,
            'similarity_score': max(0, 1 - (min_distance / 64))  # Normalized 0-1
        }

    def detect_impersonation(self, domain: str, target_phash: str,
                            registrable: str) -> Dict:
        """
        Detect visual impersonation attempt

        Logic:
        1. If domain is in CSE whitelist → BENIGN
        2. If visually similar to CSE but NOT in whitelist → PHISHING (impersonation)
        3. If not visually similar → UNKNOWN (need other detection methods)

        Args:
            domain: Domain being checked
            target_phash: Visual hash of domain
            registrable: Registrable domain (e.g., example.com)

        Returns:
            Detection result dictionary
        """
        # Check if domain is in CSE whitelist
        is_whitelisted = registrable in self.cse_domains

        # Check visual similarity
        is_similar, similarity_details = self.is_visually_similar_to_cse(target_phash)

        # Determine verdict
        if is_whitelisted:
            verdict = 'BENIGN'
            confidence = 0.95
            reason = 'Domain in CSE whitelist'
        elif is_similar:
            verdict = 'PHISHING'
            confidence = min(0.9, 0.5 + similarity_details['similarity_score'] * 0.4)
            reason = f"Visually impersonates CSE (distance={similarity_details['distance']})"
        else:
            verdict = 'UNKNOWN'
            confidence = 0.0
            reason = 'Not visually similar to known CSE sites'

        return {
            'verdict': verdict,
            'confidence': confidence,
            'reason': reason,
            'details': {
                'is_whitelisted': is_whitelisted,
                'is_visually_similar': is_similar,
                **similarity_details
            }
        }

    def batch_check_similarity(self, domains_with_phashes: List[Tuple[str, str]]) -> List[Dict]:
        """
        Check visual similarity for multiple domains

        Args:
            domains_with_phashes: List of (registrable, phash) tuples

        Returns:
            List of detection results
        """
        results = []
        for registrable, phash in domains_with_phashes:
            result = self.detect_impersonation(registrable, phash, registrable)
            result['registrable'] = registrable
            results.append(result)

        return results

    def generate_report(self, results: List[Dict]) -> str:
        """Generate human-readable report of detection results"""
        report = []
        report.append("="*70)
        report.append("VISUAL SIMILARITY DETECTION REPORT")
        report.append("="*70)

        phishing_count = sum(1 for r in results if r['verdict'] == 'PHISHING')
        benign_count = sum(1 for r in results if r['verdict'] == 'BENIGN')
        unknown_count = sum(1 for r in results if r['verdict'] == 'UNKNOWN')

        report.append(f"\nSummary:")
        report.append(f"  Total domains: {len(results)}")
        report.append(f"  Phishing (impersonation): {phishing_count}")
        report.append(f"  Benign (whitelisted): {benign_count}")
        report.append(f"  Unknown: {unknown_count}")

        if phishing_count > 0:
            report.append(f"\nPhishing Detections:")
            for r in results:
                if r['verdict'] == 'PHISHING':
                    report.append(f"  - {r['registrable']}")
                    report.append(f"    Confidence: {r['confidence']:.2f}")
                    report.append(f"    Reason: {r['reason']}")
                    report.append(f"    Distance: {r['details']['distance']}")

        report.append("="*70)
        return "\n".join(report)


def main():
    """Example usage and testing"""
    import argparse

    parser = argparse.ArgumentParser(description='Visual similarity detector')
    parser.add_argument('--baseline', default='AIML/data/training/cse_baseline_profile.json',
                       help='CSE baseline profile JSON')
    parser.add_argument('--test-jsonl', help='JSONL file with domains to test')
    args = parser.parse_args()

    # Initialize detector
    print("Initializing Visual Similarity Detector...")
    detector = VisualSimilarityDetector(cse_baseline_path=args.baseline)

    if args.test_jsonl:
        # Test on domains from JSONL
        print(f"\nTesting on domains from {args.test_jsonl}...")

        domains_with_phashes = []
        with open(args.test_jsonl, 'r') as f:
            for line in f:
                data = json.loads(line)
                registrable = data['metadata'].get('registrable', '')
                phash = data['metadata'].get('screenshot_phash', '')
                if registrable and phash:
                    domains_with_phashes.append((registrable, phash))

        results = detector.batch_check_similarity(domains_with_phashes)
        print(detector.generate_report(results))

        # Save results
        output_file = 'AIML/data/visual_detection_results.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✓ Results saved to {output_file}")

    else:
        # Demo mode
        print("\nDemo mode: Testing visual similarity detector")
        print("=" * 70)

        # Example: Test if a hypothetical phishing site matches CSE baseline
        if detector.cse_phashes:
            # Use first CSE phash as example
            test_phash = detector.cse_phashes[0]
            print(f"\nTest 1: CSE domain with exact visual match")
            result = detector.detect_impersonation("test.com", test_phash, "test.com")
            print(f"  Verdict: {result['verdict']}")
            print(f"  Confidence: {result['confidence']:.2f}")
            print(f"  Reason: {result['reason']}")

            # Simulate slightly modified phash (1 bit different)
            test_hash_obj = imagehash.hex_to_hash(test_phash)
            modified_bits = list(test_hash_obj.hash.flatten())
            modified_bits[0] = not modified_bits[0]  # Flip one bit
            modified_hash_array = np.array(modified_bits).reshape(test_hash_obj.hash.shape)
            modified_phash = str(imagehash.ImageHash(modified_hash_array))

            print(f"\nTest 2: Non-CSE domain with similar visual (distance=1)")
            result = detector.detect_impersonation("fake-bank.com", modified_phash, "fake-bank.com")
            print(f"  Verdict: {result['verdict']}")
            print(f"  Confidence: {result['confidence']:.2f}")
            print(f"  Reason: {result['reason']}")
            print(f"  Distance: {result['details']['distance']}")


if __name__ == "__main__":
    main()
