#!/usr/bin/env python3
"""
Unified Phishing Detection Engine

Combines multiple detection modules for comprehensive phishing detection:
1. Anomaly detection (deviation from CSE baseline)
2. Visual similarity (screenshot impersonation)
3. Content analysis (phishing keywords, forms)
4. Domain reputation (typo-squatting, IDN, TLD risk)

Provides weighted verdict aggregation and confidence scoring.
"""

import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional
import sys

# Import detection modules
sys.path.append(str(Path(__file__).parent))
try:
    from detectors.visual_similarity_clip import CLIPVisualDetector
    CLIP_AVAILABLE = True
except ImportError:
    from detectors.visual_similarity import VisualSimilarityDetector
    CLIP_AVAILABLE = False
from detectors.content_detector import ContentPhishingDetector
from detectors.domain_reputation import DomainReputationAnalyzer

# Import PyTorch for autoencoder
try:
    import torch
    import torch.nn as nn
    from torchvision import transforms, models
    from PIL import Image
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


class ScreenshotAutoencoder(nn.Module):
    """Autoencoder for screenshot anomaly detection"""
    def __init__(self, latent_dim=512):
        super().__init__()
        # Use pretrained ResNet as encoder
        resnet = models.resnet18(weights='IMAGENET1K_V1')
        self.encoder = nn.Sequential(*list(resnet.children())[:-2])

        # Decoder: upsample from 7x7 to 224x224
        self.decoder = nn.Sequential(
            nn.ConvTranspose2d(512, 256, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm2d(256),
            nn.ReLU(),
            nn.ConvTranspose2d(256, 128, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm2d(128),
            nn.ReLU(),
            nn.ConvTranspose2d(128, 64, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm2d(64),
            nn.ReLU(),
            nn.ConvTranspose2d(64, 32, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.BatchNorm2d(32),
            nn.ReLU(),
            nn.ConvTranspose2d(32, 3, kernel_size=3, stride=2, padding=1, output_padding=1),
            nn.Tanh()
        )

    def forward(self, x):
        features = self.encoder(x)
        reconstructed = self.decoder(features)
        return reconstructed, features


class UnifiedPhishingDetector:
    """Unified multi-modal phishing detection engine"""

    def __init__(self, config: Dict = None):
        """
        Initialize unified detector

        Args:
            config: Configuration dictionary with paths and weights
        """
        self.config = config or self._get_default_config()

        # Initialize sub-detectors
        self.anomaly_model = None
        self.visual_detector = None
        self.content_detector = None
        self.domain_analyzer = None
        self.autoencoder = None
        self.autoencoder_transform = None

        # Feature names for anomaly model
        self.feature_names = None

        # Verdict weights (configurable)
        self.weights = {
            'anomaly': 0.20,
            'visual': 0.30,
            'content': 0.20,
            'domain': 0.15,
            'autoencoder': 0.15
        }

    def _get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'anomaly_model_path': 'AIML/models/anomaly/anomaly_detector.pkl',
            'feature_names_path': 'AIML/models/anomaly/feature_names.txt',
            'cse_baseline_path': 'AIML/data/training/cse_baseline_profile.json',
            'clip_index_path': 'AIML/models/vision/cse_index_updated',
            'autoencoder_path': 'AIML/models/vision/autoencoder_new/autoencoder_best.pth',
            'use_clip': True,  # Use CLIP if available
            'use_autoencoder': True,  # Use autoencoder if available
            'autoencoder_threshold': 3.5  # Reconstruction error threshold (trained on CSE baseline)
        }

    def load_models(self):
        """Load all detection models"""
        print("Loading detection models...")

        # Load anomaly detection model
        print("  Loading anomaly model...")
        with open(self.config['anomaly_model_path'], 'rb') as f:
            self.anomaly_model = pickle.load(f)

        # Load feature names
        with open(self.config['feature_names_path'], 'r') as f:
            self.feature_names = [line.strip() for line in f]

        # Initialize visual detector (CLIP if available, else phash)
        print("  Initializing visual detector...")
        if CLIP_AVAILABLE and self.config.get('use_clip', True):
            print("    Using CLIP-based visual similarity")
            self.visual_detector = CLIPVisualDetector(
                cse_index_path=self.config['clip_index_path'],
                cse_baseline_path=self.config['cse_baseline_path']
            )
        else:
            print("    Using phash-based visual similarity (CLIP not available)")
            from detectors.visual_similarity import VisualSimilarityDetector
            self.visual_detector = VisualSimilarityDetector(
                cse_baseline_path=self.config['cse_baseline_path']
            )

        # Initialize content detector
        print("  Initializing content detector...")
        self.content_detector = ContentPhishingDetector()

        # Initialize domain analyzer
        print("  Initializing domain analyzer...")
        self.domain_analyzer = DomainReputationAnalyzer()
        self.domain_analyzer.load_cse_whitelist(self.config['cse_baseline_path'])

        # Load autoencoder if available
        if TORCH_AVAILABLE and self.config.get('use_autoencoder', True):
            print("  Loading autoencoder...")
            try:
                autoencoder_path = Path(self.config['autoencoder_path'])
                if autoencoder_path.exists():
                    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
                    self.autoencoder = ScreenshotAutoencoder()
                    self.autoencoder.load_state_dict(torch.load(autoencoder_path, map_location=device))
                    self.autoencoder.to(device)
                    self.autoencoder.eval()

                    # Image preprocessing transform
                    self.autoencoder_transform = transforms.Compose([
                        transforms.Resize((224, 224)),
                        transforms.ToTensor(),
                        transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
                    ])

                    print(f"    ✓ Autoencoder loaded from {autoencoder_path}")
                else:
                    print(f"    ! Autoencoder not found at {autoencoder_path}")
            except Exception as e:
                print(f"    ! Failed to load autoencoder: {e}")

        print("✓ All models loaded successfully\n")

    def prepare_features(self, metadata: Dict) -> Optional[pd.DataFrame]:
        """
        Prepare feature vector for anomaly detection

        Args:
            metadata: Domain metadata dictionary

        Returns:
            Feature DataFrame or None if features unavailable
        """
        try:
            # Extract features in correct order
            features = {}
            for feature_name in self.feature_names:
                value = metadata.get(feature_name)

                # Convert boolean to int
                if isinstance(value, bool):
                    features[feature_name] = int(value)
                # Keep numeric values
                elif isinstance(value, (int, float)):
                    features[feature_name] = value
                # Skip None/missing
                else:
                    features[feature_name] = 0  # Default to 0

            # Create DataFrame
            df = pd.DataFrame([features])
            return df

        except Exception as e:
            print(f"Error preparing features: {e}")
            return None

    def run_anomaly_detection(self, metadata: Dict) -> Dict:
        """Run anomaly detection"""
        try:
            features_df = self.prepare_features(metadata)
            if features_df is None:
                return {
                    'verdict': 'UNKNOWN',
                    'confidence': 0.0,
                    'score': 0.0,
                    'reason': 'Feature extraction failed'
                }

            # Get anomaly score
            score = self.anomaly_model.decision_function(features_df)[0]
            prediction = self.anomaly_model.predict(features_df)[0]

            # Higher score = more normal (benign)
            # Lower score = anomaly (potential phishing)
            if prediction == -1:  # Anomaly
                verdict = 'ANOMALY'
                confidence = 0.6 + min(0.3, abs(score) * 0.5)
            else:  # Normal
                verdict = 'NORMAL'
                confidence = 0.5 + min(0.4, score * 2)

            return {
                'verdict': verdict,
                'confidence': confidence,
                'score': float(score),
                'reason': f'Anomaly score: {score:.3f}'
            }

        except Exception as e:
            return {
                'verdict': 'ERROR',
                'confidence': 0.0,
                'score': 0.0,
                'reason': f'Anomaly detection error: {str(e)}'
            }

    def find_screenshot_path(self, registrable: str, domain_id: str = '', screenshot_path_hint: str = '') -> Optional[str]:
        """Find screenshot file for a domain"""
        # If we have a path hint, extract filename and search for it
        if screenshot_path_hint:
            filename = Path(screenshot_path_hint).name
            screenshot_dirs = [
                Path('/home/turtleneck/Desktop/PS02/Pipeline/out/screenshots'),
                Path('Pipeline/out/screenshots'),
                Path('../Pipeline/out/screenshots')
            ]

            for screenshot_dir in screenshot_dirs:
                if not screenshot_dir.exists():
                    continue
                candidate = screenshot_dir / filename
                if candidate.exists():
                    return str(candidate)

        # Fall back to pattern matching
        screenshot_dirs = [
            Path('/home/turtleneck/Desktop/PS02/Pipeline/out/screenshots'),
            Path('Pipeline/out/screenshots'),
            Path('../Pipeline/out/screenshots')
        ]

        for screenshot_dir in screenshot_dirs:
            if not screenshot_dir.exists():
                continue

            # Try various filename patterns
            patterns = [
                f"{registrable.replace('.', '_')}*.png",
                f"{registrable}*.png"
            ]

            for pattern in patterns:
                matches = list(screenshot_dir.glob(pattern))
                if matches:
                    return str(matches[0])

        return None

    def run_visual_detection(self, metadata: Dict) -> Dict:
        """Run visual similarity detection"""
        try:
            registrable = metadata.get('registrable', '')
            domain_id = metadata.get('id', '')

            # Try CLIP-based detection if available
            if isinstance(self.visual_detector, CLIPVisualDetector):
                screenshot_path_hint = metadata.get('screenshot_path', '')
                screenshot_path = self.find_screenshot_path(registrable, domain_id, screenshot_path_hint)

                phash = metadata.get('screenshot_phash', '')

                result = self.visual_detector.detect(
                    screenshot_path=screenshot_path if screenshot_path else None,
                    phash=phash if phash else None,
                    domain=registrable,
                    registrable=registrable
                )
                return result

            # Fall back to phash-only detection
            else:
                phash = metadata.get('screenshot_phash', '')

                if not phash:
                    return {
                        'verdict': 'UNKNOWN',
                        'confidence': 0.0,
                        'reason': 'No screenshot available'
                    }

                result = self.visual_detector.detect_impersonation(
                    registrable, phash, registrable
                )
                return result

        except Exception as e:
            return {
                'verdict': 'ERROR',
                'confidence': 0.0,
                'reason': f'Visual detection error: {str(e)}'
            }

    def run_content_detection(self, metadata: Dict) -> Dict:
        """Run content-based detection"""
        try:
            result = self.content_detector.detect_phishing(metadata)
            return result

        except Exception as e:
            return {
                'verdict': 'ERROR',
                'confidence': 0.0,
                'reason': f'Content detection error: {str(e)}'
            }

    def run_domain_analysis(self, metadata: Dict) -> Dict:
        """Run domain reputation analysis"""
        try:
            registrable = metadata.get('registrable', '')
            result = self.domain_analyzer.analyze_reputation(registrable, metadata)
            return result

        except Exception as e:
            return {
                'verdict': 'ERROR',
                'confidence': 0.0,
                'reason': f'Domain analysis error: {str(e)}'
            }

    def run_autoencoder_detection(self, metadata: Dict) -> Dict:
        """Run autoencoder-based visual anomaly detection"""
        if not self.autoencoder:
            return {
                'verdict': 'UNKNOWN',
                'confidence': 0.0,
                'error': 0.0,
                'reason': 'Autoencoder not available'
            }

        try:
            registrable = metadata.get('registrable', '')
            domain_id = metadata.get('id', '')

            # Find screenshot
            screenshot_path_hint = metadata.get('screenshot_path', '')
            screenshot_path = self.find_screenshot_path(registrable, domain_id, screenshot_path_hint)

            if not screenshot_path or not Path(screenshot_path).exists():
                return {
                    'verdict': 'UNKNOWN',
                    'confidence': 0.0,
                    'error': 0.0,
                    'reason': 'Screenshot not found'
                }

            # Load and preprocess image
            img = Image.open(screenshot_path).convert('RGB')
            img_tensor = self.autoencoder_transform(img).unsqueeze(0)

            device = next(self.autoencoder.parameters()).device
            img_tensor = img_tensor.to(device)

            # Compute reconstruction error
            with torch.no_grad():
                reconstructed, _ = self.autoencoder(img_tensor)
                error = nn.MSELoss()(reconstructed, img_tensor).item()

            # Determine verdict based on reconstruction error
            threshold = self.config.get('autoencoder_threshold', 2.0)

            if error > threshold * 1.5:
                # Very high error - likely phishing
                verdict = 'ANOMALY'
                confidence = 0.75 + min(0.20, (error - threshold * 1.5) / threshold * 0.2)
                reason = f'High visual reconstruction error ({error:.3f} > {threshold:.3f})'
            elif error > threshold:
                # Moderate error - suspicious
                verdict = 'SUSPICIOUS'
                confidence = 0.5 + min(0.25, (error - threshold) / threshold * 0.25)
                reason = f'Moderate visual reconstruction error ({error:.3f})'
            else:
                # Low error - looks like CSE baseline
                verdict = 'NORMAL'
                confidence = 0.6 + min(0.35, (1 - error / threshold) * 0.35)
                reason = f'Low visual reconstruction error ({error:.3f})'

            return {
                'verdict': verdict,
                'confidence': confidence,
                'error': float(error),
                'threshold': threshold,
                'reason': reason
            }

        except Exception as e:
            return {
                'verdict': 'ERROR',
                'confidence': 0.0,
                'error': 0.0,
                'reason': f'Autoencoder detection error: {str(e)}'
            }

    def aggregate_verdicts(self, results: Dict) -> Dict:
        """
        Aggregate verdicts from all detectors

        Weighted voting system:
        - PHISHING/MALICIOUS → high risk
        - SUSPICIOUS/ANOMALY → medium risk
        - BENIGN/NORMAL → low risk

        Args:
            results: Dictionary with results from each detector

        Returns:
            Final aggregated verdict
        """
        # Map verdicts to risk scores
        verdict_risk_map = {
            'PHISHING': 1.0,
            'MALICIOUS': 1.0,
            'SUSPICIOUS': 0.6,
            'ANOMALY': 0.7,
            'SIMILAR': 0.8,  # Visual similarity to CSE but not whitelisted
            'BENIGN': 0.0,
            'NORMAL': 0.0,
            'DISSIMILAR': 0.0,
            'UNKNOWN': 0.3,  # Neutral
            'ERROR': 0.0     # Ignore errors
        }

        # Calculate weighted risk score
        total_risk = 0.0
        total_weight = 0.0

        for detector_name, weight in self.weights.items():
            result = results.get(detector_name, {})
            verdict = result.get('verdict', 'UNKNOWN')
            confidence = result.get('confidence', 0.0)

            risk = verdict_risk_map.get(verdict, 0.3)

            # Weight by both detector weight and confidence
            effective_weight = weight * confidence
            total_risk += risk * effective_weight
            total_weight += effective_weight

        # Calculate final risk score
        if total_weight > 0:
            final_risk_score = total_risk / total_weight
        else:
            final_risk_score = 0.3  # Default neutral

        # Determine final verdict
        if final_risk_score >= 0.7:
            final_verdict = 'PHISHING'
            final_confidence = 0.7 + final_risk_score * 0.25
        elif final_risk_score >= 0.45:
            final_verdict = 'SUSPICIOUS'
            final_confidence = 0.5 + final_risk_score * 0.3
        else:
            final_verdict = 'BENIGN'
            final_confidence = max(0.4, 1.0 - final_risk_score)

        # Collect reasons
        reasons = []
        for detector, result in results.items():
            if result['verdict'] in ['PHISHING', 'MALICIOUS', 'SUSPICIOUS', 'ANOMALY', 'SIMILAR']:
                reasons.append(f"{detector}: {result.get('reason', result['verdict'])}")

        return {
            'verdict': final_verdict,
            'confidence': final_confidence,
            'risk_score': final_risk_score,
            'reasons': reasons,
            'detector_results': results
        }

    def detect(self, metadata: Dict) -> Dict:
        """
        Run complete detection pipeline on a domain

        Args:
            metadata: Domain metadata with all features

        Returns:
            Complete detection result
        """
        # Run all detectors
        results = {
            'anomaly': self.run_anomaly_detection(metadata),
            'visual': self.run_visual_detection(metadata),
            'content': self.run_content_detection(metadata),
            'domain': self.run_domain_analysis(metadata),
            'autoencoder': self.run_autoencoder_detection(metadata)
        }

        # Aggregate verdicts
        final_result = self.aggregate_verdicts(results)

        # Add domain info
        final_result['registrable'] = metadata.get('registrable', 'unknown')
        final_result['url'] = metadata.get('document', '')

        return final_result

    def _convert_to_json_serializable(self, obj):
        """Convert numpy/pandas types to JSON-serializable Python types"""
        if isinstance(obj, dict):
            return {k: self._convert_to_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_to_json_serializable(item) for item in obj]
        elif isinstance(obj, (np.bool_, np.integer)):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        else:
            return obj

    def batch_detect(self, domains_jsonl: str, output_file: str = None) -> List[Dict]:
        """
        Detect phishing for multiple domains from JSONL

        Args:
            domains_jsonl: Path to JSONL file with domain metadata
            output_file: Optional path to save results

        Returns:
            List of detection results
        """
        print(f"Loading domains from {domains_jsonl}...")
        domains = []
        with open(domains_jsonl, 'r') as f:
            for line in f:
                domains.append(json.loads(line))

        print(f"Processing {len(domains)} domains...\n")

        results = []
        for idx, domain_data in enumerate(domains):
            metadata = domain_data['metadata']
            result = self.detect(metadata)
            # Convert to JSON-serializable
            result = self._convert_to_json_serializable(result)
            results.append(result)

            # Progress
            if (idx + 1) % 10 == 0:
                print(f"  Processed {idx + 1}/{len(domains)} domains...")

        # Save results if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n✓ Results saved to {output_file}")

        return results

    def generate_report(self, results: List[Dict]) -> str:
        """Generate detection summary report"""
        report = []
        report.append("="*70)
        report.append("UNIFIED PHISHING DETECTION REPORT")
        report.append("="*70)

        phishing_count = sum(1 for r in results if r['verdict'] == 'PHISHING')
        suspicious_count = sum(1 for r in results if r['verdict'] == 'SUSPICIOUS')
        benign_count = sum(1 for r in results if r['verdict'] == 'BENIGN')

        report.append(f"\nSummary:")
        report.append(f"  Total domains: {len(results)}")
        report.append(f"  Phishing: {phishing_count}")
        report.append(f"  Suspicious: {suspicious_count}")
        report.append(f"  Benign: {benign_count}")

        if phishing_count > 0:
            report.append(f"\nPhishing Detections:")
            for r in results:
                if r['verdict'] == 'PHISHING':
                    report.append(f"\n  {r['registrable']}")
                    report.append(f"    Confidence: {r['confidence']:.2f}")
                    report.append(f"    Risk Score: {r['risk_score']:.2f}")
                    if r['reasons']:
                        report.append(f"    Reasons:")
                        for reason in r['reasons']:
                            report.append(f"      - {reason}")

        if suspicious_count > 0:
            report.append(f"\nSuspicious Domains:")
            for r in results:
                if r['verdict'] == 'SUSPICIOUS':
                    report.append(f"  - {r['registrable']} (confidence: {r['confidence']:.2f})")

        report.append("="*70)
        return "\n".join(report)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Unified phishing detection engine')
    parser.add_argument('--input', default='AIML/data/complete_features.jsonl',
                       help='Input JSONL with domain features')
    parser.add_argument('--output', default='AIML/results/detection_results.json',
                       help='Output JSON file for results')
    parser.add_argument('--config', help='Optional config JSON file')
    args = parser.parse_args()

    # Load config
    config = None
    if args.config and Path(args.config).exists():
        with open(args.config, 'r') as f:
            config = json.load(f)

    # Initialize detector
    print("="*70)
    print("UNIFIED PHISHING DETECTION ENGINE")
    print("="*70)
    print()

    detector = UnifiedPhishingDetector(config=config)
    detector.load_models()

    # Run detection
    print(f"Input: {args.input}")
    print(f"Output: {args.output}")
    print()

    # Create output directory
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    # Batch detect
    results = detector.batch_detect(args.input, args.output)

    # Generate report
    print()
    print(detector.generate_report(results))


if __name__ == "__main__":
    main()
