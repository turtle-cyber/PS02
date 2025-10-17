"""
Unified Multi-Modal Phishing Detection System
Combines: Tabular Anomaly + Screenshot Phash + Favicon Hash + CLIP Similarity + Autoencoder
"""

import argparse
import json
import numpy as np
import pandas as pd
import joblib
import torch
import torch.nn as nn
from pathlib import Path
from PIL import Image
import imagehash
import open_clip
from torchvision import transforms, models
from urllib.parse import urlparse

def extract_domain_from_url(url_or_domain):
    """Extract clean domain from URL or domain string"""
    # Remove whitespace
    url_or_domain = url_or_domain.strip()

    # Add scheme if missing (for urlparse to work correctly)
    if not url_or_domain.startswith(('http://', 'https://')):
        url_or_domain = 'http://' + url_or_domain

    # Parse URL
    parsed = urlparse(url_or_domain)
    domain = parsed.netloc or parsed.path

    # Remove port if present
    if ':' in domain:
        domain = domain.split(':')[0]

    # Remove trailing slashes or dots
    domain = domain.rstrip('./').strip()

    return domain


class UnifiedPhishingDetector:
    """Multi-modal phishing detector combining all signals"""

    def __init__(self, model_dir="models", data_dir="data"):
        self.model_dir = Path(model_dir)
        self.data_dir = Path(data_dir)

        print("Loading models and databases...")

        # 1. Load tabular anomaly detector
        self.tabular_model = joblib.load(
            self.model_dir / "tabular/anomaly_all/anomaly_detector.joblib"
        )
        # Load feature names from metadata
        with open(self.model_dir / "tabular/anomaly_all/metadata.json") as f:
            metadata = json.load(f)
            all_features = metadata['features']

        # Use all features from metadata (model was trained on all 52)
        self.feature_names = all_features

        # Identify string columns that need encoding
        self.string_columns = [
            'registrar', 'country', 'favicon_md5', 'favicon_sha256',
            'document_text', 'doc_verdict', 'doc_submit_buttons',
            'screenshot_phash', 'ocr_text'
        ]
        print(f"✓ Tabular model loaded ({len(self.feature_names)} features)")

        # 2. Load CLIP model and CSE index
        try:
            self.clip_model, _, self.clip_preprocess = open_clip.create_model_and_transforms(
                'ViT-B-32', pretrained='laion2b_s34b_b79k'
            )
            self.clip_model.eval()
            self.cse_embeddings = np.load(self.model_dir / "vision/cse_index/cse_embeddings.npy")
            with open(self.model_dir / "vision/cse_index/cse_metadata.json") as f:
                self.cse_metadata = json.load(f)
            print(f"✓ CLIP model loaded ({len(self.cse_embeddings)} CSE embeddings)")
        except Exception as e:
            print(f"⚠ CLIP model not available: {e}")
            self.clip_model = None

        # 3. Load vision autoencoder
        try:
            self.autoencoder = self._load_autoencoder(
                self.model_dir / "vision/autoencoder/autoencoder_best.pth"
            )
            print(f"✓ Autoencoder loaded")
        except Exception as e:
            print(f"⚠ Autoencoder not available: {e}")
            self.autoencoder = None

        # 4. Load hash databases
        self.favicon_db = pd.read_csv(self.data_dir / "cse_favicon_db.csv")
        self.phash_db = pd.read_csv(self.data_dir / "cse_phash_db.csv")
        print(f"✓ Favicon DB: {len(self.favicon_db)} entries")
        print(f"✓ Phash DB: {len(self.phash_db)} entries")

        # 5. Load CSE features for registrar matching
        self.cse_features_df = pd.read_csv(self.data_dir / "cse_all_features.csv")
        print(f"✓ CSE Features DB: {len(self.cse_features_df)} entries")

        # 6. Build CSE domain whitelist
        self.cse_domains = set(self.cse_features_df['registrable'].unique())
        print(f"✓ CSE Whitelist: {len(self.cse_domains)} verified benign domains")

        print("\nAll models loaded successfully!\n")

    def _load_autoencoder(self, path):
        """Load autoencoder model"""
        from models.vision.train_cse_autoencoder import ScreenshotAutoencoder
        model = ScreenshotAutoencoder()
        model.load_state_dict(torch.load(path, map_location='cpu'))
        model.eval()
        return model

    def domains_are_related(self, domain1, domain2):
        """Check if domains likely belong to same organization"""
        # Extract base names (before first dot)
        base1 = domain1.split('.')[0]
        base2 = domain2.split('.')[0]

        # Check if subdomain (e.g., api.sbi.co.in vs sbi.co.in)
        if domain1.endswith('.' + domain2) or domain2.endswith('.' + domain1):
            return True

        # Check if same base name or one contains the other
        if base1 in base2 or base2 in base1:
            return True

        return False

    def check_favicon_match(self, favicon_md5, domain):
        """Check if favicon matches CSE site"""
        if not favicon_md5 or pd.isna(favicon_md5):
            return None

        matches = self.favicon_db[self.favicon_db['favicon_md5'] == favicon_md5]
        if len(matches) > 0:
            for _, row in matches.iterrows():
                cse_domain = row['registrable']
                if domain != cse_domain:
                    return {
                        'signal': 'favicon_match',
                        'verdict': 'PHISHING',
                        'confidence': 0.95,
                        'reason': f"Favicon matches {cse_domain} but domain is different",
                        'matched_cse': cse_domain
                    }
        return None

    def check_registrar_match(self, suspicious_domain, suspicious_registrar, matched_cse_domain):
        """Check if registrar matches CSE organization (reduces false positives)"""
        if not suspicious_registrar or pd.isna(suspicious_registrar) or suspicious_registrar == '':
            return None  # No WHOIS data available

        # Find CSE domain's registrar
        cse_data = self.cse_features_df[
            self.cse_features_df['registrable'] == matched_cse_domain
        ]

        if len(cse_data) == 0:
            return None

        cse_registrar = cse_data.iloc[0]['registrar']

        if pd.isna(cse_registrar) or cse_registrar == '':
            return None  # CSE also has no registrar data

        # Check if same registrar
        if suspicious_registrar == cse_registrar:
            # Same registrar - check if domain names are related
            if self.domains_are_related(suspicious_domain, matched_cse_domain):
                return {
                    'signal': 'registrar_match',
                    'verdict': 'BENIGN',
                    'confidence': 0.90,
                    'reason': f'Registered by {suspicious_registrar} (same as {matched_cse_domain})',
                    'matched_cse': matched_cse_domain
                }
        else:
            # Different registrar + visual match = likely phishing
            return {
                'signal': 'registrar_mismatch',
                'verdict': 'PHISHING',
                'confidence': 0.93,
                'reason': f'Visual clone of {matched_cse_domain} but different registrar ({suspicious_registrar} vs {cse_registrar})',
                'suspicious_registrar': suspicious_registrar,
                'cse_registrar': cse_registrar,
                'matched_cse': matched_cse_domain
            }

        return None

    def check_phash_match(self, screenshot_path, domain):
        """Check if screenshot phash matches CSE site"""
        if not screenshot_path or not Path(screenshot_path).exists():
            return None

        # Compute phash
        img = Image.open(screenshot_path)
        phash = str(imagehash.phash(img))

        # Check against database
        matches = self.phash_db[self.phash_db['screenshot_phash'] == phash]
        if len(matches) > 0:
            for _, row in matches.iterrows():
                cse_domain = row['registrable']
                if domain != cse_domain:
                    return {
                        'signal': 'phash_match',
                        'verdict': 'PHISHING',
                        'confidence': 0.92,
                        'reason': f"Screenshot identical to {cse_domain}",
                        'matched_cse': cse_domain,
                        'phash': phash
                    }
        return None

    def check_clip_similarity(self, screenshot_path, domain):
        """Check CLIP visual similarity"""
        if not self.clip_model or not screenshot_path:
            return None

        # Embed query screenshot
        img = Image.open(screenshot_path).convert('RGB')
        img_tensor = self.clip_preprocess(img).unsqueeze(0)

        with torch.no_grad():
            query_emb = self.clip_model.encode_image(img_tensor)
            query_emb = query_emb / query_emb.norm(dim=-1, keepdim=True)

        # Compute similarities
        query_emb = query_emb.cpu().numpy().flatten()
        similarities = query_emb @ self.cse_embeddings.T

        # Find best match
        max_idx = similarities.argmax()
        max_sim = float(similarities[max_idx])
        matched_meta = self.cse_metadata[max_idx]
        matched_domain_raw = matched_meta['domain']

        # Normalize domain (strip filename suffixes like _99dd5fbe)
        matched_domain = matched_domain_raw.split('_')[0]

        if max_sim > 0.85 and domain != matched_domain:
            return {
                'signal': 'clip_similarity',
                'verdict': 'PHISHING',
                'confidence': 0.88,
                'reason': f"High visual similarity to {matched_domain} (sim={max_sim:.3f})",
                'matched_cse': matched_domain,
                'similarity': max_sim
            }

        return None

    def check_autoencoder_anomaly(self, screenshot_path):
        """Check autoencoder reconstruction error"""
        if not self.autoencoder or not screenshot_path:
            return None

        transform = transforms.Compose([
            transforms.Resize((224, 224)),
            transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406], [0.229, 0.224, 0.225])
        ])

        img = Image.open(screenshot_path).convert('RGB')
        img_tensor = transform(img).unsqueeze(0)

        with torch.no_grad():
            reconstructed, _ = self.autoencoder(img_tensor)
            error = nn.functional.mse_loss(reconstructed, img_tensor).item()

        # Threshold for anomaly (adjusted to be less sensitive)
        if error > 2.0:  # Increased from 0.05
            return {
                'signal': 'autoencoder_anomaly',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.70,
                'reason': f"Unusual visual patterns (reconstruction error={error:.4f})",
                'error': error
            }

        return None

    def check_parking_signals(self, features, domain):
        """Detect if domain shows parking indicators via ML features"""
        if not features:
            return None

        parking_score = 0
        indicators = []

        # 1. DNS-based: NS records pointing to parking providers
        ns_records = features.get('ns_records', '') or ''
        if isinstance(ns_records, str):
            ns_lower = ns_records.lower()
            parking_ns = ['sedoparking', 'parkingcrew', 'bodis', 'cashparking', 'dns-parking']
            for provider in parking_ns:
                if provider in ns_lower:
                    parking_score += 3
                    indicators.append(f"NS points to {provider}")
                    break

        # 2. No MX records (parked domains typically don't have email)
        mx_count = features.get('mx_count', 0) or 0
        if mx_count == 0:
            parking_score += 1

        # 3. Minimal HTML with parking keywords
        html_size = features.get('html_size', 0) or 0
        doc_text = (features.get('document_text', '') or '').lower()

        if html_size < 10000:  # Small page
            parking_keywords = ['domain for sale', 'buy this domain', 'parked', 'make an offer',
                               'sedoparking', 'afternic', 'dan.com', 'hugedomains']
            keyword_count = sum(1 for kw in parking_keywords if kw in doc_text)
            if keyword_count >= 2:
                parking_score += 2
                indicators.append(f"Parking keywords detected ({keyword_count} matches)")

        # 4. No forms (parked domains rarely have forms)
        form_count = features.get('form_count', 0) or 0
        if form_count == 0 and html_size > 0:
            parking_score += 1

        # Decision: Score ≥ 4 indicates parking
        if parking_score >= 4:
            return {
                'signal': 'parking_detection',
                'verdict': 'PARKED',
                'confidence': 0.90,
                'reason': f"Parking indicators detected: {', '.join(indicators)}",
                'parking_score': parking_score
            }

        return None

    def check_tabular_anomaly(self, features):
        """Check tabular feature anomaly"""
        # Prepare features - convert strings to category codes
        feature_dict = {}
        for fname in self.feature_names:
            val = features.get(fname, 0)

            # Handle NaN/None values FIRST (before any processing)
            if val is None or pd.isna(val):
                val = 0

            # Convert string columns to numeric (simple hash for now)
            if fname in self.string_columns and isinstance(val, str):
                val = hash(val) % 10000  # Simple encoding

            # Ensure numeric type (convert bool to int)
            if isinstance(val, bool):
                val = int(val)

            feature_dict[fname] = val

        feature_vector = [feature_dict[f] for f in self.feature_names]

        # Predict
        score = self.tabular_model.decision_function([feature_vector])[0]
        prediction = self.tabular_model.predict([feature_vector])[0]

        # Only flag if strongly anomalous (stricter threshold)
        if prediction == -1 and score < -0.10:  # Added score threshold
            return {
                'signal': 'tabular_anomaly',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.65,
                'reason': f"Features deviate from CSE baseline (score={score:.3f})",
                'anomaly_score': score
            }

        return None

    def detect(self, domain, features=None, screenshot_path=None, favicon_md5=None, registrar=None):
        """
        Run complete multi-modal detection

        Args:
            domain: Domain name or URL to check
            features: Dict of tabular features
            screenshot_path: Path to screenshot
            favicon_md5: MD5 hash of favicon
            registrar: Registrar name from WHOIS (optional, reduces false positives)

        Returns:
            Dict with verdict, confidence, signals, and reasons
        """
        # Clean domain from URL
        domain = extract_domain_from_url(domain)

        # STAGE 1: CSE Whitelist Check (fast path)
        if domain in self.cse_domains:
            return {
                'domain': domain,
                'verdict': 'BENIGN',
                'confidence': 0.95,
                'signals': [{
                    'signal': 'cse_whitelist',
                    'verdict': 'BENIGN',
                    'confidence': 0.95,
                    'reason': f'{domain} is a verified CSE domain (whitelist match)'
                }],
                'signal_count': 0
            }

        # Check if domain is subdomain of any CSE domain (suffix matching)
        for cse_domain in self.cse_domains:
            # Check if query domain ends with CSE domain (proper subdomain)
            # e.g., api.sbi.co.in ends with sbi.co.in
            if domain.endswith('.' + cse_domain) or domain == cse_domain:
                return {
                    'domain': domain,
                    'verdict': 'BENIGN',
                    'confidence': 0.90,
                    'signals': [{
                        'signal': 'cse_subdomain',
                        'verdict': 'BENIGN',
                        'confidence': 0.90,
                        'reason': f'{domain} is subdomain of verified CSE domain: {cse_domain}'
                    }],
                    'signal_count': 0
                }

        # STAGE 2: Parking Detection (before similarity checks)
        if features:
            parking_result = self.check_parking_signals(features, domain)
            if parking_result and parking_result['verdict'] == 'PARKED':
                return {
                    'domain': domain,
                    'verdict': 'PARKED',
                    'confidence': parking_result['confidence'],
                    'signals': [parking_result],
                    'signal_count': 0
                }

        # STAGE 3: Similarity Detection (slow path)
        signals = []
        matched_cse_domain = None  # Track which CSE domain was matched

        # Priority 1: Favicon match (highest confidence)
        result = self.check_favicon_match(favicon_md5, domain)
        if result and result['verdict'] == 'PHISHING':
            matched_cse_domain = result.get('matched_cse')
            # Check registrar before declaring phishing
            if registrar and matched_cse_domain:
                registrar_result = self.check_registrar_match(domain, registrar, matched_cse_domain)
                if registrar_result and registrar_result['verdict'] == 'BENIGN':
                    # Same registrar - legitimate new domain, not phishing
                    signals.append(registrar_result)
                    result = None  # Cancel phishing verdict
            if result:
                signals.append(result)

        # Priority 2: Screenshot phash match
        result = self.check_phash_match(screenshot_path, domain)
        if result and result['verdict'] == 'PHISHING':
            matched_cse_domain = result.get('matched_cse')
            # Check registrar before declaring phishing
            if registrar and matched_cse_domain:
                registrar_result = self.check_registrar_match(domain, registrar, matched_cse_domain)
                if registrar_result and registrar_result['verdict'] == 'BENIGN':
                    signals.append(registrar_result)
                    result = None
                elif registrar_result and registrar_result['verdict'] == 'PHISHING':
                    # Different registrar strengthens phishing verdict
                    signals.append(registrar_result)
            if result:
                signals.append(result)

        # Priority 3: CLIP similarity
        result = self.check_clip_similarity(screenshot_path, domain)
        if result and result['verdict'] == 'PHISHING':
            matched_cse_domain = result.get('matched_cse')
            # Check registrar before declaring phishing
            if registrar and matched_cse_domain:
                registrar_result = self.check_registrar_match(domain, registrar, matched_cse_domain)
                if registrar_result and registrar_result['verdict'] == 'BENIGN':
                    signals.append(registrar_result)
                    result = None
                elif registrar_result and registrar_result['verdict'] == 'PHISHING':
                    signals.append(registrar_result)
            if result:
                signals.append(result)

        # Priority 4: Autoencoder anomaly
        result = self.check_autoencoder_anomaly(screenshot_path)
        if result:
            signals.append(result)

        # Priority 5: Tabular anomaly
        if features:
            result = self.check_tabular_anomaly(features)
            if result:
                signals.append(result)

        # Determine final verdict (priority: PHISHING > PARKED > SUSPICIOUS > BENIGN)
        if any(s['verdict'] == 'PHISHING' for s in signals):
            verdict = 'PHISHING'
            confidence = max(s['confidence'] for s in signals if s['verdict'] == 'PHISHING')
        elif any(s['verdict'] == 'PARKED' for s in signals):
            verdict = 'PARKED'
            confidence = max(s['confidence'] for s in signals if s['verdict'] == 'PARKED')
        elif any(s['verdict'] == 'SUSPICIOUS' for s in signals):
            verdict = 'SUSPICIOUS'
            confidence = max(s['confidence'] for s in signals)
        else:
            verdict = 'BENIGN'
            confidence = 0.85
            signals.append({
                'signal': 'no_anomalies',
                'verdict': 'BENIGN',
                'confidence': 0.85,
                'reason': 'No anomalies detected across all modalities'
            })

        return {
            'domain': domain,
            'verdict': verdict,
            'confidence': confidence,
            'signals': signals,
            'signal_count': len([s for s in signals if s['verdict'] != 'BENIGN'])
        }


def main():
    ap = argparse.ArgumentParser(description="Unified multi-modal phishing detection")
    ap.add_argument("--domain", required=True, help="Domain to check")
    ap.add_argument("--screenshot", help="Path to screenshot (optional)")
    ap.add_argument("--favicon_md5", help="Favicon MD5 hash (optional)")
    ap.add_argument("--features_csv", help="CSV with features (optional)")
    args = ap.parse_args()

    # Load detector
    detector = UnifiedPhishingDetector()

    # Load features if provided
    features = None
    registrar = None
    if args.features_csv:
        df = pd.read_csv(args.features_csv)
        domain_row = df[df['registrable'] == args.domain]
        if len(domain_row) > 0:
            features = domain_row.iloc[0].to_dict()
            # Extract registrar for false positive reduction
            registrar = features.get('registrar', None)
            if pd.isna(registrar) or registrar == '':
                registrar = None

    # Detect
    result = detector.detect(
        domain=args.domain,
        features=features,
        screenshot_path=args.screenshot,
        favicon_md5=args.favicon_md5,
        registrar=registrar
    )

    # Print results
    print("\n" + "="*70)
    print(f"DETECTION RESULTS: {args.domain}")
    print("="*70)
    print(f"\nVerdict: {result['verdict']}")
    print(f"Confidence: {result['confidence']:.2f}")
    print(f"Signals detected: {result['signal_count']}")

    print(f"\nDetailed Signals:")
    for i, signal in enumerate(result['signals'], 1):
        print(f"\n{i}. [{signal['signal'].upper()}]")
        print(f"   Verdict: {signal['verdict']}")
        print(f"   Confidence: {signal['confidence']:.2f}")
        print(f"   Reason: {signal['reason']}")
        if 'matched_cse' in signal:
            print(f"   Matched CSE domain: {signal['matched_cse']}")

    print("\n" + "="*70)


if __name__ == "__main__":
    main()
