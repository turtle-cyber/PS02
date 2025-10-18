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
from difflib import SequenceMatcher

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

        # 7. Load legitimate domains database (similar names, different orgs)
        try:
            self.legitimate_domains_df = pd.read_csv(self.data_dir / "legitimate_domains.csv")
            self.legitimate_domains = set(self.legitimate_domains_df['domain'].unique())
            print(f"✓ Legitimate Domains DB: {len(self.legitimate_domains)} verified non-CSE benign domains")
        except FileNotFoundError:
            print("⚠ legitimate_domains.csv not found, skipping similar-name protection")
            self.legitimate_domains = set()
            self.legitimate_domains_df = pd.DataFrame()

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

    def calculate_name_similarity(self, domain1, domain2):
        """Calculate similarity between two domain names (0-1 scale)"""
        # Extract base names (before TLD)
        base1 = domain1.split('.')[0].lower()
        base2 = domain2.split('.')[0].lower()

        # Use SequenceMatcher for similarity ratio
        similarity = SequenceMatcher(None, base1, base2).ratio()
        return similarity

    def find_similar_cse_domains(self, domain, similarity_threshold=0.6):
        """
        Find CSE domains with similar names

        Args:
            domain: Domain to check
            similarity_threshold: Minimum similarity ratio (0.6 = 60% similar)

        Returns:
            List of (cse_domain, similarity_score) tuples
        """
        similar_domains = []

        for cse_domain in self.cse_domains:
            similarity = self.calculate_name_similarity(domain, cse_domain)

            # If similar enough but not exact match
            if similarity >= similarity_threshold and domain != cse_domain:
                similar_domains.append((cse_domain, similarity))

        # Sort by similarity (highest first)
        similar_domains.sort(key=lambda x: x[1], reverse=True)
        return similar_domains

    def check_visual_dissimilarity(self, screenshot_path, favicon_md5, matched_cse_domain):
        """
        Check if visual characteristics differ from matched CSE domain

        Returns:
            True if visually different (NOT phishing), False if similar (possible phishing)
        """
        # Check 1: Favicon mismatch
        if favicon_md5:
            cse_favicons = self.favicon_db[self.favicon_db['registrable'] == matched_cse_domain]
            if len(cse_favicons) > 0:
                cse_favicon_md5 = cse_favicons.iloc[0]['favicon_md5']
                if favicon_md5 != cse_favicon_md5:
                    return True  # Different favicon = different brand

        # Check 2: Screenshot phash mismatch
        if screenshot_path and Path(screenshot_path).exists():
            try:
                img = Image.open(screenshot_path)
                phash = str(imagehash.phash(img))

                cse_phashes = self.phash_db[self.phash_db['registrable'] == matched_cse_domain]
                if len(cse_phashes) > 0:
                    cse_phash = cse_phashes.iloc[0]['screenshot_phash']

                    # Calculate hamming distance
                    hash1 = imagehash.hex_to_hash(phash)
                    hash2 = imagehash.hex_to_hash(cse_phash)
                    distance = hash1 - hash2

                    # If distance > 15, visually very different
                    if distance > 15:
                        return True  # Different appearance = different website
            except Exception as e:
                print(f"⚠ Screenshot comparison failed: {e}")

        # Check 3: CLIP embedding dissimilarity
        if screenshot_path and Path(screenshot_path).exists() and self.clip_model:
            try:
                # Get CLIP embedding for test image
                test_img = Image.open(screenshot_path).convert('RGB')
                test_img_tensor = self.clip_preprocess(test_img).unsqueeze(0)

                with torch.no_grad():
                    test_embedding = self.clip_model.encode_image(test_img_tensor).cpu().numpy()[0]

                # Find CSE domain embedding
                for i, meta in enumerate(self.cse_metadata):
                    if meta['registrable'] == matched_cse_domain:
                        cse_embedding = self.cse_embeddings[i]

                        # Calculate cosine similarity
                        similarity = np.dot(test_embedding, cse_embedding) / (
                            np.linalg.norm(test_embedding) * np.linalg.norm(cse_embedding)
                        )

                        # If similarity < 0.70, visually very different
                        if similarity < 0.70:
                            return True  # Different visual content
                        break
            except Exception as e:
                print(f"⚠ CLIP comparison failed: {e}")

        # Default: cannot confirm dissimilarity
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

    def check_redirected_brand_impersonation(self, domain, redirect_count, screenshot_path):
        """
        Detect brand impersonation when domain redirects to parking/different site

        This handles the case where a phishing domain redirects to a parking page:
        - Original domain name looks like a CSE brand (e.g., sbi-secure-login.com)
        - But redirects to parking (e.g., sedo.com)
        - Visual features won't match brand (screenshot shows parking page)
        - But domain name itself indicates impersonation attempt

        Args:
            domain: Original domain name
            redirect_count: Number of redirects that occurred
            screenshot_path: Path to screenshot (of final redirected page)

        Returns:
            Detection result dict if brand impersonation detected via redirect, None otherwise
        """
        # Only check if domain actually redirected
        if not redirect_count or redirect_count == 0:
            return None

        # Check if domain name is similar to any CSE brand
        similar_cse = self.find_similar_cse_domains(domain, similarity_threshold=0.6)

        if not similar_cse:
            return None  # No CSE brand similarity

        most_similar_cse, similarity_score = similar_cse[0]

        # Check if domain is already in CSE whitelist (legitimate subdomain/variant)
        if domain in self.cse_domains or domain in self.legitimate_domains:
            return None

        # Check if it's a related domain (same organization)
        if self.domains_are_related(domain, most_similar_cse):
            return None  # Likely legitimate variant

        # Domain name looks like CSE brand AND redirected
        # This is suspicious - likely parking or phishing attempt

        # Additional check: if screenshot available, see if it shows parking indicators
        is_parking_page = False
        if screenshot_path and Path(screenshot_path).exists():
            # Could add OCR-based parking detection here
            # For now, rely on redirect + brand similarity
            pass

        return {
            'signal': 'redirected_brand_impersonation',
            'verdict': 'SUSPICIOUS',
            'confidence': 0.82,
            'reason': f"Domain name similar to {most_similar_cse} ({similarity_score:.0%}) but redirects ({redirect_count} hops) - possible brand impersonation or parked domain",
            'matched_cse': most_similar_cse,
            'similarity': similarity_score,
            'redirect_count': redirect_count
        }

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

            # Final NaN check - ensure no NaN/inf values remain
            if isinstance(val, float) and (np.isnan(val) or np.isinf(val)):
                val = 0

            feature_dict[fname] = val

        feature_vector = [feature_dict[f] for f in self.feature_names]

        # Additional validation: replace any remaining NaN/inf in the vector
        feature_vector = [0 if isinstance(v, float) and (np.isnan(v) or np.isinf(v)) else v for v in feature_vector]

        # Extra safety: Check for NaN after all processing
        if any(isinstance(v, float) and (np.isnan(v) or np.isinf(v)) for v in feature_vector):
            print(f"⚠ Warning: NaN/inf values still present after cleaning, replacing with 0")
            feature_vector = [0 if isinstance(v, float) and (np.isnan(v) or np.isinf(v)) else v for v in feature_vector]

        # Ensure all values are numeric (convert any remaining strings)
        try:
            feature_vector = [float(v) if not isinstance(v, str) else 0 for v in feature_vector]
        except (ValueError, TypeError) as e:
            print(f"⚠ Warning: Cannot convert feature vector to numeric: {e}")
            return None  # Cannot process this domain

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

        # STAGE 1.5: Check legitimate non-CSE domains (similar names, different orgs)
        if domain in self.legitimate_domains:
            org = 'Verified organization'
            if len(self.legitimate_domains_df) > 0:
                matching = self.legitimate_domains_df[self.legitimate_domains_df['domain'] == domain]
                if len(matching) > 0:
                    org = matching.iloc[0]['organization']

            return {
                'domain': domain,
                'verdict': 'BENIGN',
                'confidence': 0.92,
                'signals': [{
                    'signal': 'legitimate_domain_database',
                    'verdict': 'BENIGN',
                    'confidence': 0.92,
                    'reason': f'{domain} is verified legitimate domain ({org})'
                }],
                'signal_count': 0
            }

        # STAGE 1.6: Check similar-name domains with visual dissimilarity
        # If domain name is similar to CSE domain BUT visually different → BENIGN
        similar_cse = self.find_similar_cse_domains(domain, similarity_threshold=0.6)

        if similar_cse:
            # Get most similar CSE domain
            most_similar_cse, similarity_score = similar_cse[0]

            # Check if visually different from the similar CSE domain
            is_visually_different = self.check_visual_dissimilarity(
                screenshot_path,
                favicon_md5,
                most_similar_cse
            )

            if is_visually_different:
                return {
                    'domain': domain,
                    'verdict': 'BENIGN',
                    'confidence': 0.88,
                    'signals': [{
                        'signal': 'similar_name_different_visuals',
                        'verdict': 'BENIGN',
                        'confidence': 0.88,
                        'reason': f'{domain} has similar name to {most_similar_cse} ({similarity_score:.0%} similar) but visually different content - likely legitimate alternative organization'
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

        # Check for redirected brand impersonation FIRST
        # This catches domains that look like brands but redirect to parking/other sites
        if features:
            redirect_count = features.get('redirect_count', 0)
            if redirect_count and redirect_count > 0:
                redirect_brand_result = self.check_redirected_brand_impersonation(
                    domain, redirect_count, screenshot_path
                )
                if redirect_brand_result:
                    signals.append(redirect_brand_result)
                    matched_cse_domain = redirect_brand_result.get('matched_cse')

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
