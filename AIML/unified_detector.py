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

# Import text feature extraction for keyword detection
try:
    from data_prep.extract_text_features import TextFeatureExtractor
    TEXT_EXTRACTOR_AVAILABLE = True
except ImportError:
    TEXT_EXTRACTOR_AVAILABLE = False
    print("Warning: TextFeatureExtractor not available - keyword detection will be limited")

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

    # COMPREHENSIVE FEATURE MAPPING: Model feature names → Actual data field names
    # This mapping handles the mismatch between training data features and runtime data schema
    FEATURE_MAPPING = {
        # === DIRECT MAPPINGS (field names match exactly) ===
        'url_length': 'url_length',
        'url_entropy': 'url_entropy',
        'num_subdomains': 'num_subdomains',
        'is_idn': 'is_idn',
        'has_repeated_digits': 'has_repeated_digits',
        'mixed_script': 'mixed_script',
        'domain_age_days': 'domain_age_days',
        'is_newly_registered': 'is_newly_registered',
        'is_very_new': 'is_very_new',
        'days_until_expiry': 'days_until_expiry',
        'is_self_signed': 'is_self_signed',
        'has_credential_form': 'has_credential_form',
        'form_count': 'form_count',
        'password_fields': 'password_fields',
        'email_fields': 'email_fields',
        'has_suspicious_forms': 'has_suspicious_forms',
        'suspicious_form_count': 'suspicious_form_count',
        'html_size': 'html_size',
        'external_links': 'external_links',
        'iframe_count': 'iframe_count',
        'js_obfuscated': 'js_obfuscated',
        'js_keylogger': 'js_keylogger',
        'js_form_manipulation': 'js_form_manipulation',
        'js_eval_usage': 'js_eval_usage',
        'js_risk_score': 'js_risk_score',
        'redirect_count': 'redirect_count',
        'had_redirects': 'had_redirects',  # THIS EXISTS! Was causing error
        'a_count': 'a_count',
        'mx_count': 'mx_count',
        'ns_count': 'ns_count',

        # === RENAMED FEATURES (model feature → actual field name) ===
        'doc_has_verdict': 'has_verdict',  # Renamed: doc_has_verdict → has_verdict
        'doc_risk_score': 'risk_score',    # Renamed: doc_risk_score → risk_score
        'doc_form_count': 'form_count',    # Same as form_count (duplicate)
        'ocr_length': 'ocr_text_length',   # Renamed: ocr_length → ocr_text_length

        # === SPECIAL DERIVATIONS (need custom extraction) ===
        'cert_age_days': 'domain_age_days',  # Fallback: use domain_age_days
        'doc_length': 'html_size',           # Fallback: use html_size (or derive from document_text)

        # === KEYWORD FEATURES (require text analysis) ===
        'doc_has_login_keywords': None,      # Extract from document_text
        'doc_has_verify_keywords': None,     # Extract from document_text
        'doc_has_password_keywords': None,   # Extract from document_text
        'doc_has_credential_keywords': None, # Extract from document_text
        'ocr_has_login_keywords': None,      # Extract from ocr_text_excerpt
        'ocr_has_verify_keywords': None,     # Extract from ocr_text_excerpt
    }

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

        # Text feature extractor for keyword detection
        self.text_extractor = None
        if TEXT_EXTRACTOR_AVAILABLE:
            self.text_extractor = TextFeatureExtractor()

        # Feature names for anomaly model
        self.feature_names = None

        # Verdict weights (configurable)
        # PHASE 2: Reweighted for CSE-specificity to reduce false positives
        # Prioritize detectors that are CSE-focused (visual, domain)
        # Reduce weight of generic detectors (content, anomaly, autoencoder)
        self.weights = {
            'anomaly': 0.05,     # REDUCED from 0.10 - flags all non-CSE sites as anomalies
            'visual': 0.40,      # INCREASED from 0.20 - most CSE-specific detector (CLIP similarity)
            'content': 0.15,     # REDUCED from 0.25 - not CSE-specific (flags generic phishing)
            'domain': 0.35,      # UNCHANGED - partially CSE-specific (typosquat, favicon, homograph)
            'autoencoder': 0.05  # REDUCED from 0.10 - flags all non-CSE sites as anomalies
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
            missing_features = []

            for feature_name in self.feature_names:
                value = metadata.get(feature_name)

                # Convert boolean to int
                if isinstance(value, bool):
                    features[feature_name] = int(value)
                # Keep numeric values
                elif isinstance(value, (int, float)):
                    features[feature_name] = value
                # Handle missing features with smart defaults
                else:
                    # Try to derive missing features from available data
                    derived_value = self._derive_missing_feature(feature_name, metadata)
                    if derived_value is not None:
                        features[feature_name] = derived_value
                    else:
                        features[feature_name] = 0  # Default to 0
                        missing_features.append(feature_name)

            # Log warnings for missing features (but don't fail)
            if missing_features:
                print(f"Warning: {len(missing_features)} features missing, using defaults: {missing_features[:5]}...")

            # Create DataFrame
            df = pd.DataFrame([features])

            # CRITICAL FIX: Reindex to ensure EXACT column order matching model training
            # This prevents "feature names unseen at fit time" errors
            df = df[self.feature_names]

            return df

        except Exception as e:
            print(f"Error preparing features: {e}")
            return None

    def _derive_missing_feature(self, feature_name: str, metadata: Dict) -> Optional[float]:
        """
        Try to derive missing features from available metadata using FEATURE_MAPPING

        Args:
            feature_name: Name of the missing feature (from model training)
            metadata: Available metadata (from dump_all.jsonl)

        Returns:
            Derived value or None if cannot derive
        """
        # PRIORITY 1: Use FEATURE_MAPPING dictionary
        mapped_field_name = self.FEATURE_MAPPING.get(feature_name)

        if mapped_field_name is not None:
            # Direct field mapping
            value = metadata.get(mapped_field_name)

            # Convert boolean to int
            if isinstance(value, bool):
                return int(value)
            # Return numeric values
            elif isinstance(value, (int, float)):
                return float(value)
            # If value is None or missing, continue to other strategies

        # PRIORITY 2: Keyword extraction from HTML text
        if feature_name in ['doc_has_login_keywords', 'doc_has_verify_keywords',
                           'doc_has_password_keywords', 'doc_has_credential_keywords']:
            return self._extract_keyword_feature(feature_name, metadata, source='html')

        # PRIORITY 3: Keyword extraction from OCR text
        if feature_name in ['ocr_has_login_keywords', 'ocr_has_verify_keywords']:
            return self._extract_keyword_feature(feature_name, metadata, source='ocr')

        # PRIORITY 4: Special case - doc_length (try to extract clean text)
        if feature_name == 'doc_length':
            # Try to get actual text length from document_text, fallback to html_size
            document_text = metadata.get('document_text', '')
            if document_text:
                # If document_text is HTML, extract clean text length
                if '<' in document_text and '>' in document_text:
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(document_text, 'html.parser')
                        clean_text = soup.get_text()
                        return float(len(clean_text.strip()))
                    except:
                        return float(len(document_text))
                else:
                    return float(len(document_text))
            else:
                # Fallback to html_size
                return float(metadata.get('html_size', 0))

        return None

    def _extract_keyword_feature(self, feature_name: str, metadata: Dict, source: str = 'html') -> int:
        """
        Extract keyword-based features from HTML or OCR text

        Args:
            feature_name: Feature to extract (e.g., 'doc_has_login_keywords')
            metadata: Domain metadata
            source: 'html' or 'ocr'

        Returns:
            1 if keywords found, 0 otherwise
        """
        if not self.text_extractor:
            return 0

        # Get text source
        if source == 'html':
            text = metadata.get('document_text', '')
        elif source == 'ocr':
            text = metadata.get('ocr_text_excerpt', '') or metadata.get('ocr_text', '')
        else:
            return 0

        if not text:
            return 0

        # Determine which keywords to search for
        if 'login' in feature_name:
            keywords = self.text_extractor.login_keywords
        elif 'verify' in feature_name:
            keywords = self.text_extractor.verify_keywords
        elif 'password' in feature_name:
            keywords = self.text_extractor.password_keywords
        elif 'credential' in feature_name:
            keywords = self.text_extractor.credential_keywords
        else:
            return 0

        # Check for keywords (case-insensitive)
        has_keywords = self.text_extractor.has_keywords(text, keywords, threshold=1)
        return int(has_keywords)

    def _calc_avg_subdomain_length(self, domain: str) -> float:
        """Calculate average subdomain length"""
        if not domain:
            return 0.0
        parts = domain.split('.')
        if len(parts) <= 2:  # No subdomains
            return 0.0
        subdomains = parts[:-2]  # Exclude domain and TLD
        return sum(len(s) for s in subdomains) / len(subdomains) if subdomains else 0.0

    def _calc_max_subdomain_length(self, domain: str) -> int:
        """Calculate maximum subdomain length"""
        if not domain:
            return 0
        parts = domain.split('.')
        if len(parts) <= 2:  # No subdomains
            return 0
        subdomains = parts[:-2]  # Exclude domain and TLD
        return max(len(s) for s in subdomains) if subdomains else 0

    def _calc_subdomain_digit_ratio(self, domain: str) -> float:
        """Calculate ratio of digits in subdomains"""
        if not domain:
            return 0.0
        parts = domain.split('.')
        if len(parts) <= 2:  # No subdomains
            return 0.0
        subdomains = '.'.join(parts[:-2])  # Join all subdomains
        if not subdomains:
            return 0.0
        digit_count = sum(c.isdigit() for c in subdomains)
        return digit_count / len(subdomains) if subdomains else 0.0

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
                Path('/out/screenshots'),  # Docker container mount point
                Path('/home/turtleneck/Desktop/PS02/Pipeline/out/screenshots'),  # Local testing fallback
            ]

            for screenshot_dir in screenshot_dirs:
                if not screenshot_dir.exists():
                    continue
                candidate = screenshot_dir / filename
                if candidate.exists():
                    return str(candidate)

        # Fall back to pattern matching
        screenshot_dirs = [
            Path('/out/screenshots'),  # Docker container mount point
            Path('/home/turtleneck/Desktop/PS02/Pipeline/out/screenshots'),  # Local testing fallback
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

    def aggregate_verdicts(self, results: Dict, metadata: Dict = None) -> Dict:
        """
        Aggregate verdicts from all detectors

        Weighted voting system:
        - PHISHING/MALICIOUS → high risk
        - SUSPICIOUS/ANOMALY → medium risk
        - BENIGN/NORMAL → low risk

        Args:
            results: Dictionary with results from each detector
            metadata: Optional domain metadata for TLD-aware weighting

        Returns:
            Final aggregated verdict
        """
        # Map verdicts to risk scores
        verdict_risk_map = {
            # Malicious/High Risk
            'PHISHING': 1.0,
            'MALICIOUS': 1.0,
            'GAMBLING': 0.9,  # Treat as high risk per requirements

            # Suspicious/Medium Risk
            'SUSPICIOUS': 0.6,
            'ANOMALY': 0.7,
            'SIMILAR': 0.8,  # Visual similarity to CSE but not whitelisted
            'SUSPICIOUS_GAMBLING': 0.65,

            # Benign/Safe
            'BENIGN': 0.0,
            'NORMAL': 0.0,
            'DISSIMILAR': 0.0,
            'NOT_GAMBLING': 0.0,
            'NOT_PARKED': 0.0,

            # Status Categories (not risk-scored in normal flow)
            'INACTIVE': 0.0,
            'PARKED': 0.0,
            'N/A': 0.0,
            'UNREGISTERED': 0.0,
            'POSSIBLE_PARKED': 0.1,

            # Unknown/Error
            'UNKNOWN': 0.3,  # Neutral
            'ERROR': 0.0     # Ignore errors
        }

        # Check if domain has trusted TLD (for weight adjustment)
        is_trusted_tld = False
        if metadata:
            registrable = metadata.get('registrable', '')
            is_trusted_tld = self._has_trusted_tld(registrable)

        # Adjust detector weights based on TLD trust
        adjusted_weights = self.weights.copy()
        if is_trusted_tld:
            # For trusted TLDs (government, edu, etc.):
            # - Boost domain detector weight (more important)
            # - Reduce visual detector weight (less reliable)
            # - Keep content and anomaly weights neutral
            adjusted_weights['domain'] = self.weights['domain'] * 2.0  # Double domain weight
            adjusted_weights['visual'] = self.weights['visual'] * 0.5  # Halve visual weight
            adjusted_weights['content'] = self.weights['content'] * 1.2  # Slight boost to content
            adjusted_weights['anomaly'] = self.weights['anomaly'] * 0.8  # Slight reduction

        # Calculate weighted risk score
        total_risk = 0.0
        total_weight = 0.0

        for detector_name, weight in adjusted_weights.items():
            result = results.get(detector_name, {})
            verdict = result.get('verdict', 'UNKNOWN')
            confidence = result.get('confidence', 0.0)

            # Skip detectors that returned ERROR or UNKNOWN with 0 confidence
            if verdict in ['ERROR', 'UNKNOWN'] and confidence == 0.0:
                continue  # Exclude from ensemble

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

        # ============ CSE-TARGETING GATE (CRITICAL FOR FALSE POSITIVE REDUCTION) ============
        # Check if ANY detector found CSE impersonation/targeting signal
        # Without CSE-targeting, maximum verdict is SUSPICIOUS (never PHISHING)
        has_cse_signal, signal_type, target_cse = self._has_cse_targeting_signal(results)

        # Determine final verdict
        if final_risk_score >= 0.7:
            if has_cse_signal:
                # CSE impersonation detected → PHISHING allowed
                final_verdict = 'PHISHING'
                final_confidence = 0.7 + final_risk_score * 0.25
            else:
                # High risk but NO CSE targeting → Cap at SUSPICIOUS
                final_verdict = 'SUSPICIOUS'
                final_confidence = 0.50 + final_risk_score * 0.20  # Lower confidence
        elif final_risk_score >= 0.45:
            final_verdict = 'SUSPICIOUS'
            final_confidence = 0.5 + final_risk_score * 0.3
        else:
            final_verdict = 'BENIGN'
            # Boost confidence for trusted TLDs
            base_confidence = max(0.4, 1.0 - final_risk_score)
            final_confidence = min(0.95, base_confidence * 1.15) if is_trusted_tld else base_confidence

        # Collect reasons
        reasons = []

        # Add CSE-targeting reason if detected
        if has_cse_signal:
            signal_desc = {
                'visual_impersonation': 'Visual impersonation',
                'typosquatting': 'Typosquatting',
                'idn_homograph': 'IDN homograph attack',
                'favicon_impersonation': 'Favicon impersonation'
            }.get(signal_type, signal_type)
            reasons.append(f"CSE Targeting: {signal_desc} of {target_cse}")
        elif final_risk_score >= 0.7:
            # High risk but no CSE targeting
            reasons.append("High risk indicators but no CSE impersonation detected")

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

    def _has_trusted_tld(self, registrable: str) -> bool:
        """
        Check if domain has a trusted TLD (government, education, etc.)

        Args:
            registrable: Registrable domain

        Returns:
            True if has trusted TLD
        """
        if not registrable:
            return False

        trusted_tlds = {
            'gov', 'gov.in', 'nic.in', 'ac.in', 'edu.in', 'mil',
            'edu', 'mil.in', 'res.in'
        }

        registrable_lower = registrable.lower()
        for tld in trusted_tlds:
            if registrable_lower.endswith(f'.{tld}') or registrable_lower == tld:
                return True

        return False

    def _has_cse_targeting_signal(self, results: Dict) -> tuple[bool, str, str]:
        """
        Check if ANY detector found CSE impersonation/targeting signals.
        This is the gate that prevents non-CSE phishing from being marked as PHISHING.

        CSE-targeting signals include:
        1. Visual similarity to CSE ≥ 0.92 (CLIP detector)
        2. Typosquatting CSE domain (≥85% similarity)
        3. IDN homograph targeting CSE
        4. Favicon matching CSE entity

        Args:
            results: Dictionary with results from each detector

        Returns:
            Tuple of (has_signal: bool, signal_type: str, target_cse: str)
        """
        # Check 1: Visual detector - CLIP similarity to CSE
        visual_result = results.get('visual', {})
        if visual_result.get('verdict') == 'PHISHING':
            details = visual_result.get('details', {})
            clip_similarity = details.get('clip_similarity', 0)
            matched_cse = details.get('matched_cse_domain', '')

            if clip_similarity >= 0.92 and matched_cse:
                return (True, 'visual_impersonation', matched_cse)

        # Check 2: Domain reputation - Typosquatting/Homograph/Favicon
        domain_result = results.get('domain', {})
        domain_details = domain_result.get('details', {})

        # Check 2a: Typosquatting
        if domain_details.get('is_typosquatting'):
            typosquat_target = domain_details.get('typosquat_target', '')
            if typosquat_target:
                return (True, 'typosquatting', typosquat_target)

        # Check 2b: IDN Homograph
        if domain_details.get('is_homograph_attack'):
            homograph_target = domain_details.get('homograph_target', '')
            if homograph_target:
                return (True, 'idn_homograph', homograph_target)

        # Check 2c: Favicon impersonation
        if domain_details.get('is_favicon_impersonation'):
            favicon_target = domain_details.get('favicon_target', '')
            if favicon_target:
                return (True, 'favicon_impersonation', favicon_target)

        # No CSE-targeting signal detected
        return (False, '', '')

    def is_insufficient_data(self, metadata: Dict) -> bool:
        """
        Check if domain has insufficient data for analysis

        Args:
            metadata: Domain metadata

        Returns:
            True if insufficient data
        """
        # Check if we have HTML content loaded
        has_html = bool(metadata.get('document_text'))
        doc_length = metadata.get('doc_length', 0)

        # Check if HTML file exists (even if not loaded yet)
        html_path = metadata.get('html_path', '')
        html_size = metadata.get('html_size', 0)

        # Check screenshot
        screenshot_path = metadata.get('screenshot_path', '')
        has_screenshot = bool(screenshot_path) and (Path(screenshot_path).exists() if screenshot_path else False)

        # Check OCR
        has_ocr = bool(metadata.get('ocr_text')) or bool(metadata.get('ocr_text_excerpt'))

        # Need at least one data source
        # Either: (1) HTML content loaded, (2) HTML file exists, (3) screenshot exists, (4) OCR available
        has_any_data = has_html or (html_path and html_size > 0) or has_screenshot or has_ocr

        if not has_any_data:
            return True

        # HTML too short to analyze meaningfully (only if it's the only source)
        if has_html and doc_length < 50 and not has_screenshot and not has_ocr:
            return True

        return False

    def check_domain_status(self, metadata: Dict) -> Optional[Dict]:
        """
        Check domain status before running ML detectors.
        Returns immediate verdict for INACTIVE/PARKED/GAMBLING/N/A cases.

        Args:
            metadata: Domain metadata

        Returns:
            Status verdict dict or None if should continue to ML detectors
        """
        registrable = metadata.get('registrable', 'unknown')

        # 1. Check INACTIVE status (highest priority - site is down)
        if metadata.get('is_inactive'):
            inactive_reason = metadata.get('inactive_reason', 'unknown')
            inactive_status = metadata.get('inactive_status', 'inactive')
            return {
                'verdict': 'INACTIVE',
                'confidence': 0.95,
                'risk_score': 0.0,
                'reasons': [f'Domain is inactive: {inactive_reason}'],
                'status_check': 'inactive',
                'inactive_reason': inactive_reason,
                'inactive_status': inactive_status,
                'detector_results': {}
            }

        # 2. Check N/A (insufficient data - cannot analyze)
        if self.is_insufficient_data(metadata):
            return {
                'verdict': 'N/A',
                'confidence': 0.90,
                'risk_score': 0.0,
                'reasons': ['Insufficient data for analysis (no HTML, screenshot, or OCR)'],
                'status_check': 'insufficient_data',
                'detector_results': {}
            }

        # 3. Check PARKED domain patterns
        parked_result = self.domain_analyzer.detect_parked_domain(metadata)
        if parked_result['verdict'] == 'PARKED':
            return {
                'verdict': 'PARKED',
                'confidence': parked_result['confidence'],
                'risk_score': 0.0,
                'reasons': [parked_result['reason']],
                'status_check': 'parked',
                'parking_details': parked_result,
                'detector_results': {}
            }

        # 4. Check GAMBLING patterns (treat as phishing per requirements)
        gambling_result = self.content_detector.detect_gambling(metadata)
        if gambling_result['verdict'] == 'GAMBLING':
            return {
                'verdict': 'GAMBLING',
                'confidence': gambling_result['confidence'],
                'risk_score': 0.9,  # Treat as high risk
                'reasons': [gambling_result['reason']],
                'status_check': 'gambling',
                'gambling_details': gambling_result,
                'detector_results': {}
            }

        # 5. Check REDIRECT patterns (suspicious redirect chains)
        redirect_result = self.domain_analyzer.analyze_redirect_risk(metadata)
        if redirect_result['verdict'] == 'SUSPICIOUS_REDIRECTS':
            return {
                'verdict': 'SUSPICIOUS',
                'confidence': 0.75,
                'risk_score': redirect_result['risk_score'],
                'reasons': redirect_result['risk_factors'],
                'status_check': 'suspicious_redirects',
                'redirect_details': redirect_result,
                'detector_results': {}
            }

        # Continue to ML detectors
        return None

    def detect(self, metadata: Dict) -> Dict:
        """
        Run complete detection pipeline on a domain

        Args:
            metadata: Domain metadata with all features

        Returns:
            Complete detection result
        """
        registrable = metadata.get('registrable', 'unknown')

        # PRIORITY 1: Check if domain is in CSE baseline (known good)
        if self.domain_analyzer and hasattr(self.domain_analyzer, 'cse_whitelist'):
            if registrable in self.domain_analyzer.cse_whitelist:
                return {
                    'verdict': 'BENIGN',
                    'confidence': 0.98,
                    'risk_score': 0.0,
                    'reasons': ['Domain in CSE baseline whitelist'],
                    'domain': registrable,
                    'registrable': registrable,
                    'url': metadata.get('document', ''),
                    'detector_results': {}
                }

        # PRIORITY 2: Check domain status (early exit for INACTIVE/PARKED/GAMBLING/N/A)
        status_result = self.check_domain_status(metadata)
        if status_result:
            status_result['domain'] = registrable  # For aiml_service.py compatibility
            status_result['registrable'] = registrable
            status_result['url'] = metadata.get('document', '')
            return status_result

        # Continue with ML detection for active domains with sufficient data
        # Run all detectors
        results = {
            'anomaly': self.run_anomaly_detection(metadata),
            'visual': self.run_visual_detection(metadata),
            'content': self.run_content_detection(metadata),
            'domain': self.run_domain_analysis(metadata),
            'autoencoder': self.run_autoencoder_detection(metadata)
        }

        # Aggregate verdicts (pass metadata for TLD-aware weighting)
        final_result = self.aggregate_verdicts(results, metadata)

        # Add domain info (use both 'domain' and 'registrable' for compatibility)
        registrable = metadata.get('registrable', 'unknown')
        final_result['domain'] = registrable  # For aiml_service.py compatibility
        final_result['registrable'] = registrable  # Keep for backward compatibility
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
