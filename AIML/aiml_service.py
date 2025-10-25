"""
AIML Phishing Detection Service

Integrates with the phishing detection pipeline:
1. Connects to ChromaDB to fetch enriched features
2. Runs multi-modal phishing detection (tabular + vision)
3. Saves verdicts as JSON files
4. Optionally publishes to Kafka for downstream consumption
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import chromadb
from chromadb.config import Settings, DEFAULT_TENANT, DEFAULT_DATABASE
import pandas as pd
from unified_detector import UnifiedPhishingDetector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/out/aiml_service.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AIMlService:
    """AIML Phishing Detection Service"""

    def __init__(self):
        """Initialize service with ChromaDB and ML models"""
        # Environment variables
        self.chroma_host = os.getenv('CHROMA_HOST', 'chroma')
        self.chroma_port = int(os.getenv('CHROMA_PORT', '8000'))
        self.chroma_collection = os.getenv('CHROMA_COLLECTION', 'domains')
        self.output_dir = Path(os.getenv('OUTPUT_DIR', '/out'))
        self.check_interval = int(os.getenv('CHECK_INTERVAL_SECONDS', '30'))
        self.batch_size = int(os.getenv('BATCH_SIZE', '10'))

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize ChromaDB client
        logger.info(f"Connecting to ChromaDB at {self.chroma_host}:{self.chroma_port}")
        self.chroma_client = chromadb.HttpClient(
            host=self.chroma_host,
            port=self.chroma_port,
            settings=Settings(anonymized_telemetry=False),
            tenant=DEFAULT_TENANT,
            database=DEFAULT_DATABASE
        )

        # Get or create collection
        try:
            self.collection = self.chroma_client.get_collection(name=self.chroma_collection)
            logger.info(f"Connected to ChromaDB collection '{self.chroma_collection}'")
        except Exception as e:
            logger.error(f"Failed to connect to ChromaDB collection: {e}")
            raise

        # Initialize ML detector
        logger.info("Loading AIML phishing detector models...")
        try:
            # Build config with correct paths (inside container)
            detector_config = {
                'anomaly_model_path': 'models/anomaly/anomaly_detector.pkl',
                'feature_names_path': 'models/anomaly/feature_names.txt',
                'cse_baseline_path': 'data/training/cse_baseline_profile.json',
                'clip_index_path': 'models/vision/cse_index_updated',
                'autoencoder_path': 'models/vision/autoencoder_new/autoencoder_best.pth',
                'use_clip': True,
                'use_autoencoder': True,
                'autoencoder_threshold': 3.5
            }
            self.detector = UnifiedPhishingDetector(config=detector_config)
            self.detector.load_models()  # Load ML models
            logger.info("AIML detector models loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load AIML models: {e}")
            raise

        # Load CSE whitelist for early exit checks
        self.cse_whitelist = set()
        try:
            cse_baseline_file = Path('data/training/cse_baseline_profile.json')
            if cse_baseline_file.exists():
                with open(cse_baseline_file, 'r') as f:
                    baseline = json.load(f)
                    # Try 'domains' first (main list), then 'cse_whitelist'
                    whitelist_domains = baseline.get('domains', baseline.get('cse_whitelist', []))
                    self.cse_whitelist = set(whitelist_domains)
                    logger.info(f"Loaded CSE whitelist: {len(self.cse_whitelist)} domains")
        except Exception as e:
            logger.warning(f"Could not load CSE whitelist: {e}")

        # Track processed domains
        self.processed_domains = set()
        self.processed_log = self.output_dir / "processed_domains.txt"
        self._load_processed_domains()

    def _load_processed_domains(self):
        """Load previously processed domains from log"""
        if self.processed_log.exists():
            with open(self.processed_log) as f:
                self.processed_domains = set(line.strip() for line in f)
            logger.info(f"Loaded {len(self.processed_domains)} previously processed domains")

    def _mark_processed(self, domain: str):
        """Mark domain as processed"""
        if domain not in self.processed_domains:
            self.processed_domains.add(domain)
            with open(self.processed_log, 'a') as f:
                f.write(f"{domain}\n")

    def check_inactive_status(self, domain: str) -> Optional[Dict]:
        """
        Check if domain is inactive/unregistered in ChromaDB

        Args:
            domain: Domain name to check

        Returns:
            Dict with status info if inactive/unregistered, None otherwise
        """
        try:
            # Query ChromaDB by registrable domain
            results = self.collection.get(
                where={"registrable": domain},
                include=['metadatas']
            )

            if not results or not results.get('metadatas'):
                return None

            # Check first match
            metadata = results['metadatas'][0]

            # Check if domain is marked as inactive
            is_inactive = metadata.get('is_inactive', False)
            inactive_status = metadata.get('inactive_status')
            inactive_reason = metadata.get('inactive_reason', 'Unknown')
            record_type = metadata.get('record_type')

            if is_inactive or record_type == 'inactive':
                return {
                    'status': inactive_status,  # "inactive" or "unregistered"
                    'reason': inactive_reason,
                    'is_inactive': True,
                    'record_type': record_type
                }

            return None

        except Exception as e:
            logger.warning(f"Failed to check inactive status for {domain}: {e}")
            return None

    def _create_inactive_verdict(self, domain: str, inactive_info: Dict, error_context: str = None) -> Dict:
        """
        Create a verdict for inactive/unregistered domains

        Args:
            domain: Domain name
            inactive_info: Dict from check_inactive_status()
            error_context: Optional error message that triggered this check

        Returns:
            Verdict dict
        """
        status = inactive_info['status']  # "inactive" or "unregistered"

        if status == 'unregistered':
            verdict = 'UNREGISTERED'
            reason = f"Domain not registered in DNS. {inactive_info['reason']}"
            confidence = 0.95
        elif status == 'inactive':
            verdict = 'INACTIVE'
            reason = f"Domain registered but HTTP probe failed. {inactive_info['reason']}"
            confidence = 0.90
        else:
            verdict = 'INACTIVE'
            reason = f"Domain inactive: {inactive_info['reason']}"
            confidence = 0.85

        result = {
            'domain': domain,
            'verdict': verdict,
            'confidence': confidence,
            'reason': reason,
            'inactive_status': status,
            'timestamp': datetime.now().isoformat()
        }

        if error_context:
            result['error_context'] = error_context

        logger.info(f"Domain {domain} identified as {verdict}: {reason}")
        return result

    def fetch_unprocessed_domains(self) -> List[Dict]:
        """Fetch domains from ChromaDB that haven't been processed by AIML"""
        try:
            # Query ChromaDB for ALL domains (no limit)
            results = self.collection.get(
                include=['metadatas', 'documents']
            )

            if not results or not results.get('metadatas'):
                return []

            total_domains = len(results['metadatas'])
            logger.info(f"Fetched {total_domains} total domains from ChromaDB")

            # Filter unprocessed domains
            unprocessed = []
            for i, metadata in enumerate(results['metadatas']):
                domain = metadata.get('registrable') or metadata.get('domain')
                if not domain or domain in self.processed_domains:
                    continue

                # Get domain metadata
                record_type = metadata.get('record_type', '')
                enrichment_level = metadata.get('enrichment_level', 0)
                has_features = metadata.get('has_features', False)

                # Include inactive/unregistered domains for verdict generation
                # They won't go through full model analysis but will get proper status verdicts
                if record_type == 'inactive':
                    unprocessed.append({
                        'domain': domain,
                        'metadata': metadata,
                        'document': results['documents'][i] if results.get('documents') else ''
                    })
                    continue

                # Process if domain has features OR enrichment level >= 1
                # This includes: verdict_only, features_only, fully_enriched, with_features
                if has_features or enrichment_level >= 1:
                    unprocessed.append({
                        'domain': domain,
                        'metadata': metadata,
                        'document': results['documents'][i] if results.get('documents') else ''
                    })
                else:
                    logger.debug(f"Skipping {domain}: no features (record_type={record_type}, level={enrichment_level})")

            logger.info(f"Found {len(unprocessed)} unprocessed domains with features (already processed: {len(self.processed_domains)})")
            return unprocessed

        except Exception as e:
            logger.error(f"Error fetching domains from ChromaDB: {e}")
            return []

    def load_html_content(self, metadata: Dict) -> str:
        """
        Load HTML content from disk if html_path exists

        Args:
            metadata: Domain metadata with html_path field

        Returns:
            HTML content string, or empty string if not available
        """
        html_path = metadata.get('html_path', '')
        if not html_path:
            return ''

        try:
            # Try multiple path variations for better compatibility
            path_candidates = []

            # Original path
            path_candidates.append(Path(html_path))

            # Workspace → container mapping
            if html_path.startswith('/workspace/out/'):
                path_candidates.append(Path(html_path.replace('/workspace/out/', '/out/')))

            # Direct /out/html/ mapping using just the filename
            html_filename = Path(html_path).name
            path_candidates.append(Path('/out/html') / html_filename)

            # Try ../out/html (relative path)
            path_candidates.append(Path('../out/html') / html_filename)

            # Try each path candidate
            for i, path in enumerate(path_candidates):
                if path.exists():
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        logger.debug(f"Loaded HTML from path candidate #{i+1}: {path} ({len(content)} bytes)")
                        return content

            # None of the paths worked
            logger.warning(f"HTML file not found in any of {len(path_candidates)} path candidates. Original: {html_path}")
            return ''

        except Exception as e:
            logger.warning(f"Failed to load HTML from {html_path}: {e}")
            return ''

    def load_ocr_text(self, metadata: Dict) -> str:
        """
        Get OCR text from metadata (already extracted by crawler)

        Args:
            metadata: Domain metadata with ocr_text_excerpt field

        Returns:
            OCR text string
        """
        # OCR text is already in metadata from crawler
        ocr_excerpt = metadata.get('ocr_text_excerpt', '')
        ocr_length = metadata.get('ocr_text_length', 0)

        # If we have OCR excerpt, use it
        if ocr_excerpt:
            return ocr_excerpt

        # Otherwise return empty
        return ''

    def calculate_feature_quality(self, metadata: Dict) -> float:
        """
        Calculate feature quality score (0-1) based on how many features are available

        Args:
            metadata: Domain metadata from ChromaDB

        Returns:
            Float between 0 and 1 indicating feature completeness
        """
        important_features = [
            'url_length', 'domain_age_days', 'a_count', 'form_count', 'html_size',
            'registrar', 'country', 'mx_count', 'ns_count', 'external_links',
            'is_self_signed', 'cert_age_days', 'keyword_count'
        ]

        available_count = 0
        for feature in important_features:
            val = metadata.get(feature)
            # Consider feature available if it exists and is not None/NaN/empty string
            if val is not None and val != '' and not (isinstance(val, float) and pd.isna(val)):
                available_count += 1

        return available_count / len(important_features)

    def run_detection(self, domain_data: Dict) -> Dict:
        """Run AIML phishing detection on a single domain"""
        domain = domain_data['domain']
        metadata = domain_data['metadata']

        logger.info(f"Running AIML detection on: {domain}")

        # Extract registrable domain (base domain without subdomains)
        registrable = metadata.get('registrable', domain)

        # Extract crawler verdict for potential fallback
        crawler_verdict = metadata.get('verdict')
        crawler_confidence = metadata.get('confidence', 0.75)

        try:
            # STEP 0: Load HTML content from disk if available
            # This is CRITICAL - without this, we can't analyze page content
            html_content = self.load_html_content(metadata)
            if html_content:
                metadata['document_text'] = html_content
                metadata['doc_length'] = len(html_content)
                logger.debug(f"Loaded HTML for {domain}: {len(html_content)} bytes")

            # Load OCR text if available
            ocr_text = self.load_ocr_text(metadata)
            if ocr_text:
                metadata['ocr_text'] = ocr_text
                metadata['ocr_length'] = len(ocr_text)

            # Fix screenshot path mapping (same issue as HTML paths)
            screenshot_path = metadata.get('screenshot_path', '')
            logger.info(f"DEBUG: screenshot_path before mapping: {screenshot_path}")
            if screenshot_path and screenshot_path.startswith('/workspace/out/'):
                # Map /workspace/out/ to /out/ for container
                fixed_path = screenshot_path.replace('/workspace/out/', '/out/')
                metadata['screenshot_path'] = fixed_path
                logger.info(f"Mapped screenshot path: {screenshot_path} -> {fixed_path}")
            else:
                logger.info(f"DEBUG: No mapping needed or path doesn't start with /workspace/out/")

            # FAST PATH 1: Check if domain is inactive/unregistered (from metadata)
            record_type = metadata.get('record_type', '')
            if record_type == 'inactive':
                inactive_info = self.check_inactive_status(domain)
                if inactive_info:
                    logger.info(f"Domain {domain} is inactive/unregistered - generating status verdict")
                    return self._create_inactive_verdict(domain, inactive_info)

            # FAST PATH 2: Check if domain is CSE whitelisted (HIGHEST PRIORITY)
            # CSE domains should ALWAYS return BENIGN regardless of other checks
            if domain in self.cse_whitelist or registrable in self.cse_whitelist:
                logger.info(f"Domain {domain} is CSE whitelisted - returning BENIGN immediately")
                return {
                    'domain': domain,
                    'verdict': 'BENIGN',
                    'confidence': 0.98,
                    'reason': 'Legitimate CSE domain (whitelisted)',
                    'source': 'cse_whitelist',
                    'registrable': registrable,
                    'timestamp': datetime.now().isoformat()
                }

            # FAST PATH 3: Check if crawler already identified as parked
            if crawler_verdict and crawler_verdict.lower() == 'parked':
                logger.info(f"Domain {domain} already identified as PARKED by crawler")
                return {
                    'domain': domain,
                    'verdict': 'PARKED',
                    'confidence': 0.95,
                    'reason': 'Identified as parked domain by crawler (DNS/HTTP/content analysis)',
                    'source': 'crawler',
                    'timestamp': datetime.now().isoformat()
                }

            # Check what data we actually have available NOW (after loading HTML)
            has_html_content = bool(metadata.get('document_text'))
            has_screenshot = bool(metadata.get('screenshot_path'))
            # Check both ocr_text (loaded) and ocr_text_excerpt (from metadata)
            has_ocr = bool(metadata.get('ocr_text') or metadata.get('ocr_text_excerpt'))
            html_size = metadata.get('html_size', 0)

            # FAST PATH 3: If truly no data available, check inactive/parked before giving up
            if not has_html_content and not has_screenshot and not has_ocr and html_size == 0:
                logger.warning(f"Domain {domain} has no HTML content, screenshot, or OCR available")

                # PRIORITY 1: Check if domain is inactive/unregistered FIRST
                inactive_info = self.check_inactive_status(domain)
                if inactive_info:
                    logger.info(f"Domain {domain} is inactive/unregistered (no data)")
                    return self._create_inactive_verdict(domain, inactive_info, "No page data available")

                # PRIORITY 2: Check if domain appears parked
                external_links = metadata.get('external_links', 0)
                mx_count = metadata.get('mx_count', 0)
                a_count = metadata.get('a_count', 0)
                cse_id = metadata.get('cse_id', '')
                registrable = metadata.get('registrable', domain)

                # Safeguard: Don't mark CSE/known benign domains as parked
                is_cse_domain = bool(cse_id and cse_id != 'BULK_IMPORT' and cse_id != 'URL from user')
                is_gov_domain = any(tld in registrable.lower() for tld in ['.gov.', '.nic.in', '.ac.in', '.edu.'])

                # Strong indicators of parked domain (no HTML but has minimal infrastructure)
                is_likely_parked = False
                parking_reason = []

                # Only check parking if NOT a CSE or government domain
                if not is_cse_domain and not is_gov_domain:
                    # No DNS infrastructure at all = likely parked/inactive
                    if mx_count == 0 and a_count <= 1 and external_links == 0:
                        is_likely_parked = True
                        parking_reason.append(f"no infrastructure (mx={mx_count}, a={a_count}, links=0)")

                if is_likely_parked:
                    logger.info(f"Domain {domain} appears parked (no data): {', '.join(parking_reason)}")
                    return {
                        'domain': domain,
                        'verdict': 'PARKED',
                        'confidence': 0.70,
                        'reason': f"Parked domain detected: {', '.join(parking_reason)}",
                        'source': 'aiml_heuristic',
                        'timestamp': datetime.now().isoformat(),
                        'original_crawler_verdict': crawler_verdict
                    }

                # PRIORITY 3: Trust crawler verdict if available
                if crawler_verdict:
                    logger.info(f"Domain {domain} has crawler verdict '{crawler_verdict}' but no AIML data - using crawler verdict")
                    return {
                        'domain': domain,
                        'verdict': crawler_verdict.upper(),
                        'confidence': metadata.get('confidence', 0.75),
                        'reason': f'Verdict from pipeline crawler (no page data available for AIML analysis)',
                        'source': 'crawler',
                        'timestamp': datetime.now().isoformat()
                    }

                # PRIORITY 4: No data and no crawler verdict = insufficient data
                logger.warning(f"Domain {domain} has no data and no crawler verdict")
                return {
                    'domain': domain,
                    'verdict': 'INSUFFICIENT_DATA',
                    'confidence': 0.0,
                    'reason': 'No HTML, screenshot, OCR, or crawler verdict available',
                    'timestamp': datetime.now().isoformat()
                }

            # CRITICAL: Check for parking indicators from metadata BEFORE trusting crawler
            # This runs even if HTML/screenshot loading failed, using OCR and metadata features
            ocr_excerpt = (metadata.get('ocr_text_excerpt', '') or metadata.get('ocr_text', '')).lower()
            external_links = metadata.get('external_links', 0)
            cse_id = metadata.get('cse_id', '')
            registrable = metadata.get('registrable', domain)

            # Safeguard: Don't mark CSE/known benign domains as parked
            is_cse_domain = bool(cse_id and cse_id != 'BULK_IMPORT' and cse_id != 'URL from user')
            is_gov_domain = any(tld in registrable.lower() for tld in ['.gov.', '.nic.in', '.ac.in', '.edu.'])

            if not is_cse_domain and not is_gov_domain:
                # Check OCR for parking keywords
                parking_keywords = [
                    'is this your domain',
                    'create your website',
                    'buy this domain',
                    'domain for sale',
                    'this domain is for sale',
                    'get started with a website',
                    'register this domain',
                    'premium domain'
                ]
                has_parking_ocr = any(kw in ocr_excerpt for kw in parking_keywords)

                # Check for bloated HTML with no real links (common parking page pattern)
                has_bloated_html_no_links = (html_size > 10000 and html_size < 500000 and external_links == 0)

                if has_parking_ocr or has_bloated_html_no_links:
                    parking_reason = []
                    if has_parking_ocr:
                        parking_reason.append("OCR contains parking keywords")
                    if has_bloated_html_no_links:
                        parking_reason.append(f"large HTML ({html_size}B) with no external links")

                    logger.info(f"Domain {domain} detected as PARKED from metadata: {', '.join(parking_reason)}")
                    return {
                        'domain': domain,
                        'verdict': 'PARKED',
                        'confidence': 0.85 if has_parking_ocr else 0.75,
                        'reason': f"Parked domain detected: {', '.join(parking_reason)}",
                        'source': 'aiml_metadata_check',
                        'timestamp': datetime.now().isoformat(),
                        'original_crawler_verdict': crawler_verdict
                    }

            # Calculate feature quality score (for logging only, not for early exit)
            feature_quality = self.calculate_feature_quality(metadata)
            logger.info(f"Domain {domain} feature quality: {feature_quality:.2%}")

            # Note: We removed the feature quality threshold check
            # Even with low feature quality, the ML detectors (visual, content, domain) can still work
            # Let unified_detector handle missing features internally with proper error handling

            # Extract features from ChromaDB metadata with proper NaN handling
            def safe_get(key, default=0):
                """Safely extract value, handling NaN/None/missing"""
                val = metadata.get(key)

                # Missing key
                if val is None:
                    return default

                # String fields - return empty string if default is 0
                string_fields = ['registrar', 'country', 'favicon_md5', 'favicon_sha256',
                               'document_text', 'doc_verdict', 'doc_submit_buttons',
                               'screenshot_phash', 'ocr_text']
                if key in string_fields:
                    return val if isinstance(val, str) else (str(default) if default else '')

                # NaN float check
                if isinstance(val, float) and pd.isna(val):
                    return default

                return val

            features = {
                # URL features
                'url_length': safe_get('url_length', 0),
                'url_entropy': safe_get('url_entropy', 0.0),
                'num_subdomains': safe_get('num_subdomains', 0),
                'is_idn': int(safe_get('is_idn', False)),
                'has_repeated_digits': int(safe_get('has_repeated_digits', False)),
                'mixed_script': int(safe_get('mixed_script', False)),

                # Domain/WHOIS features
                'domain_age_days': safe_get('domain_age_days', 0),
                'is_newly_registered': int(safe_get('is_newly_registered', False)),
                'is_very_new': int(safe_get('is_very_new', False)),
                'registrar': safe_get('registrar', ''),
                'country': safe_get('country', ''),
                'days_until_expiry': safe_get('days_until_expiry', 0),

                # Certificate features
                'is_self_signed': int(safe_get('is_self_signed', False)),
                'cert_age_days': safe_get('cert_age_days', 0),

                # Form features
                'has_credential_form': int(safe_get('has_credential_form', False)),
                'form_count': safe_get('form_count', 0),
                'password_fields': safe_get('password_fields', 0),
                'email_fields': safe_get('email_fields', 0),
                'has_suspicious_forms': int(safe_get('has_suspicious_forms', False)),
                'suspicious_form_count': safe_get('suspicious_form_count', 0),
                'keyword_count': safe_get('keyword_count', 0),

                # HTML features
                'html_size': safe_get('html_size', 0),
                'external_links': safe_get('external_links', 0),
                'iframe_count': safe_get('iframe_count', 0),

                # JavaScript features
                'js_obfuscated': int(safe_get('js_obfuscated', False)),
                'js_keylogger': int(safe_get('js_keylogger', False)),
                'js_form_manipulation': int(safe_get('js_form_manipulation', False)),
                'js_eval_usage': int(safe_get('js_eval_usage', False)),
                'js_risk_score': safe_get('js_risk_score', 0.0),

                # Redirect features
                'redirect_count': safe_get('redirect_count', 0),
                'had_redirects': int(safe_get('had_redirects', False)),

                # DNS features
                'a_count': safe_get('a_count', 0),
                'mx_count': safe_get('mx_count', 0),
                'ns_count': safe_get('ns_count', 0),

                # Visual features
                'favicon_md5': safe_get('favicon_md5', ''),
                'favicon_sha256': safe_get('favicon_sha256', ''),
                'screenshot_phash': safe_get('screenshot_phash', ''),

                # Document/text features
                'document_text': safe_get('document_text', ''),
                'doc_has_verdict': int(safe_get('doc_has_verdict', False)),
                'doc_verdict': safe_get('doc_verdict', ''),
                'doc_risk_score': safe_get('doc_risk_score', 0.0),
                'doc_form_count': safe_get('doc_form_count', 0),
                'doc_submit_buttons': safe_get('doc_submit_buttons', ''),
                'doc_has_login_keywords': int(safe_get('doc_has_login_keywords', False)),
                'doc_has_verify_keywords': int(safe_get('doc_has_verify_keywords', False)),
                'doc_has_password_keywords': int(safe_get('doc_has_password_keywords', False)),
                'doc_has_credential_keywords': int(safe_get('doc_has_credential_keywords', False)),
                'doc_length': safe_get('doc_length', 0),

                # OCR features
                'ocr_text': safe_get('ocr_text', ''),
                'ocr_length': safe_get('ocr_length', 0),
                'ocr_has_login_keywords': int(safe_get('ocr_has_login_keywords', False)),
                'ocr_has_verify_keywords': int(safe_get('ocr_has_verify_keywords', False)),
            }

            # Get screenshot path if available
            screenshot_path = metadata.get('screenshot_path')
            if screenshot_path and not Path(screenshot_path).exists():
                logger.warning(f"Screenshot not found: {screenshot_path}")
                screenshot_path = None

            # Build complete metadata dict for detector
            # The detector expects metadata with all features merged in
            detection_metadata = {**metadata, **features}
            detection_metadata['screenshot_path'] = screenshot_path

            # Run detection with error handling for individual components
            try:
                result = self.detector.detect(metadata=detection_metadata)
            except ValueError as ve:
                # Handle NaN/inf errors in model input
                error_msg = str(ve)
                if 'NaN' in error_msg or 'infinity' in error_msg or 'inf' in error_msg:
                    logger.warning(f"Model input validation error for {domain}: {error_msg}")

                    # Check if domain is inactive/unregistered first
                    inactive_info = self.check_inactive_status(domain)
                    if inactive_info:
                        return self._create_inactive_verdict(domain, inactive_info, error_msg)

                    # Check for parking indicators before falling back to crawler verdict
                    html_size = metadata.get('html_size', 0)
                    external_links = metadata.get('external_links', 0)
                    mx_count = metadata.get('mx_count', 0)
                    a_count = metadata.get('a_count', 0)
                    cse_id = metadata.get('cse_id', '')
                    registrable = metadata.get('registrable', domain)

                    # Safeguard: Don't mark CSE/known benign domains as parked
                    is_cse_domain = bool(cse_id and cse_id != 'BULK_IMPORT')
                    is_gov_domain = any(tld in registrable.lower() for tld in ['.gov.', '.nic.in', '.ac.in', '.edu.'])

                    is_likely_parked = False
                    parking_reason = []

                    # Only check parking if NOT a CSE or government domain
                    if not is_cse_domain and not is_gov_domain:
                        # Parking detection heuristics (same as earlier but adjusted for NaN error context)
                        if html_size > 0 and html_size < 500:
                            is_likely_parked = True
                            parking_reason.append(f"minimal HTML ({html_size}B)")
                        elif html_size > 0 and html_size < 10000 and external_links <= 1:
                            # Parking pages typically have minimal content and 0-1 external links
                            # This catches GoDaddy parking landers and similar
                            is_likely_parked = True
                            parking_reason.append(f"parking page pattern (html={html_size}B, links={external_links})")
                        # Removed aggressive DNS infrastructure check

                    if is_likely_parked:
                        logger.info(f"Domain {domain} detected as PARKED (NaN fallback): {', '.join(parking_reason)}")
                        return {
                            'domain': domain,
                            'verdict': 'PARKED',
                            'confidence': 0.75,
                            'reason': f"Parked domain detected: {', '.join(parking_reason)}",
                            'source': 'aiml_heuristic_nan_fallback',
                            'error_context': 'Model input had NaN values',
                            'timestamp': datetime.now().isoformat()
                        }

                    # Fall back to crawler verdict if available and not parked
                    if crawler_verdict:
                        logger.info(f"Falling back to crawler verdict due to model input error")
                        return {
                            'domain': domain,
                            'verdict': crawler_verdict.upper(),
                            'confidence': max(0.70, crawler_confidence - 0.10),  # Slightly lower confidence
                            'reason': f'Verdict from crawler (AIML model input error: {error_msg[:100]})',
                            'source': 'crawler_fallback',
                            'error_context': error_msg,
                            'timestamp': datetime.now().isoformat()
                        }
                    else:
                        # No crawler verdict - return error
                        return {
                            'domain': domain,
                            'verdict': 'ERROR',
                            'confidence': 0.0,
                            'error': f'Model input validation failed: {error_msg[:200]}',
                            'timestamp': datetime.now().isoformat()
                        }
                else:
                    raise  # Re-raise if not a NaN/inf error

            # Add metadata to result
            result['timestamp'] = datetime.now().isoformat()
            result['source'] = 'aiml_service'
            result['chroma_metadata'] = {
                'cse_id': metadata.get('cse_id'),
                'url': metadata.get('url'),
                'country': metadata.get('country'),
                'registrar': metadata.get('registrar'),
            }

            logger.info(f"Detection complete: {domain} -> {result['verdict']} (confidence: {result['confidence']:.2f})")
            return result

        except Exception as e:
            logger.error(f"Detection failed for {domain}: {e}", exc_info=True)
            error_msg = str(e)

            # Step 1: Check if domain is inactive/unregistered
            inactive_info = self.check_inactive_status(domain)
            if inactive_info:
                return self._create_inactive_verdict(domain, inactive_info, error_msg)

            # Step 2: Check for parking indicators before falling back to crawler verdict
            html_size = metadata.get('html_size', 0)
            external_links = metadata.get('external_links', 0)
            mx_count = metadata.get('mx_count', 0)
            a_count = metadata.get('a_count', 0)
            cse_id = metadata.get('cse_id', '')
            registrable = metadata.get('registrable', domain)

            # Safeguard: Don't mark CSE/known benign domains as parked
            is_cse_domain = bool(cse_id and cse_id != 'BULK_IMPORT')
            is_gov_domain = any(tld in registrable.lower() for tld in ['.gov.', '.nic.in', '.ac.in', '.edu.'])

            is_likely_parked = False
            parking_reason = []

            # Only check parking if NOT a CSE or government domain
            if not is_cse_domain and not is_gov_domain:
                # Parking detection heuristics
                if html_size > 0 and html_size < 500:
                    is_likely_parked = True
                    parking_reason.append(f"minimal HTML ({html_size}B)")
                elif html_size > 0 and html_size < 10000 and external_links <= 1:
                    is_likely_parked = True
                    parking_reason.append(f"parking page pattern (html={html_size}B, links={external_links})")
                # Removed aggressive DNS infrastructure check

            if is_likely_parked:
                logger.info(f"Domain {domain} detected as PARKED (exception fallback): {', '.join(parking_reason)}")
                return {
                    'domain': domain,
                    'verdict': 'PARKED',
                    'confidence': 0.70,
                    'reason': f"Parked domain detected: {', '.join(parking_reason)}",
                    'source': 'aiml_heuristic_exception_fallback',
                    'error_context': f'AIML detection failed: {error_msg[:100]}',
                    'timestamp': datetime.now().isoformat()
                }

            # Step 3: Fall back to crawler verdict if available and not parked
            if crawler_verdict:
                logger.info(f"Detection failed for {domain}, falling back to crawler verdict: {crawler_verdict}")
                return {
                    'domain': domain,
                    'verdict': crawler_verdict.upper(),
                    'confidence': max(0.65, crawler_confidence - 0.15),  # Lower confidence due to error
                    'reason': f'Verdict from crawler (AIML detection failed: {error_msg[:100]})',
                    'source': 'crawler_fallback',
                    'error_context': error_msg,
                    'timestamp': datetime.now().isoformat()
                }

            # Step 4: No fallback available - return error
            return {
                'domain': domain,
                'verdict': 'ERROR',
                'confidence': 0.0,
                'error': error_msg[:500],  # Limit error message length
                'timestamp': datetime.now().isoformat()
            }

    def save_verdict(self, result: Dict):
        """Save verdict to JSON file"""
        try:
            # Get domain from either 'domain' or 'registrable' key
            domain = result.get('domain') or result.get('registrable', 'unknown')

            # Create timestamped filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            domain_safe = domain.replace('.', '_').replace('/', '_')
            filename = f"aiml_verdict_{domain_safe}_{timestamp}.json"
            filepath = self.output_dir / filename

            # Ensure result has 'domain' key for consistency
            if 'domain' not in result and 'registrable' in result:
                result['domain'] = result['registrable']

            # Save JSON
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)

            logger.info(f"Verdict saved: {filepath}")

            # Also append to a single aggregated file
            aggregated_file = self.output_dir / "aiml_verdicts_all.jsonl"
            with open(aggregated_file, 'a') as f:
                f.write(json.dumps(result) + '\n')

        except Exception as e:
            # Safe error logging with fallback
            domain_for_log = result.get('domain') or result.get('registrable', 'unknown')
            logger.error(f"Failed to save verdict for {domain_for_log}: {e}")
            logger.error(f"Result keys: {list(result.keys())}")

    def run(self):
        """Main service loop"""
        logger.info("AIML Phishing Detection Service started")
        logger.info(f"ChromaDB: {self.chroma_host}:{self.chroma_port}/{self.chroma_collection}")
        logger.info(f"Output directory: {self.output_dir}")
        logger.info(f"Check interval: {self.check_interval}s")

        iteration = 0
        while True:
            try:
                iteration += 1
                logger.info(f"\n{'='*70}")
                logger.info(f"Iteration {iteration} - Checking for new domains...")
                logger.info(f"{'='*70}")

                # Fetch unprocessed domains
                domains = self.fetch_unprocessed_domains()

                if not domains:
                    logger.info("No new domains to process")
                else:
                    logger.info(f"Processing {len(domains)} domains...")

                    for domain_data in domains:
                        # Run detection
                        result = self.run_detection(domain_data)

                        # Save verdict
                        self.save_verdict(result)

                        # Mark as processed
                        self._mark_processed(domain_data['domain'])

                        # Small delay between detections
                        time.sleep(1)

                # Wait before next check
                logger.info(f"Waiting {self.check_interval}s before next check...")
                time.sleep(self.check_interval)

            except KeyboardInterrupt:
                logger.info("Received shutdown signal, exiting...")
                break
            except Exception as e:
                logger.error(f"Error in main loop: {e}", exc_info=True)
                time.sleep(10)  # Wait before retrying


def main():
    """Entry point"""
    try:
        # Wait for ChromaDB to be ready
        logger.info("Waiting for ChromaDB to be ready...")
        time.sleep(10)

        # Create and run service
        service = AIMlService()
        service.run()

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
