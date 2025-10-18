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
from detect_phishing import UnifiedPhishingDetector

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
            self.detector = UnifiedPhishingDetector(
                model_dir="models",
                data_dir="data"
            )
            logger.info("AIML detector models loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load AIML models: {e}")
            raise

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

        # Extract crawler verdict for potential fallback
        crawler_verdict = metadata.get('verdict')
        crawler_confidence = metadata.get('confidence', 0.75)

        try:
            # FAST PATH 1: Check if domain is inactive/unregistered (from metadata)
            record_type = metadata.get('record_type', '')
            if record_type == 'inactive':
                inactive_info = self.check_inactive_status(domain)
                if inactive_info:
                    logger.info(f"Domain {domain} is inactive/unregistered - generating status verdict")
                    return self._create_inactive_verdict(domain, inactive_info)

            # FAST PATH 2: Check if crawler already identified as parked
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

            # If domain has crawler verdict but no features, trust the crawler
            has_form_features = metadata.get('form_count') is not None
            has_html_features = metadata.get('html_size', 0) > 0
            if crawler_verdict and not has_form_features and not has_html_features:
                logger.info(f"Domain {domain} has crawler verdict '{crawler_verdict}' but no features - respecting crawler")
                return {
                    'domain': domain,
                    'verdict': crawler_verdict.upper(),
                    'confidence': metadata.get('confidence', 0.80),
                    'reason': f'Verdict from pipeline crawler (no page features for AIML analysis)',
                    'source': 'crawler',
                    'timestamp': datetime.now().isoformat()
                }

            # Calculate feature quality score
            feature_quality = self.calculate_feature_quality(metadata)
            logger.info(f"Domain {domain} feature quality: {feature_quality:.2%}")

            # If feature quality is low (<30%), fall back to crawler verdict
            if feature_quality < 0.30:
                logger.info(f"Domain {domain} has low feature quality ({feature_quality:.2%}) - using crawler verdict")

                if crawler_verdict:
                    # Trust crawler verdict when features are insufficient
                    # If crawler says PHISHING, trust it even without full AIML analysis
                    return {
                        'domain': domain,
                        'verdict': crawler_verdict.upper(),
                        'confidence': crawler_confidence,
                        'reason': f'Verdict from crawler (insufficient features for AIML: {feature_quality:.0%} complete)',
                        'source': 'crawler',
                        'feature_quality': feature_quality,
                        'timestamp': datetime.now().isoformat()
                    }
                else:
                    # No verdict and low features - mark as insufficient data
                    logger.warning(f"Domain {domain} has low features and no crawler verdict")
                    return {
                        'domain': domain,
                        'verdict': 'INSUFFICIENT_DATA',
                        'confidence': 0.0,
                        'reason': f'Insufficient features for analysis ({feature_quality:.0%} complete, no crawler verdict)',
                        'feature_quality': feature_quality,
                        'timestamp': datetime.now().isoformat()
                    }

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

            # Run detection with error handling for individual components
            try:
                result = self.detector.detect(
                    domain=domain,
                    features=features,
                    screenshot_path=screenshot_path,
                    favicon_md5=metadata.get('favicon_md5'),
                    registrar=metadata.get('registrar')
                )
            except ValueError as ve:
                # Handle NaN/inf errors in model input
                error_msg = str(ve)
                if 'NaN' in error_msg or 'infinity' in error_msg or 'inf' in error_msg:
                    logger.warning(f"Model input validation error for {domain}: {error_msg}")

                    # Check if domain is inactive/unregistered first
                    inactive_info = self.check_inactive_status(domain)
                    if inactive_info:
                        return self._create_inactive_verdict(domain, inactive_info, error_msg)

                    # Fall back to crawler verdict if available
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

            # Step 2: Fall back to crawler verdict if available
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

            # Step 3: No fallback available - return error
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
            # Create timestamped filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            domain_safe = result['domain'].replace('.', '_').replace('/', '_')
            filename = f"aiml_verdict_{domain_safe}_{timestamp}.json"
            filepath = self.output_dir / filename

            # Save JSON
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)

            logger.info(f"Verdict saved: {filepath}")

            # Also append to a single aggregated file
            aggregated_file = self.output_dir / "aiml_verdicts_all.jsonl"
            with open(aggregated_file, 'a') as f:
                f.write(json.dumps(result) + '\n')

        except Exception as e:
            logger.error(f"Failed to save verdict for {result['domain']}: {e}")

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
