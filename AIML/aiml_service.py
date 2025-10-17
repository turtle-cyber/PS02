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

    def fetch_unprocessed_domains(self) -> List[Dict]:
        """Fetch domains from ChromaDB that haven't been processed by AIML"""
        try:
            # Query ChromaDB for domains
            # We'll get domains that have features but may not have AIML verdicts yet
            results = self.collection.get(
                limit=self.batch_size,
                include=['metadatas', 'documents']
            )

            if not results or not results.get('metadatas'):
                return []

            # Filter unprocessed domains
            unprocessed = []
            for i, metadata in enumerate(results['metadatas']):
                domain = metadata.get('registrable') or metadata.get('domain')
                if not domain or domain in self.processed_domains:
                    continue

                # Only process domains with features
                if metadata.get('has_features') or metadata.get('html_size', 0) > 0:
                    unprocessed.append({
                        'domain': domain,
                        'metadata': metadata,
                        'document': results['documents'][i] if results.get('documents') else ''
                    })

            logger.info(f"Found {len(unprocessed)} unprocessed domains with features")
            return unprocessed

        except Exception as e:
            logger.error(f"Error fetching domains from ChromaDB: {e}")
            return []

    def run_detection(self, domain_data: Dict) -> Dict:
        """Run AIML phishing detection on a single domain"""
        domain = domain_data['domain']
        metadata = domain_data['metadata']

        logger.info(f"Running AIML detection on: {domain}")

        try:
            # Check if crawler already identified as parked (fast path)
            crawler_verdict = metadata.get('verdict')
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

            # Extract features from ChromaDB metadata with proper NaN handling
            def safe_get(key, default=0):
                """Safely extract value, handling NaN/None"""
                val = metadata.get(key, default)
                if val is None or (isinstance(val, float) and pd.isna(val)):
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
                screenshot_path = None

            # Run detection
            result = self.detector.detect(
                domain=domain,
                features=features,
                screenshot_path=screenshot_path,
                favicon_md5=metadata.get('favicon_md5'),
                registrar=metadata.get('registrar')
            )

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
            logger.error(f"Detection failed for {domain}: {e}")
            return {
                'domain': domain,
                'verdict': 'ERROR',
                'confidence': 0.0,
                'error': str(e),
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
