"""
NCIIPC PS-02 Submission Generator

Generates submission package in the exact format specified in Annexure B:
- Excel file with 20 required columns
- PDF evidence files from screenshots
- Proper folder structure for submission

Usage:
    python generate_submission.py --application-id AIGR-123456
    python generate_submission.py --application-id AIGR-123456 --filter-verdict PHISHING
    python generate_submission.py --application-id AIGR-123456 --source chromadb
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
import pandas as pd
from PIL import Image
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import chromadb
from chromadb.config import Settings, DEFAULT_TENANT, DEFAULT_DATABASE

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SubmissionGenerator:
    """Generate NCIIPC PS-02 submission package"""

    # Annexure B: Required Excel columns (exact order)
    REQUIRED_COLUMNS = [
        'Application_ID',
        'Source of detection',
        'Identified Phishing/Suspected Domain Name',
        'Corresponding CSE Domain Name',
        'Critical Sector Entity Name',
        'Phishing/Suspected Domains',  # Class Label
        'Domain Registration Date',
        'Registrar Name',
        'Registrant Name or Registrant Organisation',
        'Registrant Country',
        'Name Servers',
        'Hosting IP',
        'Hosting ISP',
        'Hosting Country',
        'DNS Records (if any)',
        'Evidence file name',
        'Date of detection (DD-MM-YYYY)',
        'Time of detection (HH-MM-SS)',
        'Date of Post (If detection is from Source: social media)',
        'Remarks (If any)'
    ]

    def __init__(self, application_id: str, output_dir: str = None):
        """
        Initialize submission generator

        Args:
            application_id: Application ID (e.g., AIGR-123456)
            output_dir: Output directory for submission (default: current directory)
        """
        self.application_id = application_id
        self.output_dir = Path(output_dir or os.getcwd())

        # Build submission folder structure per Annexure B
        self.submission_folder = self.output_dir / f"PS-02_{application_id}_Submission"
        self.evidences_folder = self.submission_folder / f"PS-02_{application_id}_Evidences"
        self.documentation_folder = self.submission_folder / f"PS-02_{application_id}_Documentation_folder"

        # Excel file path
        self.excel_filename = f"PS-02_{application_id}_Submission_Set.xlsx"
        self.excel_path = self.submission_folder / self.excel_filename

        # ChromaDB client (lazy initialization)
        self.chroma_client = None
        self.collection = None

        # CSE mapping (domain -> organization name)
        self.cse_mapping = self._load_cse_mapping()

        logger.info(f"Initialized submission generator for {application_id}")
        logger.info(f"Output directory: {self.submission_folder}")

    def _load_cse_mapping(self) -> Dict[str, str]:
        """Load CSE domain to organization name mapping"""
        cse_map = {}

        # Try to load from CSE baseline profile
        baseline_path = Path('data/training/cse_baseline_profile.json')
        if baseline_path.exists():
            try:
                with open(baseline_path, 'r') as f:
                    baseline = json.load(f)
                    # If baseline has org mapping, use it
                    if 'cse_organizations' in baseline:
                        cse_map = baseline['cse_organizations']
                    # Otherwise create mapping from domains list
                    elif 'domains' in baseline:
                        for domain in baseline['domains']:
                            # Extract organization name from domain
                            org_name = self._extract_org_name(domain)
                            cse_map[domain] = org_name
                logger.info(f"Loaded {len(cse_map)} CSE mappings")
            except Exception as e:
                logger.warning(f"Could not load CSE mapping: {e}")

        # Default mappings for common CSEs
        default_mappings = {
            'onlinesbi.com': 'State Bank of India',
            'sbi.co.in': 'State Bank of India',
            'icicibank.com': 'ICICI Bank',
            'hdfcbank.com': 'HDFC Bank',
            'axisbank.com': 'Axis Bank',
            'pnb.co.in': 'Punjab National Bank',
            'bank.in': 'Banking Sector',
            'airtel.in': 'Airtel',
            'airtel.com': 'Bharti Airtel Limited',
            'bsnl.co.in': 'BSNL',
            'uidai.gov.in': 'UIDAI',
            'epfindia.gov.in': 'EPFO',
            'irctc.co.in': 'IRCTC'
        }

        # Merge with defaults (existing mappings take priority)
        for domain, org in default_mappings.items():
            if domain not in cse_map:
                cse_map[domain] = org

        return cse_map

    def _extract_org_name(self, domain: str) -> str:
        """Extract organization name from domain"""
        # Simple heuristic: capitalize domain name
        base = domain.split('.')[0]
        return base.upper()

    def connect_to_chromadb(self, host: str = 'localhost', port: int = 8000):
        """Connect to ChromaDB for data retrieval"""
        try:
            self.chroma_client = chromadb.HttpClient(
                host=host,
                port=port,
                settings=Settings(anonymized_telemetry=False),
                tenant=DEFAULT_TENANT,
                database=DEFAULT_DATABASE
            )
            self.collection = self.chroma_client.get_collection(name='domains')
            logger.info(f"Connected to ChromaDB at {host}:{port}")
        except Exception as e:
            logger.error(f"Failed to connect to ChromaDB: {e}")
            raise

    def load_data_from_jsonl(self, jsonl_path: str) -> List[Dict]:
        """Load domain data from JSONL file"""
        data = []
        jsonl_file = Path(jsonl_path)

        if not jsonl_file.exists():
            logger.error(f"JSONL file not found: {jsonl_path}")
            return data

        try:
            with open(jsonl_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        record = json.loads(line.strip())
                        # Extract metadata (JSONL has metadata nested)
                        if 'metadata' in record:
                            metadata = record['metadata']
                            metadata['id'] = record.get('id', '')
                            data.append(metadata)
                        else:
                            data.append(record)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Invalid JSON at line {line_num}: {e}")

            logger.info(f"Loaded {len(data)} records from {jsonl_path}")
        except Exception as e:
            logger.error(f"Error reading JSONL file: {e}")

        return data

    def load_data_from_chromadb(self) -> List[Dict]:
        """Load all domain data from ChromaDB"""
        if not self.collection:
            logger.error("ChromaDB not connected. Call connect_to_chromadb() first.")
            return []

        try:
            results = self.collection.get(include=['metadatas'])
            data = results.get('metadatas', [])
            logger.info(f"Loaded {len(data)} records from ChromaDB")
            return data
        except Exception as e:
            logger.error(f"Error querying ChromaDB: {e}")
            return []

    def load_verdict_files(self, verdict_dir: str) -> Dict[str, Dict]:
        """Load AIML verdict JSON files and create domain -> verdict mapping"""
        verdicts = {}
        verdict_path = Path(verdict_dir)

        if not verdict_path.exists():
            logger.warning(f"Verdict directory not found: {verdict_dir}")
            return verdicts

        json_files = list(verdict_path.glob('aiml_verdict_*.json'))
        logger.info(f"Found {len(json_files)} verdict files")

        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    verdict = json.load(f)
                    domain = verdict.get('domain') or verdict.get('registrable', '')
                    if domain:
                        verdicts[domain] = verdict
            except Exception as e:
                logger.warning(f"Error reading {json_file}: {e}")

        logger.info(f"Loaded verdicts for {len(verdicts)} domains")
        return verdicts

    def get_cse_domain(self, metadata: Dict) -> str:
        """Extract corresponding CSE domain from metadata"""
        # Try multiple fields that might contain CSE info
        cse_domain = metadata.get('seed_registrable', '')
        if not cse_domain:
            cse_domain = metadata.get('original_domain', '')
        if not cse_domain:
            cse_id = metadata.get('cse_id', '')
            if cse_id and cse_id not in ['Unknown', 'BULK_IMPORT', 'URL from user']:
                cse_domain = cse_id

        return cse_domain or 'N/A'

    def get_cse_organization(self, cse_domain: str) -> str:
        """Get organization name for CSE domain"""
        if cse_domain == 'N/A' or not cse_domain:
            return 'N/A'

        # Direct match
        if cse_domain in self.cse_mapping:
            return self.cse_mapping[cse_domain]

        # Try registrable domain match
        for known_domain, org in self.cse_mapping.items():
            if known_domain in cse_domain or cse_domain in known_domain:
                return org

        # Extract from domain name
        return self._extract_org_name(cse_domain)

    def classify_verdict(self, verdict: str) -> str:
        """
        Classify verdict into submission categories

        Returns: PHISHING, SUSPICIOUS, BENIGN, PARKED, INACTIVE, etc.
        """
        if not verdict:
            return 'N/A'

        verdict_upper = verdict.upper()

        # Map to submission categories
        if verdict_upper in ['PHISHING', 'MALICIOUS']:
            return 'PHISHING'
        elif verdict_upper in ['SUSPICIOUS', 'SUSPECTED']:
            return 'SUSPICIOUS'
        elif verdict_upper in ['BENIGN', 'LEGITIMATE']:
            return 'BENIGN'
        elif verdict_upper == 'PARKED':
            return 'PARKED'
        elif verdict_upper in ['INACTIVE', 'UNREGISTERED']:
            return 'INACTIVE'
        elif verdict_upper == 'ERROR':
            return 'ERROR'
        else:
            return verdict_upper

    def format_dns_records(self, metadata: Dict) -> str:
        """Format DNS records from metadata"""
        dns_records = []

        # Parse DNS JSON if available
        dns_str = metadata.get('dns', '')
        if dns_str:
            try:
                dns_data = json.loads(dns_str) if isinstance(dns_str, str) else dns_str
                for record_type in ['A', 'AAAA', 'MX', 'NS', 'CNAME']:
                    if record_type in dns_data and dns_data[record_type]:
                        records = dns_data[record_type]
                        if isinstance(records, list) and records:
                            dns_records.append(f"{record_type}: {', '.join(records)}")
            except:
                pass

        # Fallback to individual fields
        if not dns_records:
            a_count = metadata.get('a_count', 0)
            mx_count = metadata.get('mx_count', 0)
            ns_count = metadata.get('ns_count', 0)
            if a_count or mx_count or ns_count:
                dns_records.append(f"A: {a_count}, MX: {mx_count}, NS: {ns_count}")

        return '; '.join(dns_records) if dns_records else 'N/A'

    def get_name_servers(self, metadata: Dict) -> str:
        """Extract name servers from DNS metadata"""
        dns_str = metadata.get('dns', '')
        if dns_str:
            try:
                dns_data = json.loads(dns_str) if isinstance(dns_str, str) else dns_str
                ns_list = dns_data.get('NS', [])
                if ns_list:
                    return ', '.join(ns_list)
            except:
                pass

        ns_count = metadata.get('ns_count', 0)
        return f"{ns_count} nameserver(s)" if ns_count > 0 else 'N/A'

    def get_hosting_ip(self, metadata: Dict) -> str:
        """Extract hosting IP address"""
        # Try DNS A records first
        dns_str = metadata.get('dns', '')
        if dns_str:
            try:
                dns_data = json.loads(dns_str) if isinstance(dns_str, str) else dns_data
                a_records = dns_data.get('A', [])
                if a_records:
                    return a_records[0]  # Return first A record
            except:
                pass

        # Try geoip data
        geoip_str = metadata.get('geoip', '')
        if geoip_str:
            try:
                geoip_data = json.loads(geoip_str) if isinstance(geoip_str, str) else geoip_str
                # GeoIP might not have IP, but we can infer from context
            except:
                pass

        return 'N/A'

    def parse_timestamp(self, timestamp_str: str) -> tuple:
        """
        Parse ISO timestamp to (date, time) in required format

        Returns:
            tuple: (DD-MM-YYYY, HH-MM-SS)
        """
        if not timestamp_str:
            return ('N/A', 'N/A')

        try:
            # Parse ISO format: 2025-10-27T11:41:59.155449
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            date_str = dt.strftime('%d-%m-%Y')
            time_str = dt.strftime('%H-%M-%S')
            return (date_str, time_str)
        except Exception as e:
            logger.warning(f"Failed to parse timestamp {timestamp_str}: {e}")
            return ('N/A', 'N/A')

    def calculate_registration_date(self, metadata: Dict) -> str:
        """Calculate domain registration date from age"""
        domain_age_days = metadata.get('domain_age_days', 0)

        if domain_age_days and domain_age_days > 0:
            try:
                # Calculate registration date from age
                reg_date = datetime.now() - pd.Timedelta(days=int(domain_age_days))
                return reg_date.strftime('%d-%m-%Y')
            except:
                pass

        # Try first_seen timestamp
        first_seen = metadata.get('first_seen', '')
        if first_seen:
            date_part, _ = self.parse_timestamp(first_seen)
            if date_part != 'N/A':
                return date_part

        return 'N/A'

    def generate_evidence_filename(self, domain: str, cse_org: str, index: int) -> str:
        """
        Generate evidence filename per Annexure B format

        Format: <Target_org_name>_<Up to Two-level subdomain_Name>_<S.No>.pdf
        Example: SBI_sbi123.co.in_1.pdf
        """
        # Clean organization name (remove spaces, special chars)
        org_clean = cse_org.replace(' ', '').replace('/', '_')
        if org_clean == 'N/A':
            org_clean = 'Unknown'

        # Extract up to two-level subdomain
        # Example: xyz.abc.sbi.123.com -> sbi.123.com
        parts = domain.split('.')
        if len(parts) <= 2:
            subdomain = domain
        else:
            # Take last 2 parts (domain + TLD) plus one subdomain if available
            subdomain = '.'.join(parts[-3:]) if len(parts) >= 3 else domain

        # Clean subdomain
        subdomain_clean = subdomain.replace('/', '_').replace(':', '_')

        return f"{org_clean}_{subdomain_clean}_{index}.pdf"

    def convert_screenshot_to_pdf(self, screenshot_path: str, pdf_output_path: str):
        """Convert PNG screenshot to PDF"""
        try:
            screenshot_file = Path(screenshot_path)

            # Handle path mapping (workspace -> out)
            if not screenshot_file.exists():
                # Try alternative path
                alt_path = screenshot_path.replace('/workspace/out/', '/out/')
                screenshot_file = Path(alt_path)

            if not screenshot_file.exists():
                # Try in Pipeline/out/screenshots/
                alt_path2 = Path('/home/turtleneck/Desktop/PS02/Pipeline/out/screenshots') / screenshot_file.name
                screenshot_file = alt_path2

            if not screenshot_file.exists():
                logger.warning(f"Screenshot not found: {screenshot_path}")
                # Create placeholder PDF
                self._create_placeholder_pdf(pdf_output_path, "Screenshot not available")
                return

            # Load image
            img = Image.open(screenshot_file)

            # Convert RGBA to RGB if needed
            if img.mode == 'RGBA':
                rgb_img = Image.new('RGB', img.size, (255, 255, 255))
                rgb_img.paste(img, mask=img.split()[3])
                img = rgb_img

            # Create PDF
            pdf_path = Path(pdf_output_path)
            pdf_path.parent.mkdir(parents=True, exist_ok=True)

            # Scale image to fit A4
            img_width, img_height = img.size
            a4_width, a4_height = A4

            scale = min(a4_width / img_width, a4_height / img_height) * 0.9
            new_width = img_width * scale
            new_height = img_height * scale

            # Create PDF with image
            c = canvas.Canvas(str(pdf_path), pagesize=A4)
            x_offset = (a4_width - new_width) / 2
            y_offset = (a4_height - new_height) / 2
            c.drawImage(str(screenshot_file), x_offset, y_offset, width=new_width, height=new_height)
            c.save()

            logger.debug(f"Created PDF: {pdf_path}")

        except Exception as e:
            logger.warning(f"Failed to convert screenshot to PDF: {e}")
            # Create placeholder
            self._create_placeholder_pdf(pdf_output_path, f"Error: {str(e)[:100]}")

    def _create_placeholder_pdf(self, pdf_path: str, message: str):
        """Create placeholder PDF with message"""
        try:
            Path(pdf_path).parent.mkdir(parents=True, exist_ok=True)
            c = canvas.Canvas(pdf_path, pagesize=A4)
            c.drawString(100, 750, "Evidence Screenshot")
            c.drawString(100, 700, message)
            c.save()
        except Exception as e:
            logger.error(f"Failed to create placeholder PDF: {e}")

    def build_excel_row(self, metadata: Dict, verdict_data: Dict, index: int) -> Dict:
        """
        Build a single Excel row from metadata and verdict

        Args:
            metadata: Domain metadata from ChromaDB/JSONL
            verdict_data: AIML verdict data
            index: Row index for evidence filename

        Returns:
            Dict with all required columns
        """
        domain = metadata.get('registrable') or metadata.get('domain', 'N/A')

        # Get verdict info (prefer verdict_data if available)
        if verdict_data:
            verdict = verdict_data.get('verdict', metadata.get('verdict', 'N/A'))
            confidence = verdict_data.get('confidence', metadata.get('confidence', 0))
            detection_source = verdict_data.get('source', 'aiml_service')
            timestamp = verdict_data.get('timestamp', metadata.get('first_seen', ''))
            reason = verdict_data.get('reason', metadata.get('reasons', ''))
        else:
            verdict = metadata.get('verdict', 'N/A')
            confidence = metadata.get('confidence', 0)
            detection_source = 'crawler'
            timestamp = metadata.get('first_seen', '')
            reason = metadata.get('reasons', '')

        # Parse timestamp
        detection_date, detection_time = self.parse_timestamp(timestamp)

        # Get CSE info
        cse_domain = self.get_cse_domain(metadata)
        cse_org = self.get_cse_organization(cse_domain)

        # Classify verdict
        class_label = self.classify_verdict(verdict)

        # Generate evidence filename
        evidence_filename = self.generate_evidence_filename(domain, cse_org, index)

        # Build row
        row = {
            'Application_ID': self.application_id,
            'Source of detection': detection_source,
            'Identified Phishing/Suspected Domain Name': domain,
            'Corresponding CSE Domain Name': cse_domain,
            'Critical Sector Entity Name': cse_org,
            'Phishing/Suspected Domains': class_label,
            'Domain Registration Date': self.calculate_registration_date(metadata),
            'Registrar Name': metadata.get('registrar', 'N/A'),
            'Registrant Name or Registrant Organisation': 'N/A',  # Not typically available in WHOIS privacy
            'Registrant Country': metadata.get('country', 'N/A'),
            'Name Servers': self.get_name_servers(metadata),
            'Hosting IP': self.get_hosting_ip(metadata),
            'Hosting ISP': metadata.get('asn_org', 'N/A'),
            'Hosting Country': metadata.get('country', 'N/A'),
            'DNS Records (if any)': self.format_dns_records(metadata),
            'Evidence file name': evidence_filename,
            'Date of detection (DD-MM-YYYY)': detection_date,
            'Time of detection (HH-MM-SS)': detection_time,
            'Date of Post (If detection is from Source: social media)': 'N/A',
            'Remarks (If any)': f"Confidence: {confidence:.2f}, {reason}"[:200]  # Limit length
        }

        return row

    def generate_submission(self, data_source: str = 'jsonl',
                           jsonl_path: str = None,
                           verdict_dir: str = None,
                           filter_verdict: str = None,
                           chromadb_host: str = 'localhost',
                           chromadb_port: int = 8000):
        """
        Generate complete submission package

        Args:
            data_source: 'jsonl' or 'chromadb'
            jsonl_path: Path to JSONL file (if data_source='jsonl')
            verdict_dir: Directory with verdict JSON files
            filter_verdict: Optional filter (PHISHING, SUSPICIOUS, etc.)
            chromadb_host: ChromaDB host (if data_source='chromadb')
            chromadb_port: ChromaDB port
        """
        logger.info("="*70)
        logger.info("NCIIPC PS-02 Submission Generator")
        logger.info("="*70)
        logger.info(f"Application ID: {self.application_id}")
        logger.info(f"Data source: {data_source}")
        if filter_verdict:
            logger.info(f"Filter: {filter_verdict}")

        # Create folder structure
        logger.info("Creating submission folder structure...")
        self.submission_folder.mkdir(parents=True, exist_ok=True)
        self.evidences_folder.mkdir(parents=True, exist_ok=True)
        self.documentation_folder.mkdir(parents=True, exist_ok=True)

        # Load data
        logger.info("Loading domain data...")
        if data_source == 'chromadb':
            self.connect_to_chromadb(chromadb_host, chromadb_port)
            domain_data = self.load_data_from_chromadb()
        else:
            if not jsonl_path:
                jsonl_path = '/home/turtleneck/Desktop/PS02/dump_all.jsonl'
            domain_data = self.load_data_from_jsonl(jsonl_path)

        if not domain_data:
            logger.error("No data loaded. Aborting.")
            return

        # Load verdicts
        logger.info("Loading AIML verdicts...")
        if not verdict_dir:
            verdict_dir = '/home/turtleneck/Desktop/PS02/Pipeline/out'
        verdicts = self.load_verdict_files(verdict_dir)

        # Build Excel rows
        logger.info("Building Excel rows...")
        excel_rows = []
        evidence_tasks = []  # (screenshot_path, pdf_path)

        for idx, metadata in enumerate(domain_data, 1):
            domain = metadata.get('registrable') or metadata.get('domain', '')

            # Get verdict data if available
            verdict_data = verdicts.get(domain, {})

            # Get verdict for filtering
            verdict = verdict_data.get('verdict', metadata.get('verdict', ''))
            class_label = self.classify_verdict(verdict)

            # Apply filter
            if filter_verdict and class_label != filter_verdict.upper():
                continue

            # Skip BENIGN domains unless explicitly requested
            if not filter_verdict and class_label == 'BENIGN':
                continue

            # Build row
            row = self.build_excel_row(metadata, verdict_data, len(excel_rows) + 1)
            excel_rows.append(row)

            # Schedule PDF generation
            screenshot_path = metadata.get('screenshot_path', '')
            if screenshot_path:
                evidence_filename = row['Evidence file name']
                pdf_path = self.evidences_folder / evidence_filename
                evidence_tasks.append((screenshot_path, str(pdf_path)))

        logger.info(f"Generated {len(excel_rows)} rows for submission")

        if not excel_rows:
            logger.warning("No domains match filter criteria. No submission generated.")
            return

        # Create Excel file
        logger.info("Creating Excel file...")
        df = pd.DataFrame(excel_rows, columns=self.REQUIRED_COLUMNS)

        # Write to Excel with formatting
        with pd.ExcelWriter(self.excel_path, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='Submission')

            # Format worksheet
            worksheet = writer.sheets['Submission']

            # Bold headers
            for cell in worksheet[1]:
                cell.font = cell.font.copy(bold=True)

            # Auto-adjust column widths
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)
                worksheet.column_dimensions[column_letter].width = adjusted_width

        logger.info(f"Excel file created: {self.excel_path}")

        # Generate PDF evidence files
        logger.info(f"Generating {len(evidence_tasks)} PDF evidence files...")
        for idx, (screenshot_path, pdf_path) in enumerate(evidence_tasks, 1):
            if idx % 50 == 0:
                logger.info(f"Progress: {idx}/{len(evidence_tasks)}")
            self.convert_screenshot_to_pdf(screenshot_path, pdf_path)

        # Create README in documentation folder
        readme_path = self.documentation_folder / "README.txt"
        with open(readme_path, 'w') as f:
            f.write(f"PS-02 Submission Package\n")
            f.write(f"Application ID: {self.application_id}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"This folder should contain:\n")
            f.write(f"- PS-02_{self.application_id}_Report.pdf (detailed solution documentation)\n")
            f.write(f"- Source code and configuration files\n")
            f.write(f"- Architecture diagrams\n")
            f.write(f"- Setup and usage instructions\n")

        # Summary
        logger.info("="*70)
        logger.info("SUBMISSION PACKAGE GENERATED SUCCESSFULLY")
        logger.info("="*70)
        logger.info(f"Location: {self.submission_folder}")
        logger.info(f"Total domains: {len(excel_rows)}")
        logger.info(f"Excel file: {self.excel_filename}")
        logger.info(f"Evidence files: {len(evidence_tasks)} PDFs")
        logger.info("")
        logger.info("Next steps:")
        logger.info("1. Add PS-02_<Application_ID>_Report.pdf to Documentation folder")
        logger.info("2. Review Excel file for accuracy")
        logger.info("3. Verify evidence PDFs are readable")
        logger.info(f"4. Zip the folder: PS-02_{self.application_id}_Submission.zip")
        logger.info("5. Submit on NCIIPC portal")
        logger.info("="*70)


def main():
    parser = argparse.ArgumentParser(
        description='Generate NCIIPC PS-02 submission package',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_submission.py --application-id AIGR-123456
  python generate_submission.py --application-id AIGR-123456 --filter-verdict PHISHING
  python generate_submission.py --application-id AIGR-123456 --source chromadb
  python generate_submission.py --application-id AIGR-123456 --output-dir /path/to/output
        """
    )

    parser.add_argument(
        '--application-id',
        required=True,
        help='Application ID (e.g., AIGR-123456)'
    )

    parser.add_argument(
        '--source',
        choices=['jsonl', 'chromadb'],
        default='jsonl',
        help='Data source (default: jsonl)'
    )

    parser.add_argument(
        '--jsonl-path',
        help='Path to JSONL file (default: dump_all.jsonl in project root)'
    )

    parser.add_argument(
        '--verdict-dir',
        help='Directory with verdict JSON files (default: Pipeline/out)'
    )

    parser.add_argument(
        '--filter-verdict',
        choices=['PHISHING', 'SUSPICIOUS', 'PARKED', 'INACTIVE', 'BENIGN'],
        help='Filter by verdict type (default: exclude BENIGN)'
    )

    parser.add_argument(
        '--output-dir',
        help='Output directory for submission (default: current directory)'
    )

    parser.add_argument(
        '--chromadb-host',
        default='localhost',
        help='ChromaDB host (default: localhost)'
    )

    parser.add_argument(
        '--chromadb-port',
        type=int,
        default=8000,
        help='ChromaDB port (default: 8000)'
    )

    args = parser.parse_args()

    try:
        generator = SubmissionGenerator(
            application_id=args.application_id,
            output_dir=args.output_dir
        )

        generator.generate_submission(
            data_source=args.source,
            jsonl_path=args.jsonl_path,
            verdict_dir=args.verdict_dir,
            filter_verdict=args.filter_verdict,
            chromadb_host=args.chromadb_host,
            chromadb_port=args.chromadb_port
        )

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
