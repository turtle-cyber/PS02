#!/usr/bin/env python3
"""
Extract Text Features from HTML Files
Extracts document text, keywords, forms, and content-based features

IMPORTANT: This extracts features that were missing from the crawler:
- document_text
- doc_* features (form_count, keywords, verdicts, etc.)
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional
import argparse

# Try importing BeautifulSoup, provide helpful error if not available
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: BeautifulSoup4 not installed")
    print("Install with: pip install beautifulsoup4 lxml")
    sys.exit(1)


class TextFeatureExtractor:
    """Extract text-based features from HTML content"""

    def __init__(self):
        # Phishing keywords by category
        self.login_keywords = [
            'login', 'log in', 'signin', 'sign in', 'sign-in',
            'authenticate', 'log on', 'logon'
        ]

        self.verify_keywords = [
            'verify', 'verification', 'confirm', 'confirmation',
            'validate', 'validation', 'update', 'renew'
        ]

        self.password_keywords = [
            'password', 'passwd', 'pwd', 'passphrase', 'pin',
            'secret', 'credential', 'credentials'
        ]

        self.credential_keywords = self.login_keywords + self.password_keywords

        self.urgency_keywords = [
            'urgent', 'immediate', 'immediately', 'expire', 'expiring',
            'suspended', 'suspend', 'limited time', 'act now', 'verify now',
            'warning', 'alert', 'action required'
        ]

        self.financial_keywords = [
            'bank', 'banking', 'account', 'payment', 'transaction',
            'credit card', 'debit card', 'wallet', 'paypal', 'invoice'
        ]

    def extract_text_from_html(self, html_content: str) -> str:
        """Extract clean text from HTML"""
        soup = BeautifulSoup(html_content, 'lxml')

        # Remove script and style elements
        for script in soup(['script', 'style', 'noscript']):
            script.decompose()

        # Get text
        text = soup.get_text()

        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)

        return text

    def count_keywords(self, text: str, keywords: List[str]) -> int:
        """Count occurrences of keywords in text (case-insensitive)"""
        text_lower = text.lower()
        count = 0
        for keyword in keywords:
            count += text_lower.count(keyword.lower())
        return count

    def has_keywords(self, text: str, keywords: List[str], threshold: int = 1) -> bool:
        """Check if text contains at least threshold keywords"""
        return self.count_keywords(text, keywords) >= threshold

    def extract_forms(self, html_content: str) -> List[Dict]:
        """Extract form information"""
        soup = BeautifulSoup(html_content, 'lxml')
        forms = []

        for form in soup.find_all('form'):
            form_info = {
                'method': form.get('method', '').lower(),
                'action': form.get('action', ''),
                'inputs': [],
                'submit_buttons': []
            }

            # Find all input fields
            for input_tag in form.find_all('input'):
                input_type = input_tag.get('type', 'text').lower()
                input_name = input_tag.get('name', '')
                form_info['inputs'].append({
                    'type': input_type,
                    'name': input_name
                })

            # Find submit buttons
            for button in form.find_all(['button', 'input']):
                if button.name == 'button' or button.get('type') == 'submit':
                    button_text = button.get_text().strip() or button.get('value', '')
                    if button_text:
                        form_info['submit_buttons'].append(button_text)

            forms.append(form_info)

        return forms

    def assess_form_risk(self, forms: List[Dict], document_text: str) -> Dict:
        """Assess risk based on form characteristics"""
        has_password = False
        has_email = False
        credential_form_count = 0
        suspicious_form_count = 0
        all_submit_buttons = []

        for form in forms:
            form_has_password = False
            form_has_email = False

            for inp in form['inputs']:
                input_type = inp['type']
                input_name = inp['name'].lower()

                if input_type == 'password':
                    has_password = True
                    form_has_password = True

                if input_type == 'email' or 'email' in input_name or 'mail' in input_name:
                    has_email = True
                    form_has_email = True

            # Credential form: has password OR (email + login keywords nearby)
            if form_has_password or (form_has_email and self.has_keywords(document_text, self.login_keywords)):
                credential_form_count += 1

            # Suspicious if credential form + urgency/verify keywords
            if (form_has_password or form_has_email) and \
               (self.has_keywords(document_text, self.urgency_keywords) or \
                self.has_keywords(document_text, self.verify_keywords)):
                suspicious_form_count += 1

            all_submit_buttons.extend(form['submit_buttons'])

        return {
            'has_password': has_password,
            'has_email': has_email,
            'credential_form_count': credential_form_count,
            'suspicious_form_count': suspicious_form_count,
            'submit_buttons': all_submit_buttons
        }

    def calculate_risk_score(self, text: str, forms: List[Dict]) -> float:
        """Calculate content-based risk score (0-1)"""
        risk_score = 0.0

        # Factor 1: Credential keywords (up to 0.3)
        credential_count = self.count_keywords(text, self.credential_keywords)
        risk_score += min(0.3, credential_count * 0.05)

        # Factor 2: Urgency keywords (up to 0.2)
        urgency_count = self.count_keywords(text, self.urgency_keywords)
        risk_score += min(0.2, urgency_count * 0.05)

        # Factor 3: Verify keywords (up to 0.2)
        verify_count = self.count_keywords(text, self.verify_keywords)
        risk_score += min(0.2, verify_count * 0.05)

        # Factor 4: Forms with passwords (up to 0.3)
        password_forms = sum(1 for form in forms if any(inp['type'] == 'password' for inp in form['inputs']))
        risk_score += min(0.3, password_forms * 0.15)

        return min(1.0, risk_score)

    def extract_features(self, html_path: str = None, html_content: str = None) -> Dict:
        """
        Extract all text-based features from HTML file or content string.

        Args:
            html_path: Path to HTML file (if html_content is not provided)
            html_content: HTML content as a string

        Returns dict with:
        - document_text
        - doc_length
        - doc_form_count
        - doc_has_verdict (whether risk assessment was done)
        - doc_verdict (benign/suspicious)
        - doc_risk_score
        - doc_submit_buttons
        - doc_has_login_keywords
        - doc_has_verify_keywords
        - doc_has_password_keywords
        - doc_has_credential_keywords
        """
        try:
            # Ensure we have HTML content
            if not html_content:
                if not html_path or not Path(html_path).exists():
                    raise ValueError("Either html_path or html_content must be provided")
                with open(html_path, 'r', encoding='utf-8', errors='ignore') as f:
                    html_content = f.read()

            # Extract text
            document_text = self.extract_text_from_html(html_content)
            doc_length = len(document_text)

            # Extract forms
            forms = self.extract_forms(html_content)
            doc_form_count = len(forms)

            # Form risk assessment
            form_risk = self.assess_form_risk(forms, document_text)

            # Keyword detection
            doc_has_login_keywords = self.has_keywords(document_text, self.login_keywords)
            doc_has_verify_keywords = self.has_keywords(document_text, self.verify_keywords)
            doc_has_password_keywords = self.has_keywords(document_text, self.password_keywords)
            doc_has_credential_keywords = self.has_keywords(document_text, self.credential_keywords)

            # Calculate risk score
            doc_risk_score = self.calculate_risk_score(document_text, forms)

            # Verdict
            doc_verdict = 'suspicious' if doc_risk_score > 0.5 else 'benign'
            doc_has_verdict = True

            # Submit buttons (join with semicolon)
            doc_submit_buttons = '; '.join(form_risk['submit_buttons'][:5])  # Max 5

            return {
                'document_text': document_text[:5000],  # Limit to 5000 chars for storage
                'doc_length': doc_length,
                'doc_form_count': doc_form_count,
                'doc_has_verdict': doc_has_verdict,
                'doc_verdict': doc_verdict,
                'doc_risk_score': round(doc_risk_score, 3),
                'doc_submit_buttons': doc_submit_buttons,
                'doc_has_login_keywords': doc_has_login_keywords,
                'doc_has_verify_keywords': doc_has_verify_keywords,
                'doc_has_password_keywords': doc_has_password_keywords,
                'doc_has_credential_keywords': doc_has_credential_keywords,
            }

        except Exception as e:
            error_source = html_path or "html_content"
            print(f"Error processing {error_source}: {e}")
            return {
                'document_text': '',
                'doc_length': 0,
                'doc_form_count': 0,
                'doc_has_verdict': False,
                'doc_verdict': '',
                'doc_risk_score': 0.0,
                'doc_submit_buttons': '',
                'doc_has_login_keywords': False,
                'doc_has_verify_keywords': False,
                'doc_has_password_keywords': False,
                'doc_has_credential_keywords': False,
            }


def main():
    parser = argparse.ArgumentParser(description='Extract text features from HTML files')
    parser.add_argument('--html-dir', default='Pipeline/out/html',
                       help='Directory containing HTML files')
    parser.add_argument('--jsonl', default='dump_all.jsonl',
                       help='Input JSONL file with domain metadata')
    parser.add_argument('--output', default='AIML/data/text_features.jsonl',
                       help='Output JSONL file')
    args = parser.parse_args()

    extractor = TextFeatureExtractor()
    html_dir = Path(args.html_dir)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print("="*70)
    print("TEXT FEATURE EXTRACTION")
    print("="*70)
    print(f"HTML directory: {html_dir}")
    print(f"Input JSONL: {args.jsonl}")
    print(f"Output: {output_path}")
    print()

    # Read input JSONL
    domains = []
    with open(args.jsonl, 'r') as f:
        for line in f:
            domains.append(json.loads(line))

    print(f"Loaded {len(domains)} domains from JSONL")

    # Process each domain
    processed = 0
    with_html = 0

    with open(output_path, 'w') as out_f:
        for domain_data in domains:
            domain_id = domain_data['id']
            metadata = domain_data['metadata']
            registrable = metadata.get('registrable', '')

            # Find HTML file
            html_path_meta = metadata.get('html_path', '')
            if html_path_meta:
                # Try the path from metadata
                html_file = Path(html_path_meta)
                if not html_file.exists():
                    # Try relative to current directory
                    html_file = Path(html_path_meta.split('/')[-1])
                    html_file = html_dir / html_file
            else:
                # Try to find by domain name
                html_files = list(html_dir.glob(f"{registrable.replace('.', '_')}*.html"))
                html_file = html_files[0] if html_files else None

            if html_file and html_file.exists():
                # Extract features
                text_features = extractor.extract_features(str(html_file))
                with_html += 1
            else:
                # No HTML available
                text_features = {
                    'document_text': '',
                    'doc_length': 0,
                    'doc_form_count': 0,
                    'doc_has_verdict': False,
                    'doc_verdict': '',
                    'doc_risk_score': 0.0,
                    'doc_submit_buttons': '',
                    'doc_has_login_keywords': False,
                    'doc_has_verify_keywords': False,
                    'doc_has_password_keywords': False,
                    'doc_has_credential_keywords': False,
                }

            # Combine with original metadata
            output_data = {
                'id': domain_id,
                'metadata': {**metadata, **text_features},
                'document': domain_data.get('document', '')
            }

            out_f.write(json.dumps(output_data) + '\n')
            processed += 1

            if processed % 10 == 0:
                print(f"Processed {processed}/{len(domains)} domains...")

    print()
    print("="*70)
    print(f"✓ Extraction complete!")
    print(f"  Total domains: {processed}")
    print(f"  With HTML: {with_html}")
    print(f"  Without HTML: {processed - with_html}")
    print(f"  Output: {output_path}")
    print("="*70)


if __name__ == "__main__":
    main()
