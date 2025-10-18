#!/usr/bin/env python3
"""
Extract Comprehensive URL Features
Extracts URL-based features per Problem Statement Annexure A

Features extracted:
- URL length, subdomain depth, special character counts
- TLD analysis, IDN detection, typo-squatting patterns
- Entropy calculations, homograph detection
- Path/query analysis, suspicious patterns
"""

import json
import re
import math
from pathlib import Path
from typing import Dict, List, Set
from urllib.parse import urlparse, parse_qs
import argparse


class URLFeatureExtractor:
    """Extract comprehensive URL-based features for phishing detection"""

    def __init__(self):
        # High-risk TLDs commonly used in phishing
        self.high_risk_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
            'top', 'xyz', 'club', 'work', 'wang',  # Common in phishing
            'loan', 'zip', 'review', 'faith', 'science'
        }

        # Trusted TLDs (government, established)
        self.trusted_tlds = {
            'gov', 'edu', 'mil', 'gov.in', 'nic.in',
            'ac.in', 'edu.in', 'co.in'
        }

        # Phishing-related keywords
        self.phishing_keywords = {
            'verify', 'account', 'update', 'confirm', 'secure',
            'login', 'signin', 'banking', 'alert', 'suspended',
            'locked', 'unusual', 'click', 'urgent', 'password'
        }

        # Common CSE domain keywords (for typo detection)
        self.cse_keywords = {
            'bank', 'sbi', 'hdfc', 'icici', 'axis', 'kotak',
            'pnb', 'ubi', 'boi', 'canara', 'union',
            'govt', 'gov', 'uidai', 'npci', 'rbi',
            'ntpc', 'ongc', 'bhel', 'gail', 'powergrid',
            'airtel', 'bsnl', 'mtnl', 'railtel'
        }

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0

        # Count character frequencies
        frequencies = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        length = len(text)
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def is_idn(self, domain: str) -> bool:
        """Check if domain is Internationalized Domain Name (non-ASCII)"""
        try:
            # If domain contains non-ASCII or starts with 'xn--' (punycode)
            return not domain.isascii() or 'xn--' in domain
        except:
            return False

    def has_homograph_chars(self, domain: str) -> bool:
        """Check for common homograph characters (look-alike chars)"""
        # Common homograph patterns
        homographs = {
            '0': 'o',  # zero vs o
            '1': 'l',  # one vs L
            'rn': 'm',  # rn vs m
            'vv': 'w',  # vv vs w
        }

        domain_lower = domain.lower()
        for pattern in homographs.keys():
            if pattern in domain_lower:
                return True
        return False

    def count_special_chars(self, url: str) -> Dict[str, int]:
        """Count special characters in URL"""
        return {
            'dot_count': url.count('.'),
            'dash_count': url.count('-'),
            'underscore_count': url.count('_'),
            'at_count': url.count('@'),
            'slash_count': url.count('/'),
            'question_count': url.count('?'),
            'equal_count': url.count('='),
            'ampersand_count': url.count('&'),
            'digit_count': sum(1 for c in url if c.isdigit()),
        }

    def analyze_subdomain(self, domain: str) -> Dict:
        """Analyze subdomain structure"""
        parts = domain.split('.')

        # Get subdomain parts (everything except TLD and domain)
        subdomain_parts = parts[:-2] if len(parts) > 2 else []
        subdomain = '.'.join(subdomain_parts) if subdomain_parts else ''

        return {
            'subdomain_depth': len(subdomain_parts),
            'has_subdomain': len(subdomain_parts) > 0,
            'subdomain_length': len(subdomain),
            'subdomain_has_digits': any(c.isdigit() for c in subdomain),
            'subdomain_has_hyphen': '-' in subdomain,
        }

    def analyze_tld(self, domain: str) -> Dict:
        """Analyze TLD"""
        parts = domain.split('.')

        # Handle multi-part TLDs (like .co.in, .gov.in)
        if len(parts) >= 2:
            tld = '.'.join(parts[-2:]) if parts[-2] in {'co', 'gov', 'ac', 'edu', 'nic'} else parts[-1]
        else:
            tld = parts[-1] if parts else ''

        return {
            'tld': tld,
            'tld_length': len(tld),
            'is_high_risk_tld': tld in self.high_risk_tlds,
            'is_trusted_tld': tld in self.trusted_tlds,
            'is_numeric_tld': tld.isdigit(),
        }

    def analyze_path(self, parsed_url) -> Dict:
        """Analyze URL path"""
        path = parsed_url.path
        query = parsed_url.query

        return {
            'path_length': len(path),
            'path_depth': len([p for p in path.split('/') if p]),
            'has_query': len(query) > 0,
            'query_length': len(query),
            'query_param_count': len(parse_qs(query)),
            'path_has_phishing_keyword': any(kw in path.lower() for kw in self.phishing_keywords),
        }

    def detect_typosquatting_pattern(self, domain: str, registrable: str) -> Dict:
        """Detect potential typo-squatting patterns"""
        domain_lower = domain.lower()
        registrable_lower = registrable.lower()

        # Check for CSE keyword usage
        has_cse_keyword = any(kw in domain_lower for kw in self.cse_keywords)

        # Check for common typo patterns
        has_double_chars = bool(re.search(r'(.)\1{2,}', domain_lower))  # Triple+ repeated chars
        has_char_substitution = self.has_homograph_chars(domain)

        # Check for suspicious additions
        has_hyphen_variant = '-' in registrable_lower and registrable_lower.count('-') > 2

        return {
            'has_cse_keyword': has_cse_keyword,
            'has_typo_pattern': has_double_chars or has_char_substitution,
            'has_suspicious_hyphen': has_hyphen_variant,
        }

    def extract_features(self, url: str, registrable: str) -> Dict:
        """
        Extract all URL-based features

        Args:
            url: Full URL (e.g., https://www.example.com/path?query=1)
            registrable: Registrable domain (e.g., example.com)

        Returns:
            Dictionary with all URL features
        """
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            domain = parsed.netloc or registrable

            # Basic URL features
            url_features = {
                'url_length': len(url),
                'domain_length': len(domain),
                'registrable_length': len(registrable),
            }

            # Special character counts
            url_features.update(self.count_special_chars(url))

            # Subdomain analysis
            url_features.update(self.analyze_subdomain(domain))

            # TLD analysis
            url_features.update(self.analyze_tld(domain))

            # Path and query analysis
            url_features.update(self.analyze_path(parsed))

            # Entropy
            url_features['url_entropy'] = self.calculate_entropy(url)
            url_features['domain_entropy'] = self.calculate_entropy(domain)

            # IDN and homograph detection
            url_features['is_idn'] = self.is_idn(domain)
            url_features['has_homograph'] = self.has_homograph_chars(domain)

            # Typo-squatting patterns
            url_features.update(self.detect_typosquatting_pattern(domain, registrable))

            # Phishing keyword detection
            url_features['url_has_phishing_keyword'] = any(
                kw in url.lower() for kw in self.phishing_keywords
            )

            # IP address detection
            url_features['is_ip_address'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))

            # Port number detection
            url_features['has_custom_port'] = ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443')

            return url_features

        except Exception as e:
            print(f"Error extracting URL features from {url}: {e}")
            return self._get_empty_features()

    def _get_empty_features(self) -> Dict:
        """Return empty/default feature values"""
        return {
            'url_length': 0,
            'domain_length': 0,
            'registrable_length': 0,
            'dot_count': 0,
            'dash_count': 0,
            'underscore_count': 0,
            'at_count': 0,
            'slash_count': 0,
            'question_count': 0,
            'equal_count': 0,
            'ampersand_count': 0,
            'digit_count': 0,
            'subdomain_depth': 0,
            'has_subdomain': False,
            'subdomain_length': 0,
            'subdomain_has_digits': False,
            'subdomain_has_hyphen': False,
            'tld': '',
            'tld_length': 0,
            'is_high_risk_tld': False,
            'is_trusted_tld': False,
            'is_numeric_tld': False,
            'path_length': 0,
            'path_depth': 0,
            'has_query': False,
            'query_length': 0,
            'query_param_count': 0,
            'path_has_phishing_keyword': False,
            'url_entropy': 0.0,
            'domain_entropy': 0.0,
            'is_idn': False,
            'has_homograph': False,
            'has_cse_keyword': False,
            'has_typo_pattern': False,
            'has_suspicious_hyphen': False,
            'url_has_phishing_keyword': False,
            'is_ip_address': False,
            'has_custom_port': False,
        }


def main():
    parser = argparse.ArgumentParser(description='Extract URL features for phishing detection')
    parser.add_argument('--jsonl', default='AIML/data/text_and_visual_features.jsonl',
                       help='Input JSONL with domain data')
    parser.add_argument('--output', default='AIML/data/complete_features.jsonl',
                       help='Output JSONL with all features')
    args = parser.parse_args()

    extractor = URLFeatureExtractor()

    print("="*70)
    print("URL FEATURE EXTRACTION")
    print("="*70)
    print(f"Input JSONL: {args.jsonl}")
    print(f"Output: {args.output}")
    print()

    # Load domains
    print("Loading domains...")
    domains = []
    with open(args.jsonl, 'r') as f:
        for line in f:
            domains.append(json.loads(line))

    print(f"Found {len(domains)} domains")

    # Process each domain
    results = []
    for idx, domain_data in enumerate(domains):
        domain_id = domain_data['id']
        metadata = domain_data['metadata']
        registrable = metadata.get('registrable', '')

        # Try to get full URL from document or construct from registrable
        url = domain_data.get('document', '').strip()
        if not url:
            url = f"https://{registrable}"

        # Extract URL features
        url_features = extractor.extract_features(url, registrable)

        # Merge with existing metadata
        metadata_enriched = {**metadata, **url_features}

        results.append({
            'id': domain_id,
            'metadata': metadata_enriched,
            'document': domain_data.get('document', '')
        })

        # Progress
        if (idx + 1) % 10 == 0:
            print(f"  Processed {idx + 1}/{len(domains)} domains...")

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        for result in results:
            f.write(json.dumps(result) + '\n')

    print()
    print("="*70)
    print("✓ URL feature extraction complete!")
    print(f"  Total domains: {len(results)}")
    print(f"  Output: {output_path}")

    # Statistics
    idn_count = sum(1 for r in results if r['metadata'].get('is_idn', False))
    high_risk_tld_count = sum(1 for r in results if r['metadata'].get('is_high_risk_tld', False))
    trusted_tld_count = sum(1 for r in results if r['metadata'].get('is_trusted_tld', False))
    cse_keyword_count = sum(1 for r in results if r['metadata'].get('has_cse_keyword', False))

    print(f"\nURL Feature Summary:")
    print(f"  IDN domains: {idn_count}")
    print(f"  High-risk TLD: {high_risk_tld_count}")
    print(f"  Trusted TLD: {trusted_tld_count}")
    print(f"  CSE keywords: {cse_keyword_count}")
    print("="*70)


if __name__ == "__main__":
    main()
