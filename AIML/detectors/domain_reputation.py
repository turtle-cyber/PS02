#!/usr/bin/env python3
"""
Domain Reputation Analyzer

Analyzes domain characteristics for phishing indicators:
- Typo-squatting detection
- IDN homograph detection
- TLD risk analysis
- Domain age and patterns
"""

import re
import json
from typing import Dict, List, Set, Tuple
from pathlib import Path
import difflib


class DomainReputationAnalyzer:
    """Analyze domain reputation based on URL patterns"""

    def __init__(self, cse_whitelist: List[str] = None):
        """
        Initialize analyzer

        Args:
            cse_whitelist: List of legitimate CSE domains
        """
        self.cse_whitelist = cse_whitelist or []

        # High-risk TLDs
        self.high_risk_tlds = {
            'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs
            'top', 'xyz', 'club', 'work', 'wang',
            'loan', 'zip', 'review', 'faith', 'science',
            'cricket', 'download', 'racing', 'webcam'
        }

        # Trusted TLDs
        self.trusted_tlds = {
            'gov', 'edu', 'mil',
            'gov.in', 'nic.in', 'ac.in', 'edu.in', 'co.in',
            'org', 'com', 'net'  # Common but need other checks
        }

        # Homograph character mappings (lookalike chars)
        self.homograph_pairs = {
            'a': ['а', 'ɑ', 'α'],  # Cyrillic/Greek a
            'e': ['е', 'ė', 'ē'],  # Cyrillic e
            'o': ['о', 'ο', '0'],  # Cyrillic o, zero
            'p': ['р', 'ρ'],       # Cyrillic p
            'c': ['с', 'ϲ'],       # Cyrillic c
            'i': ['і', 'ı', 'l', '1'],  # Cyrillic i, lowercase L, one
            'x': ['х', 'χ'],       # Cyrillic x
            'y': ['у', 'ү'],       # Cyrillic y
        }

    def load_cse_whitelist(self, baseline_path: str):
        """Load CSE whitelist from baseline profile"""
        with open(baseline_path, 'r') as f:
            baseline = json.load(f)
        self.cse_whitelist = baseline.get('cse_whitelist', [])
        print(f"Loaded CSE whitelist: {len(self.cse_whitelist)} domains")

    def calculate_edit_distance(self, str1: str, str2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        return difflib.SequenceMatcher(None, str1, str2).ratio()

    def detect_typosquatting(self, target_domain: str) -> Tuple[bool, Dict]:
        """
        Detect if target domain is typo-squatting a CSE domain

        Checks for:
        - Character substitution (o→0, i→l, etc.)
        - Character insertion/deletion
        - Character transposition
        - Similar-looking domains

        Args:
            target_domain: Domain to check

        Returns:
            (is_typosquatting, details)
        """
        if not self.cse_whitelist:
            return False, {'reason': 'No CSE whitelist available'}

        target_lower = target_domain.lower()
        closest_match = None
        highest_similarity = 0.0
        typo_type = None

        for cse_domain in self.cse_whitelist:
            cse_lower = cse_domain.lower()

            # Exact match - not typosquatting
            if target_lower == cse_lower:
                return False, {'reason': 'Exact match with CSE domain'}

            # Calculate similarity
            similarity = self.calculate_edit_distance(target_lower, cse_lower)

            if similarity > highest_similarity:
                highest_similarity = similarity
                closest_match = cse_domain

            # Check for specific typo patterns
            # 1. Single character substitution
            if len(target_lower) == len(cse_lower):
                diff_count = sum(1 for a, b in zip(target_lower, cse_lower) if a != b)
                if diff_count == 1:
                    typo_type = 'single_char_substitution'
                    break

            # 2. Single character insertion/deletion
            if abs(len(target_lower) - len(cse_lower)) == 1:
                longer = target_lower if len(target_lower) > len(cse_lower) else cse_lower
                shorter = cse_lower if len(target_lower) > len(cse_lower) else target_lower

                # Try removing each character from longer string
                for i in range(len(longer)):
                    if longer[:i] + longer[i+1:] == shorter:
                        typo_type = 'char_insertion' if target_lower == longer else 'char_deletion'
                        break

            # 3. Hyphen/underscore variants
            if target_lower.replace('-', '') == cse_lower.replace('-', ''):
                typo_type = 'hyphen_variant'

            if target_lower.replace('_', '') == cse_lower.replace('_', ''):
                typo_type = 'underscore_variant'

        # Determine if it's typosquatting
        is_typosquatting = False

        if typo_type:
            is_typosquatting = True
        elif highest_similarity > 0.85:  # Very similar (85%+)
            is_typosquatting = True
            typo_type = 'high_similarity'

        return is_typosquatting, {
            'is_typosquatting': is_typosquatting,
            'typo_type': typo_type,
            'closest_cse_match': closest_match,
            'similarity_score': highest_similarity,
            'threshold': 0.85
        }

    def detect_idn_homograph(self, domain: str) -> Tuple[bool, Dict]:
        """
        Detect IDN homograph attacks

        Args:
            domain: Domain to check

        Returns:
            (is_homograph_attack, details)
        """
        # Check if domain is IDN (non-ASCII or punycode)
        is_idn = not domain.isascii() or 'xn--' in domain

        # Check for homograph characters
        has_homograph = False
        suspicious_chars = []

        for char in domain.lower():
            for latin_char, lookalikes in self.homograph_pairs.items():
                if char in lookalikes:
                    has_homograph = True
                    suspicious_chars.append((char, latin_char))

        # Check if it might be impersonating a CSE domain
        impersonation_target = None
        if has_homograph or is_idn:
            # Convert lookalikes to ASCII equivalent
            normalized = domain.lower()
            for char, latin_char in suspicious_chars:
                normalized = normalized.replace(char, latin_char)

            # Check against CSE whitelist
            for cse_domain in self.cse_whitelist:
                if normalized == cse_domain.lower():
                    impersonation_target = cse_domain
                    break

        is_attack = (has_homograph or is_idn) and impersonation_target is not None

        return is_attack, {
            'is_idn': is_idn,
            'has_homograph_chars': has_homograph,
            'suspicious_chars': suspicious_chars,
            'impersonation_target': impersonation_target,
            'is_homograph_attack': is_attack
        }

    def analyze_tld_risk(self, domain: str) -> Dict:
        """Analyze TLD risk"""
        parts = domain.split('.')

        # Extract TLD
        if len(parts) >= 2:
            tld = '.'.join(parts[-2:]) if parts[-2] in {'co', 'gov', 'ac', 'edu', 'nic'} else parts[-1]
        else:
            tld = parts[-1] if parts else ''

        is_high_risk = tld in self.high_risk_tlds
        is_trusted = tld in self.trusted_tlds

        # Calculate risk score
        if is_high_risk:
            risk_score = 0.7
            risk_level = 'HIGH'
        elif is_trusted:
            risk_score = 0.1
            risk_level = 'LOW'
        else:
            risk_score = 0.3
            risk_level = 'MEDIUM'

        return {
            'tld': tld,
            'is_high_risk_tld': is_high_risk,
            'is_trusted_tld': is_trusted,
            'tld_risk_score': risk_score,
            'tld_risk_level': risk_level
        }

    def analyze_domain_patterns(self, domain: str, metadata: Dict) -> Dict:
        """Analyze suspicious domain patterns"""
        domain_lower = domain.lower()

        # Check for IP address as domain
        is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain))

        # Excessive hyphens/numbers
        hyphen_count = domain.count('-')
        digit_count = sum(1 for c in domain if c.isdigit())
        domain_length = len(domain)

        excessive_hyphens = hyphen_count > 3
        excessive_digits = digit_count > 5

        # Suspicious subdomain patterns
        subdomain_depth = metadata.get('subdomain_depth', 0)
        excessive_subdomains = subdomain_depth > 3

        # Calculate pattern risk
        pattern_risk = 0.0
        risk_factors = []

        if is_ip:
            pattern_risk += 0.8
            risk_factors.append('IP address as domain')

        if excessive_hyphens:
            pattern_risk += 0.3
            risk_factors.append(f'Excessive hyphens ({hyphen_count})')

        if excessive_digits:
            pattern_risk += 0.2
            risk_factors.append(f'Excessive digits ({digit_count})')

        if excessive_subdomains:
            pattern_risk += 0.3
            risk_factors.append(f'Deep subdomain ({subdomain_depth})')

        return {
            'is_ip_address': is_ip,
            'excessive_hyphens': excessive_hyphens,
            'excessive_digits': excessive_digits,
            'excessive_subdomains': excessive_subdomains,
            'pattern_risk_score': min(1.0, pattern_risk),
            'pattern_risk_factors': risk_factors
        }

    def analyze_reputation(self, domain: str, metadata: Dict) -> Dict:
        """
        Complete domain reputation analysis

        Args:
            domain: Registrable domain
            metadata: Domain metadata with features

        Returns:
            Reputation analysis result
        """
        # Typo-squatting detection
        is_typosquatting, typo_details = self.detect_typosquatting(domain)

        # IDN homograph detection
        is_homograph, homograph_details = self.detect_idn_homograph(domain)

        # TLD risk analysis
        tld_analysis = self.analyze_tld_risk(domain)

        # Domain pattern analysis
        pattern_analysis = self.analyze_domain_patterns(domain, metadata)

        # Calculate overall reputation risk
        risk_score = 0.0

        if is_typosquatting:
            risk_score += 0.6
        if is_homograph:
            risk_score += 0.7
        risk_score += tld_analysis['tld_risk_score'] * 0.3
        risk_score += pattern_analysis['pattern_risk_score'] * 0.4

        risk_score = min(1.0, risk_score)

        # Determine verdict
        if risk_score >= 0.7:
            verdict = 'MALICIOUS'
            confidence = 0.8 + risk_score * 0.15
        elif risk_score >= 0.4:
            verdict = 'SUSPICIOUS'
            confidence = 0.5 + risk_score * 0.2
        else:
            verdict = 'BENIGN'
            confidence = max(0.3, 1.0 - risk_score)

        return {
            'verdict': verdict,
            'confidence': confidence,
            'risk_score': risk_score,
            'details': {
                **typo_details,
                **homograph_details,
                **tld_analysis,
                **pattern_analysis
            }
        }

    def batch_analyze(self, domains_with_metadata: List[Tuple[str, Dict]]) -> List[Dict]:
        """Analyze multiple domains"""
        results = []
        for domain, metadata in domains_with_metadata:
            result = self.analyze_reputation(domain, metadata)
            result['registrable'] = domain
            results.append(result)
        return results

    def generate_report(self, results: List[Dict]) -> str:
        """Generate reputation analysis report"""
        report = []
        report.append("="*70)
        report.append("DOMAIN REPUTATION ANALYSIS REPORT")
        report.append("="*70)

        malicious_count = sum(1 for r in results if r['verdict'] == 'MALICIOUS')
        suspicious_count = sum(1 for r in results if r['verdict'] == 'SUSPICIOUS')
        benign_count = sum(1 for r in results if r['verdict'] == 'BENIGN')

        report.append(f"\nSummary:")
        report.append(f"  Total domains: {len(results)}")
        report.append(f"  Malicious: {malicious_count}")
        report.append(f"  Suspicious: {suspicious_count}")
        report.append(f"  Benign: {benign_count}")

        # Typo-squatting detections
        typosquatting = [r for r in results if r['details'].get('is_typosquatting')]
        if typosquatting:
            report.append(f"\nTypo-squatting Detections ({len(typosquatting)}):")
            for r in typosquatting[:5]:
                report.append(f"  - {r['registrable']}")
                report.append(f"    Target: {r['details']['closest_cse_match']}")
                report.append(f"    Type: {r['details']['typo_type']}")
                report.append(f"    Similarity: {r['details']['similarity_score']:.2f}")

        # IDN homograph attacks
        homographs = [r for r in results if r['details'].get('is_homograph_attack')]
        if homographs:
            report.append(f"\nIDN Homograph Attacks ({len(homographs)}):")
            for r in homographs:
                report.append(f"  - {r['registrable']}")
                report.append(f"    Target: {r['details']['impersonation_target']}")

        report.append("="*70)
        return "\n".join(report)


def main():
    """Example usage and testing"""
    import argparse

    parser = argparse.ArgumentParser(description='Domain reputation analyzer')
    parser.add_argument('--baseline', default='AIML/data/training/cse_baseline_profile.json',
                       help='CSE baseline profile JSON')
    parser.add_argument('--test-jsonl', help='JSONL file with domains to test')
    args = parser.parse_args()

    # Initialize analyzer
    print("Initializing Domain Reputation Analyzer...")
    analyzer = DomainReputationAnalyzer()

    if args.baseline:
        analyzer.load_cse_whitelist(args.baseline)

    if args.test_jsonl:
        # Test on domains
        print(f"\nTesting on domains from {args.test_jsonl}...")

        domains_with_metadata = []
        with open(args.test_jsonl, 'r') as f:
            for line in f:
                data = json.loads(line)
                domain = data['metadata'].get('registrable', '')
                if domain:
                    domains_with_metadata.append((domain, data['metadata']))

        results = analyzer.batch_analyze(domains_with_metadata)
        print(analyzer.generate_report(results))

        # Save results
        output_file = 'AIML/data/reputation_analysis_results.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✓ Results saved to {output_file}")

    else:
        # Demo mode
        print("\nDemo mode: Testing reputation analyzer")
        print("=" * 70)

        test_metadata = {'subdomain_depth': 0}

        # Test 1: Normal domain
        result = analyzer.analyze_reputation('google.com', test_metadata)
        print(f"\nTest 1: google.com")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Risk Score: {result['risk_score']:.2f}")

        # Test 2: High-risk TLD
        result = analyzer.analyze_reputation('phishing.tk', test_metadata)
        print(f"\nTest 2: phishing.tk (high-risk TLD)")
        print(f"  Verdict: {result['verdict']}")
        print(f"  Risk Score: {result['risk_score']:.2f}")


if __name__ == "__main__":
    main()
