#!/usr/bin/env python3
"""
Content-Based Phishing Detector

Detects phishing based on page content analysis:
- Credential harvesting forms
- Phishing keywords and urgency language
- Suspicious button/link text
- Content risk patterns
"""

import re
import json
from typing import Dict, List, Set
from pathlib import Path


class ContentPhishingDetector:
    """Detect phishing based on HTML/OCR content analysis"""

    def __init__(self):
        """Initialize detector with keyword databases"""

        # Credential-related keywords (high risk)
        self.credential_keywords = {
            'password', 'passwd', 'pwd', 'passphrase',
            'username', 'user name', 'userid', 'user id',
            'login', 'log in', 'signin', 'sign in',
            'account', 'email', 'e-mail',
            'credit card', 'debit card', 'card number',
            'cvv', 'cvc', 'expiry', 'expiration',
            'ssn', 'social security', 'pan', 'aadhar', 'aadhaar',
            'otp', 'one time password', 'verification code',
            'pin', 'security code', 'secret code'
        }

        # Verification/urgency keywords (medium risk)
        self.urgency_keywords = {
            'verify', 'verification', 'confirm', 'confirmation',
            'update', 'renew', 'renewal', 'validate', 'validation',
            'suspended', 'suspend', 'locked', 'lock', 'freeze',
            'unusual', 'suspicious', 'unauthorized', 'compromised',
            'urgent', 'immediately', 'within 24 hours', 'expire',
            'limited time', 'act now', 'click here', 'click below',
            'alert', 'warning', 'notice', 'important',
            'restore', 'reactivate', 'secure', 'protect'
        }

        # Financial keywords
        self.financial_keywords = {
            'bank', 'banking', 'account balance', 'transaction',
            'payment', 'refund', 'deposit', 'withdraw',
            'transfer', 'wire', 'credit', 'debit',
            'loan', 'mortgage', 'insurance', 'investment',
            'tax', 'irs', 'income tax', 'refund'
        }

        # Scam-related keywords
        self.scam_keywords = {
            'congratulations', 'winner', 'won', 'prize', 'lottery',
            'free', 'gift', 'reward', 'claim', 'unclaimed',
            'inheritance', 'beneficiary', 'million', 'billion',
            'prince', 'nigeria', 'fund transfer',
            'click here to claim', 'act fast', 'limited offer'
        }

        # CSE-specific impersonation keywords
        self.cse_impersonation_keywords = {
            'state bank', 'sbi', 'hdfc', 'icici', 'axis',
            'reserve bank', 'rbi', 'npci', 'uidai', 'aadhaar',
            'income tax', 'tax department', 'government of india',
            'digital india', 'mygov', 'digilocker',
            'ntpc', 'ongc', 'bhel', 'gail', 'powergrid'
        }

        # Gambling-related keywords (specific to avoid false positives)
        self.gambling_keywords = {
            # Casinos (specific phrases)
            'online casino', 'live casino', 'casino online',
            'play casino', 'casino games', 'casino bonus',

            # Slot machines
            'slot machine', 'slot machines', 'slots game',
            'jackpot', 'mega jackpot', 'progressive jackpot',

            # Card games (specific)
            'online poker', 'texas holdem', 'live poker',
            'play blackjack', 'live blackjack',
            'baccarat online', 'roulette online',

            # Betting (specific to avoid 'bet' matching 'better')
            'place your bet', 'online betting', 'sports betting',
            'sportsbook', 'bookmaker', 'betting odds',

            # Gambling explicit
            'gambling site', 'online gambling', 'gamble online',
            'real money gambling',

            # Lottery (specific)
            'lottery online', 'buy lottery', 'lottery tickets',
            'powerball', 'mega millions',

            # Gaming terms (multi-word to reduce false positives)
            'spin to win', 'free spins', 'bonus spins',
            'deposit bonus', 'welcome bonus', 'no deposit bonus',
            'play for real money', 'real money casino',

            # Winnings (specific phrases)
            'withdraw winnings', 'cash out winnings',
            'instant payout', 'fast withdrawal',

            # Licenses (gambling-specific)
            'curacao gaming license', 'malta gaming authority',
            'gambling license', 'casino license'
        }

    def count_keywords(self, text: str, keywords: Set[str]) -> int:
        """Count keyword occurrences in text (case-insensitive)"""
        if not text:
            return 0

        text_lower = text.lower()
        count = 0
        for keyword in keywords:
            count += text_lower.count(keyword)
        return count

    def has_keywords(self, text: str, keywords: Set[str], threshold: int = 1) -> bool:
        """Check if text contains keywords above threshold"""
        return self.count_keywords(text, keywords) >= threshold

    def analyze_forms(self, form_count: int, doc_text: str) -> Dict:
        """
        Analyze forms for credential harvesting

        Args:
            form_count: Number of forms on page
            doc_text: HTML/document text

        Returns:
            Form analysis results
        """
        if form_count == 0:
            return {
                'has_forms': False,
                'form_risk': 'NONE',
                'form_score': 0.0
            }

        # Check for credential fields in form context
        has_password_field = 'password' in doc_text.lower() or 'passwd' in doc_text.lower()
        has_login_field = any(kw in doc_text.lower() for kw in ['username', 'email', 'user id'])
        has_financial_field = any(kw in doc_text.lower() for kw in ['card number', 'cvv', 'account number'])

        # Risk scoring
        if has_password_field and has_login_field:
            risk = 'HIGH'
            score = 0.8
        elif has_financial_field:
            risk = 'HIGH'
            score = 0.7
        elif has_password_field or has_login_field:
            risk = 'MEDIUM'
            score = 0.5
        elif form_count > 3:
            risk = 'MEDIUM'
            score = 0.4
        else:
            risk = 'LOW'
            score = 0.2

        return {
            'has_forms': True,
            'form_count': form_count,
            'has_password_field': has_password_field,
            'has_login_field': has_login_field,
            'has_financial_field': has_financial_field,
            'form_risk': risk,
            'form_score': score
        }

    def analyze_content(self, doc_text: str, ocr_text: str = "") -> Dict:
        """
        Analyze page content for phishing indicators

        Args:
            doc_text: HTML document text
            ocr_text: OCR text from screenshot

        Returns:
            Content analysis results
        """
        combined_text = f"{doc_text} {ocr_text}"

        # Keyword counts
        credential_count = self.count_keywords(combined_text, self.credential_keywords)
        urgency_count = self.count_keywords(combined_text, self.urgency_keywords)
        financial_count = self.count_keywords(combined_text, self.financial_keywords)
        scam_count = self.count_keywords(combined_text, self.scam_keywords)
        cse_count = self.count_keywords(combined_text, self.cse_impersonation_keywords)

        # Calculate risk score
        risk_score = 0.0
        risk_factors = []

        if credential_count >= 3:
            risk_score += 0.3
            risk_factors.append(f"High credential keywords ({credential_count})")

        if urgency_count >= 2:
            risk_score += 0.2
            risk_factors.append(f"Urgency language ({urgency_count})")

        if scam_count >= 1:
            risk_score += 0.3
            risk_factors.append(f"Scam keywords ({scam_count})")

        if cse_count >= 2:
            risk_score += 0.2
            risk_factors.append(f"CSE impersonation ({cse_count})")

        # Check for suspicious patterns
        has_fake_url = bool(re.search(r'http[s]?://[^\s]+\.(tk|ml|ga|cf|gq)', combined_text.lower()))
        if has_fake_url:
            risk_score += 0.2
            risk_factors.append("Suspicious URL in content")

        return {
            'credential_keyword_count': credential_count,
            'urgency_keyword_count': urgency_count,
            'financial_keyword_count': financial_count,
            'scam_keyword_count': scam_count,
            'cse_keyword_count': cse_count,
            'content_risk_score': min(1.0, risk_score),
            'risk_factors': risk_factors
        }

    def detect_gambling(self, domain_metadata: Dict) -> Dict:
        """
        Detect gambling content in domain

        Args:
            domain_metadata: Dictionary with domain metadata

        Returns:
            Gambling detection verdict
        """
        doc_text = domain_metadata.get('document_text', '')
        ocr_text = domain_metadata.get('ocr_text', '')
        domain = domain_metadata.get('registrable', '')

        combined_text = f"{doc_text} {ocr_text} {domain}".lower()

        # Count gambling keywords
        gambling_count = self.count_keywords(combined_text, self.gambling_keywords)

        # Check for gambling TLDs
        gambling_tlds = ['.bet', '.casino', '.poker', '.lotto', '.game']
        has_gambling_tld = any(domain.lower().endswith(tld) for tld in gambling_tlds)

        # High confidence gambling detection
        # Increased threshold to reduce false positives (was 5, now 10)
        if gambling_count >= 10 or has_gambling_tld:
            return {
                'verdict': 'GAMBLING',
                'confidence': min(0.95, 0.80 + min(0.15, gambling_count * 0.02)),
                'reason': f'Gambling site detected ({gambling_count} gambling keywords)',
                'gambling_keyword_count': gambling_count,
                'has_gambling_tld': has_gambling_tld
            }

        # Moderate confidence - suspicious gambling
        # Increased threshold (was 2, now 5)
        elif gambling_count >= 5:
            return {
                'verdict': 'SUSPICIOUS_GAMBLING',
                'confidence': 0.60 + min(0.20, gambling_count * 0.05),
                'reason': f'Possible gambling content ({gambling_count} keywords)',
                'gambling_keyword_count': gambling_count,
                'has_gambling_tld': has_gambling_tld
            }

        # Not gambling
        return {
            'verdict': 'NOT_GAMBLING',
            'confidence': 0.0,
            'gambling_keyword_count': gambling_count,
            'has_gambling_tld': has_gambling_tld
        }

    def detect_phishing(self, domain_metadata: Dict) -> Dict:
        """
        Detect phishing based on content analysis

        Args:
            domain_metadata: Dictionary with domain metadata including:
                - document_text, ocr_text
                - doc_form_count
                - doc_has_login_keywords, etc.

        Returns:
            Detection verdict and details
        """
        # Extract features
        doc_text = domain_metadata.get('document_text', '')
        ocr_text = domain_metadata.get('ocr_text', '')
        form_count = domain_metadata.get('doc_form_count', 0)

        # Analyze forms
        form_analysis = self.analyze_forms(form_count, doc_text)

        # Analyze content
        content_analysis = self.analyze_content(doc_text, ocr_text)

        # Calculate overall risk
        overall_risk = (form_analysis['form_score'] * 0.6 +
                       content_analysis['content_risk_score'] * 0.4)

        # Determine verdict
        if overall_risk >= 0.7:
            verdict = 'PHISHING'
            confidence = min(0.95, 0.6 + overall_risk * 0.3)
            reason = 'High-risk content detected'
        elif overall_risk >= 0.4:
            verdict = 'SUSPICIOUS'
            confidence = 0.5 + overall_risk * 0.2
            reason = 'Moderate risk content'
        else:
            verdict = 'BENIGN'
            confidence = max(0.3, 1.0 - overall_risk)
            reason = 'Low-risk content'

        return {
            'verdict': verdict,
            'confidence': confidence,
            'reason': reason,
            'risk_score': overall_risk,
            'details': {
                **form_analysis,
                **content_analysis
            }
        }

    def batch_detect(self, domains_metadata: List[Dict]) -> List[Dict]:
        """Detect phishing for multiple domains"""
        results = []
        for metadata in domains_metadata:
            result = self.detect_phishing(metadata)
            result['registrable'] = metadata.get('registrable', 'unknown')
            results.append(result)
        return results

    def generate_report(self, results: List[Dict]) -> str:
        """Generate detection report"""
        report = []
        report.append("="*70)
        report.append("CONTENT-BASED PHISHING DETECTION REPORT")
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
                    report.append(f"  - {r['registrable']}")
                    report.append(f"    Confidence: {r['confidence']:.2f}")
                    report.append(f"    Risk Score: {r['risk_score']:.2f}")
                    if r['details'].get('risk_factors'):
                        report.append(f"    Factors: {', '.join(r['details']['risk_factors'])}")

        if suspicious_count > 0:
            report.append(f"\nSuspicious Detections:")
            for r in results:
                if r['verdict'] == 'SUSPICIOUS':
                    report.append(f"  - {r['registrable']}")
                    report.append(f"    Risk Score: {r['risk_score']:.2f}")

        report.append("="*70)
        return "\n".join(report)


def main():
    """Example usage and testing"""
    import argparse

    parser = argparse.ArgumentParser(description='Content-based phishing detector')
    parser.add_argument('--test-jsonl', help='JSONL file with domains to test')
    args = parser.parse_args()

    # Initialize detector
    print("Initializing Content Phishing Detector...")
    detector = ContentPhishingDetector()

    if args.test_jsonl:
        # Test on domains from JSONL
        print(f"\nTesting on domains from {args.test_jsonl}...")

        domains_metadata = []
        with open(args.test_jsonl, 'r') as f:
            for line in f:
                data = json.loads(line)
                domains_metadata.append(data['metadata'])

        results = detector.batch_detect(domains_metadata)
        print(detector.generate_report(results))

        # Save results
        output_file = 'AIML/data/content_detection_results.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n✓ Results saved to {output_file}")

    else:
        # Demo mode
        print("\nDemo mode: Testing content detector")
        print("=" * 70)

        # Test case 1: Phishing page with credential form
        test1 = {
            'document_text': 'Urgent: Your account has been suspended. Please verify your password and username immediately to restore access.',
            'doc_form_count': 1,
            'ocr_text': 'Login Password Username Verify Account',
            'registrable': 'test-phishing.com'
        }

        result1 = detector.detect_phishing(test1)
        print(f"\nTest 1: Phishing with credential form")
        print(f"  Verdict: {result1['verdict']}")
        print(f"  Confidence: {result1['confidence']:.2f}")
        print(f"  Risk Score: {result1['risk_score']:.2f}")
        print(f"  Factors: {', '.join(result1['details'].get('risk_factors', []))}")

        # Test case 2: Benign page
        test2 = {
            'document_text': 'Welcome to our website. Learn more about our services and contact us for information.',
            'doc_form_count': 1,
            'ocr_text': 'Contact Us Name Email Message',
            'registrable': 'legitimate-site.com'
        }

        result2 = detector.detect_phishing(test2)
        print(f"\nTest 2: Benign contact form")
        print(f"  Verdict: {result2['verdict']}")
        print(f"  Confidence: {result2['confidence']:.2f}")
        print(f"  Risk Score: {result2['risk_score']:.2f}")


if __name__ == "__main__":
    main()
