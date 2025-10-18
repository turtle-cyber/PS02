"""
Content-Based Risk Classifier for Non-CSE Threats

Detects:
- Generic phishing (PayPal, Google, crypto, etc.)
- Gambling/casino sites
- Malware distribution
- Adult content
- Cryptocurrency scams
"""

import re
from typing import Dict, List, Tuple, Optional


class ContentRiskClassifier:
    """Classify domains based on content patterns (not CSE-specific)"""

    def __init__(self):
        # Phishing keywords (credential harvesting)
        self.phishing_keywords = {
            'credential_harvest': [
                'login', 'signin', 'sign-in', 'password', 'verify', 'account',
                'suspended', 'confirm', 'secure', 'update', 'authenticate'
            ],
            'urgency': [
                'urgent', 'immediate', 'expire', 'suspended', 'limited time',
                'act now', 'verify now', 'confirm now', 'warning', 'alert'
            ],
            'financial': [
                'bank', 'credit card', 'payment', 'transaction', 'wallet',
                'paypal', 'stripe', 'billing', 'invoice', 'refund'
            ],
            'crypto': [
                'bitcoin', 'ethereum', 'crypto', 'cryptocurrency', 'btc', 'eth',
                'wallet', 'giveaway', 'airdrop', 'tokens', 'blockchain'
            ]
        }

        # Gambling keywords
        self.gambling_keywords = [
            'casino', 'betting', 'poker', 'slots', 'jackpot', 'roulette',
            'blackjack', 'gamble', 'wager', 'bet', 'odds', 'bookmaker',
            'sportsbook', 'lottery', 'scratch card', 'baccarat'
        ]

        # Adult content keywords (basic detection)
        self.adult_keywords = [
            'adult', 'xxx', 'porn', 'sex', 'escort', 'dating',
            'webcam', 'nude', 'nsfw'
        ]

        # Malware/suspicious JS indicators
        self.malware_indicators = [
            'download exe', 'install now', 'flash player', 'codec required',
            'update required', 'plugin missing', 'click allow', 'enable notifications'
        ]

    def calculate_keyword_score(self, text: str, keywords: List[str]) -> Tuple[int, List[str]]:
        """
        Count keyword matches in text

        Returns:
            (match_count, matched_keywords)
        """
        if not text:
            return (0, [])

        text_lower = text.lower()
        matches = []

        for keyword in keywords:
            if keyword in text_lower:
                matches.append(keyword)

        return (len(matches), matches)

    def check_phishing_patterns(self, features: Dict) -> Optional[Dict]:
        """Detect generic phishing patterns"""
        if not features:
            return None

        risk_score = 0
        indicators = []
        category = 'PHISHING_GENERIC'

        # Get content fields
        doc_text = (features.get('document_text', '') or '').lower()
        ocr_text = (features.get('ocr_text', '') or '').lower()
        combined_text = f"{doc_text} {ocr_text}"

        # 1. Credential harvesting patterns
        has_credential_form = features.get('has_credential_form', False)
        password_fields = features.get('password_fields', 0) or 0
        email_fields = features.get('email_fields', 0) or 0

        if has_credential_form or password_fields > 0:
            # Check for credential + urgency keywords
            cred_score, cred_matches = self.calculate_keyword_score(
                combined_text, self.phishing_keywords['credential_harvest']
            )
            urgency_score, urgency_matches = self.calculate_keyword_score(
                combined_text, self.phishing_keywords['urgency']
            )

            if cred_score >= 2 and urgency_score >= 1:
                risk_score += 4
                indicators.append(f"Credential form + urgency keywords ({urgency_matches[:2]})")

            if cred_score >= 3:
                risk_score += 2
                indicators.append(f"High credential keyword density ({cred_score} matches)")

        # 2. Financial phishing
        fin_score, fin_matches = self.calculate_keyword_score(
            combined_text, self.phishing_keywords['financial']
        )

        if fin_score >= 2 and (has_credential_form or password_fields > 0):
            risk_score += 3
            indicators.append(f"Financial keywords + credential form ({fin_matches[:2]})")
            category = 'PHISHING_FINANCIAL'

        # 3. Cryptocurrency scams
        crypto_score, crypto_matches = self.calculate_keyword_score(
            combined_text, self.phishing_keywords['crypto']
        )

        if crypto_score >= 2:
            risk_score += 3
            indicators.append(f"Cryptocurrency scam indicators ({crypto_matches[:2]})")
            category = 'PHISHING_CRYPTO'

        # 4. Suspicious JavaScript with forms
        js_risk_score = features.get('js_risk_score', 0.0) or 0.0
        js_keylogger = features.get('js_keylogger', False)
        js_form_manipulation = features.get('js_form_manipulation', False)

        if (js_keylogger or js_form_manipulation) and has_credential_form:
            risk_score += 3
            indicators.append("Malicious JavaScript + credential form")

        if js_risk_score > 0.7 and password_fields > 0:
            risk_score += 2
            indicators.append(f"High JS risk score ({js_risk_score:.2f}) + password field")

        # 5. Form action pointing to external domain (if available)
        # This would require form_action_url feature (not currently extracted)

        # Decision: Risk score >= 5 indicates phishing
        if risk_score >= 5:
            return {
                'signal': 'content_risk_phishing',
                'verdict': category,
                'confidence': min(0.85, 0.65 + (risk_score * 0.05)),
                'reason': f"Phishing pattern detected: {', '.join(indicators)}",
                'risk_score': risk_score,
                'category': category
            }

        return None

    def check_gambling_patterns(self, features: Dict) -> Optional[Dict]:
        """Detect gambling/casino sites"""
        if not features:
            return None

        doc_text = (features.get('document_text', '') or '').lower()
        ocr_text = (features.get('ocr_text', '') or '').lower()
        combined_text = f"{doc_text} {ocr_text}"

        # Count gambling keywords
        gambling_score, gambling_matches = self.calculate_keyword_score(
            combined_text, self.gambling_keywords
        )

        # Decision: >= 3 gambling keywords indicates gambling site
        if gambling_score >= 3:
            return {
                'signal': 'content_risk_gambling',
                'verdict': 'GAMBLING',
                'confidence': min(0.90, 0.70 + (gambling_score * 0.05)),
                'reason': f"Gambling content detected: {', '.join(gambling_matches[:5])}",
                'keyword_count': gambling_score
            }

        return None

    def check_adult_content(self, features: Dict) -> Optional[Dict]:
        """Detect adult content (basic)"""
        if not features:
            return None

        doc_text = (features.get('document_text', '') or '').lower()
        ocr_text = (features.get('ocr_text', '') or '').lower()
        combined_text = f"{doc_text} {ocr_text}"

        # Count adult keywords
        adult_score, adult_matches = self.calculate_keyword_score(
            combined_text, self.adult_keywords
        )

        # Decision: >= 2 adult keywords indicates adult content
        if adult_score >= 2:
            return {
                'signal': 'content_risk_adult',
                'verdict': 'ADULT_CONTENT',
                'confidence': 0.85,
                'reason': f"Adult content detected ({adult_score} indicators)",
                'keyword_count': adult_score
            }

        return None

    def check_malware_patterns(self, features: Dict) -> Optional[Dict]:
        """Detect malware distribution indicators"""
        if not features:
            return None

        risk_score = 0
        indicators = []

        doc_text = (features.get('document_text', '') or '').lower()
        ocr_text = (features.get('ocr_text', '') or '').lower()
        combined_text = f"{doc_text} {ocr_text}"

        # 1. Malware download keywords
        malware_score, malware_matches = self.calculate_keyword_score(
            combined_text, self.malware_indicators
        )

        if malware_score >= 2:
            risk_score += 3
            indicators.append(f"Malware download indicators ({malware_matches[:2]})")

        # 2. High JS risk without legitimate purpose
        js_risk_score = features.get('js_risk_score', 0.0) or 0.0
        js_obfuscated = features.get('js_obfuscated', False)
        js_eval_usage = features.get('js_eval_usage', False)

        if js_risk_score > 0.8 or (js_obfuscated and js_eval_usage):
            risk_score += 2
            indicators.append("Highly suspicious JavaScript")

        # 3. Auto-redirects (meta refresh or JS redirect)
        redirect_count = features.get('redirect_count', 0) or 0
        if redirect_count > 3:
            risk_score += 1
            indicators.append(f"Multiple redirects ({redirect_count} hops)")

        # Decision: Risk score >= 4 indicates potential malware
        if risk_score >= 4:
            return {
                'signal': 'content_risk_malware',
                'verdict': 'MALWARE',
                'confidence': 0.75,
                'reason': f"Malware indicators detected: {', '.join(indicators)}",
                'risk_score': risk_score
            }

        return None

    def classify(self, features: Dict) -> List[Dict]:
        """
        Run all content-based risk checks

        Returns:
            List of detected risk signals (may be empty, or contain multiple)
        """
        signals = []

        # Check all risk categories
        result = self.check_phishing_patterns(features)
        if result:
            signals.append(result)

        result = self.check_gambling_patterns(features)
        if result:
            signals.append(result)

        result = self.check_adult_content(features)
        if result:
            signals.append(result)

        result = self.check_malware_patterns(features)
        if result:
            signals.append(result)

        return signals
