"""
Domain Reputation Checker

Evaluates domain reputation based on:
- TLD risk
- Domain age
- Subdomain patterns
- Registrar reputation
- Hosting patterns
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse


class DomainReputationChecker:
    """Check domain reputation indicators"""

    def __init__(self):
        # High-risk TLDs (commonly abused for phishing/spam)
        self.high_risk_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
            '.top', '.xyz', '.club', '.online', '.bid',  # Commonly abused
            '.pw', '.cc', '.ws', '.info', '.biz',  # Suspicious
            '.link', '.click', '.loan', '.win', '.download'  # Scam-prone
        }

        # Medium-risk TLDs (less severe but watch for suspicious patterns)
        self.medium_risk_tlds = {
            '.site', '.website', '.space', '.tech', '.store',
            '.live', '.today', '.work', '.guru', '.solutions'
        }

        # Suspicious subdomain patterns
        self.suspicious_subdomain_patterns = [
            r'^secure[.-]',
            r'^login[.-]',
            r'^verify[.-]',
            r'^account[.-]',
            r'^update[.-]',
            r'^confirm[.-]',
            r'^signin[.-]',
            r'^banking[.-]',
            r'^pay[.-]',
            r'^auth[.-]',
            r'^service[.-]',
            r'^support[.-]',
            r'^wallet[.-]',
        ]

        # Known bad/privacy registrars (commonly used for abuse)
        self.suspicious_registrars = [
            'namecheap',  # Privacy protection often used
            'domains by proxy',  # GoDaddy privacy
            'whoisguard',  # Privacy service
            'privacy protect',
            'contact privacy',
            'data protected'
        ]

        # Free/disposable hosting providers
        self.free_hosting_patterns = [
            'netlify.app',
            'herokuapp.com',
            'github.io',
            'vercel.app',
            'surge.sh',
            'firebase.app',
            'repl.co',
            'glitch.me',
            '000webhostapp.com',
            'freehosting'
        ]

    def extract_tld(self, domain: str) -> str:
        """Extract TLD from domain"""
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            # Handle multi-part TLDs like .co.in, .com.au
            if len(parts) >= 3 and parts[-2] in ['co', 'com', 'org', 'net', 'edu', 'gov']:
                return f".{parts[-2]}.{parts[-1]}"
            return f".{parts[-1]}"
        return ''

    def check_tld_risk(self, domain: str) -> Optional[Dict]:
        """Check if domain uses high-risk TLD"""
        tld = self.extract_tld(domain)

        if tld in self.high_risk_tlds:
            return {
                'signal': 'high_risk_tld',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.70,
                'reason': f"Domain uses high-risk TLD: {tld}",
                'tld': tld,
                'risk_level': 'high'
            }
        elif tld in self.medium_risk_tlds:
            return {
                'signal': 'medium_risk_tld',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.55,
                'reason': f"Domain uses medium-risk TLD: {tld}",
                'tld': tld,
                'risk_level': 'medium'
            }

        return None

    def check_domain_age(self, features: Dict) -> Optional[Dict]:
        """Check if domain is newly registered (high risk)"""
        if not features:
            return None

        domain_age_days = features.get('domain_age_days', None)
        is_newly_registered = features.get('is_newly_registered', False)
        is_very_new = features.get('is_very_new', False)

        # Very new domains (<7 days) with suspicious content
        has_credential_form = features.get('has_credential_form', False)
        has_suspicious_forms = features.get('has_suspicious_forms', False)

        if is_very_new and (has_credential_form or has_suspicious_forms):
            return {
                'signal': 'new_domain_suspicious_content',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.75,
                'reason': f"Very new domain ({domain_age_days} days) with suspicious forms",
                'domain_age_days': domain_age_days
            }

        # Newly registered (<30 days) with credential harvesting
        if is_newly_registered and has_credential_form:
            return {
                'signal': 'new_domain_credential_form',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.68,
                'reason': f"Newly registered domain ({domain_age_days} days) with credential form",
                'domain_age_days': domain_age_days
            }

        return None

    def check_subdomain_patterns(self, domain: str, features: Dict) -> Optional[Dict]:
        """Check for suspicious subdomain patterns"""
        if not domain:
            return None

        domain_lower = domain.lower()

        # Check each suspicious pattern
        for pattern in self.suspicious_subdomain_patterns:
            if re.search(pattern, domain_lower):
                # Additional check: Does it also have credential forms?
                has_credential_form = features.get('has_credential_form', False) if features else False

                if has_credential_form:
                    return {
                        'signal': 'suspicious_subdomain_credential',
                        'verdict': 'SUSPICIOUS',
                        'confidence': 0.72,
                        'reason': f"Suspicious subdomain pattern ({pattern[1:-1]}) + credential form",
                        'pattern': pattern
                    }
                else:
                    return {
                        'signal': 'suspicious_subdomain',
                        'verdict': 'SUSPICIOUS',
                        'confidence': 0.55,
                        'reason': f"Suspicious subdomain pattern: {pattern[1:-1]}",
                        'pattern': pattern
                    }

        return None

    def check_excessive_hyphens(self, domain: str) -> Optional[Dict]:
        """Check for excessive hyphens (common in phishing)"""
        if not domain:
            return None

        # Count hyphens in domain (before first TLD dot)
        domain_name = domain.split('.')[0]
        hyphen_count = domain_name.count('-')

        # 3+ hyphens is suspicious
        if hyphen_count >= 3:
            return {
                'signal': 'excessive_hyphens',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.60,
                'reason': f"Excessive hyphens in domain name ({hyphen_count} hyphens)",
                'hyphen_count': hyphen_count
            }

        return None

    def check_ip_based_url(self, domain: str) -> Optional[Dict]:
        """Check if URL uses IP address instead of domain"""
        if not domain:
            return None

        # Regex for IPv4 address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'

        if re.match(ip_pattern, domain):
            return {
                'signal': 'ip_based_url',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.78,
                'reason': "URL uses IP address instead of domain name",
                'ip_address': domain
            }

        return None

    def check_free_hosting(self, domain: str) -> Optional[Dict]:
        """Check if domain is on free hosting with suspicious content"""
        if not domain:
            return None

        domain_lower = domain.lower()

        for hosting_pattern in self.free_hosting_patterns:
            if hosting_pattern in domain_lower:
                return {
                    'signal': 'free_hosting',
                    'verdict': 'SUSPICIOUS',
                    'confidence': 0.50,
                    'reason': f"Domain hosted on free service: {hosting_pattern}",
                    'hosting_service': hosting_pattern
                }

        return None

    def check_registrar_reputation(self, features: Dict) -> Optional[Dict]:
        """Check registrar reputation (privacy services are suspicious)"""
        if not features:
            return None

        registrar = features.get('registrar', '') or ''
        if not registrar or not isinstance(registrar, str):
            return None

        registrar_lower = registrar.lower()

        # Check for privacy/proxy registrars
        for suspicious_reg in self.suspicious_registrars:
            if suspicious_reg in registrar_lower:
                # Privacy registrar alone isn't enough, combine with other factors
                has_credential_form = features.get('has_credential_form', False)
                is_newly_registered = features.get('is_newly_registered', False)

                if has_credential_form and is_newly_registered:
                    return {
                        'signal': 'privacy_registrar_suspicious',
                        'verdict': 'SUSPICIOUS',
                        'confidence': 0.65,
                        'reason': f"Privacy registrar ({suspicious_reg}) + new domain + credential form",
                        'registrar': registrar
                    }

        return None

    def check_self_signed_cert(self, features: Dict) -> Optional[Dict]:
        """Check for self-signed certificate with financial content"""
        if not features:
            return None

        is_self_signed = features.get('is_self_signed', False)

        if not is_self_signed:
            return None

        # Self-signed cert with financial/credential content is highly suspicious
        doc_text = (features.get('document_text', '') or '').lower()
        has_credential_form = features.get('has_credential_form', False)

        financial_keywords = ['bank', 'payment', 'credit card', 'wallet', 'paypal']
        has_financial_keywords = any(kw in doc_text for kw in financial_keywords)

        if has_credential_form and has_financial_keywords:
            return {
                'signal': 'self_signed_cert_financial',
                'verdict': 'SUSPICIOUS',
                'confidence': 0.80,
                'reason': "Self-signed certificate + financial content + credential form",
            }

        return None

    def check_reputation(self, domain: str, features: Dict = None) -> List[Dict]:
        """
        Run all domain reputation checks

        Returns:
            List of reputation signals (may be empty)
        """
        signals = []

        # Check all reputation indicators
        result = self.check_tld_risk(domain)
        if result:
            signals.append(result)

        result = self.check_ip_based_url(domain)
        if result:
            signals.append(result)

        result = self.check_excessive_hyphens(domain)
        if result:
            signals.append(result)

        result = self.check_free_hosting(domain)
        if result:
            signals.append(result)

        if features:
            result = self.check_domain_age(features)
            if result:
                signals.append(result)

            result = self.check_subdomain_patterns(domain, features)
            if result:
                signals.append(result)

            result = self.check_registrar_reputation(features)
            if result:
                signals.append(result)

            result = self.check_self_signed_cert(features)
            if result:
                signals.append(result)

        return signals
