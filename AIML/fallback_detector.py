"""
Fallback Phishing Detection for Domains with Insufficient Content Data

This module provides metadata-based risk scoring when HTML, screenshots,
or OCR data are unavailable. It analyzes DNS records, domain characteristics,
network intelligence, and WHOIS data to generate dynamic verdicts.
"""

import json
import logging
import math
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Try to import similarity libraries (optional dependencies)
try:
    import Levenshtein
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False
    logger.warning("python-Levenshtein not installed - using fallback similarity")

try:
    import jellyfish
    HAS_JELLYFISH = True
except ImportError:
    HAS_JELLYFISH = False
    logger.warning("jellyfish not installed - using fallback similarity")


class FallbackDetector:
    """
    Metadata-based phishing detection for domains with insufficient content data
    """

    # High-risk TLDs frequently used in phishing
    HIGH_RISK_TLDS = {
        # Free TLDs
        '.tk', '.ml', '.ga', '.cf', '.gq',
        # Suspicious generic TLDs
        '.top', '.xyz', '.club', '.work', '.live',
        '.click', '.link', '.online', '.site', '.website',
        '.bid', '.win', '.vip', '.red', '.date',
        # E-commerce scam TLDs (often used for fake shops)
        '.shop', '.store', '.digital', '.space', '.tech',
        '.host', '.cloud', '.network', '.zone'
    }

    # Trusted government/educational TLDs
    TRUSTED_TLDS = {
        '.gov', '.mil', '.edu',
        '.gov.in', '.nic.in', '.ac.in', '.edu.in',
        '.gov.uk', '.ac.uk', '.nhs.uk'
    }

    # Known parking service nameservers (expanded list)
    PARKING_NAMESERVERS = {
        'afternic.com', 'parkingcrew.net', 'bodis.com',
        'sedoparking.com', 'parklogic.com', 'above.com',
        'dan.com', 'hugedomains.com', 'godaddy.com',
        'domaincontrol.com', 'parkweb.com', 'namebrightdns.com',
        'dsredirection.com', 'parkpage.foundationapi.com',
        'registrar-servers.com', 'worldnic.com', 'uniregistrymarket.link'
    }

    # Known bullet-proof/high-risk hosting ASNs
    HIGH_RISK_ASNS = {
        '197695',  # REG.RU (frequently abused)
        '44592',   # SkyLink (bullet-proof hosting)
        '39798',   # MivoCloud (high abuse)
        '394695',  # Hostwinds (frequently abused)
    }

    # Typosquatting detection thresholds
    TYPOSQUAT_SIMILARITY_THRESHOLD = 0.75  # 75% similar = potential typosquat

    # Visual confusables (character substitutions used in typosquatting)
    VISUAL_CONFUSABLES = {
        'o': '0', '0': 'o',
        'l': '1', '1': 'l', 'i': '1',
        'rn': 'm', 'm': 'rn',
        's': '5', '5': 's',
        'g': '9', '9': 'g',
        'b': '8', '8': 'b',
        'a': '@', '@': 'a',
        'e': '3', '3': 'e',
    }

    def __init__(self, config: Optional[Dict] = None, cse_whitelist: Optional[set] = None):
        """
        Initialize fallback detector with optional configuration

        Args:
            config: Optional dict with custom thresholds and weights
            cse_whitelist: Optional set of CSE-whitelisted domains
        """
        self.config = config or self._default_config()
        self.cse_whitelist = cse_whitelist or set()
        logger.info(f"FallbackDetector initialized with {len(self.cse_whitelist)} CSE domains")

    def _default_config(self) -> Dict:
        """Default configuration for risk scoring"""
        return {
            'weights': {
                'tld_risk': 1.0,
                'domain_age': 1.2,  # Higher weight for recent registrations
                'dns_infrastructure': 0.8,
                'network_reputation': 1.0,
                'domain_entropy': 0.6,
                'registrar_reputation': 0.7,
                'whois_privacy': 0.5
            },
            'thresholds': {
                'benign': 30,
                'suspicious': 50,
                'likely_phishing': 70
            },
            'confidence_ranges': {
                'benign': (0.40, 0.55),
                'suspicious': (0.50, 0.65),
                'likely_phishing': (0.60, 0.75),
                'phishing': (0.70, 0.85)
            },
            'age_thresholds': {
                'very_new': 7,      # < 7 days
                'new': 30,          # < 30 days
                'recent': 90        # < 90 days
            }
        }

    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """
        Calculate similarity between two strings using multiple metrics.

        Uses Levenshtein distance, Jaro-Winkler, and visual confusable detection.
        Returns a score between 0.0 (completely different) and 1.0 (identical).

        Args:
            str1: First string (domain to check)
            str2: Second string (CSE domain)

        Returns:
            Float similarity score (0.0 to 1.0)
        """
        # Normalize: remove TLD, lowercase
        s1 = str1.split('.')[0].lower()
        s2 = str2.split('.')[0].lower()

        if s1 == s2:
            return 1.0

        similarities = []

        # 1. Levenshtein-based similarity (edit distance)
        if HAS_LEVENSHTEIN:
            lev_distance = Levenshtein.distance(s1, s2)
            max_len = max(len(s1), len(s2))
            if max_len > 0:
                lev_similarity = 1.0 - (lev_distance / max_len)
                similarities.append(lev_similarity)
        else:
            # Fallback: simple character overlap
            overlap = len(set(s1) & set(s2))
            union = len(set(s1) | set(s2))
            if union > 0:
                similarities.append(overlap / union)

        # 2. Jaro-Winkler similarity (prefix-focused)
        if HAS_JELLYFISH:
            jaro_sim = jellyfish.jaro_winkler_similarity(s1, s2)
            similarities.append(jaro_sim)

        # 3. Length-based similarity (typosquats often have similar length)
        len_diff = abs(len(s1) - len(s2))
        max_len = max(len(s1), len(s2))
        if max_len > 0:
            len_similarity = 1.0 - (len_diff / max_len)
            similarities.append(len_similarity)

        # Return average of all available metrics
        return sum(similarities) / len(similarities) if similarities else 0.0

    def _check_typosquatting(self, domain: str) -> Optional[Tuple[str, float]]:
        """
        Check if domain is typosquatting a CSE-whitelisted brand.

        Args:
            domain: Domain to check (e.g., 'aortel.in')

        Returns:
            Tuple of (cse_domain, similarity) if typosquat detected, None otherwise
        """
        if not self.cse_whitelist:
            return None

        # Extract base domain (remove subdomain if present)
        parts = domain.split('.')
        if len(parts) > 2:
            # Has subdomain - check both full and base domain
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = domain

        # Skip if domain or its base is whitelisted (prevents false positives)
        if domain in self.cse_whitelist or base_domain in self.cse_whitelist:
            return None

        # Also check subdomain matches to avoid false positives
        for cse_domain in self.cse_whitelist:
            if domain.endswith('.' + cse_domain) or domain == cse_domain:
                return None

        max_similarity = 0.0
        best_match = None

        for cse_domain in self.cse_whitelist:
            # Skip exact matches
            if domain == cse_domain or base_domain == cse_domain:
                continue

            # Calculate similarity
            similarity = self._calculate_string_similarity(domain, cse_domain)

            if similarity > max_similarity:
                max_similarity = similarity
                best_match = cse_domain

        # If similarity exceeds threshold, it's a potential typosquat
        if max_similarity >= self.TYPOSQUAT_SIMILARITY_THRESHOLD:
            logger.warning(
                f"Typosquat detected: {domain} is {max_similarity:.2%} similar to {best_match}"
            )
            return (best_match, max_similarity)

        return None

    def analyze_metadata(self, metadata: Dict) -> Dict:
        """
        Perform fallback analysis on domain metadata

        Args:
            metadata: Domain metadata dict from ChromaDB

        Returns:
            Dict with verdict, confidence, risk_score, and reasoning
        """
        domain = metadata.get('registrable') or metadata.get('domain', 'unknown')
        logger.info(f"Starting fallback analysis for domain: {domain}")

        # ============ PRIORITY CHECKS (Early Exit) ============

        # PRIORITY 1: Check CSE whitelist (always BENIGN)
        # Use subdomain-aware matching to handle www. and other subdomains
        is_whitelisted = False
        matched_cse = None

        if self.cse_whitelist:
            # Check 1: Exact match
            if domain in self.cse_whitelist:
                is_whitelisted = True
                matched_cse = domain

            # Check 2: Subdomain-aware matching (e.g., www.icicibank.com matches icicibank.com)
            if not is_whitelisted:
                # Extract registrable domain (remove subdomains like www.)
                parts = domain.split('.')
                if len(parts) > 2:
                    # Try different registrable domain combinations
                    # For domain like "www.ecatering.irctc.co.in", check both:
                    # - "ecatering.irctc.co.in" (one subdomain removed)
                    # - "irctc.co.in" (all subdomains removed)
                    for i in range(1, len(parts) - 1):
                        registrable_candidate = '.'.join(parts[i:])
                        if registrable_candidate in self.cse_whitelist:
                            is_whitelisted = True
                            matched_cse = registrable_candidate
                            logger.info(f"Domain {domain} matched CSE whitelist via registrable: {registrable_candidate}")
                            break

                # Check 3: Suffix match (domain ends with whitelisted domain)
                if not is_whitelisted:
                    for cse_domain in self.cse_whitelist:
                        if domain.endswith('.' + cse_domain) or domain == cse_domain:
                            is_whitelisted = True
                            matched_cse = cse_domain
                            logger.info(f"Domain {domain} matched CSE whitelist via subdomain: {cse_domain}")
                            break

        if is_whitelisted:
            logger.info(f"Domain {domain} is CSE whitelisted (matched: {matched_cse}) - returning BENIGN")
            return {
                'domain': domain,
                'verdict': 'BENIGN',
                'confidence': 0.98,
                'risk_score': 0,
                'reason': f'Legitimate CSE domain (whitelisted: {matched_cse})',
                'source': 'cse_whitelist',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data_availability': {
                    'html': metadata.get('html_size', 0) > 0,
                    'screenshot': bool(metadata.get('screenshot_path')),
                    'ocr': metadata.get('ocr_text_length', 0) > 0,
                    'dns': bool(metadata.get('dns')),
                    'whois': bool(metadata.get('rdap') or metadata.get('whois'))
                }
            }

        # PRIORITY 2: Check for potential typosquatting (adds risk, doesn't auto-flag)
        # Note: Name similarity alone is NOT enough for PHISHING verdict
        # Only visual impersonation (when content available) should auto-flag
        typosquat_result = self._check_typosquatting(domain)
        typosquat_risk = 0
        typosquat_target = None
        typosquat_similarity = 0

        if typosquat_result:
            cse_target, similarity = typosquat_result
            # Add risk points based on similarity (not auto-PHISHING)
            # High similarity (0.85+) = +30 risk
            # Medium similarity (0.75-0.85) = +20 risk
            if similarity >= 0.85:
                typosquat_risk = 30
            else:
                typosquat_risk = 20

            typosquat_target = cse_target
            typosquat_similarity = similarity
            logger.info(
                f"Domain {domain} is {similarity:.2%} similar to CSE domain {cse_target} "
                f"(adding +{typosquat_risk} risk points - needs content verification)"
            )

        # PRIORITY 3: Check INACTIVE (no A records)
        a_count = metadata.get('a_count', 0)
        if a_count == 0:
            logger.info(f"Domain {domain} has no A records - likely INACTIVE")
            return {
                'domain': domain,
                'verdict': 'INACTIVE',
                'confidence': 0.80,
                'risk_score': 30,
                'reason': 'No A records found - domain inactive or unregistered',
                'source': 'aiml_fallback_metadata',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data_availability': {
                    'html': metadata.get('html_size', 0) > 0,
                    'screenshot': bool(metadata.get('screenshot_path')),
                    'ocr': metadata.get('ocr_text_length', 0) > 0,
                    'dns': bool(metadata.get('dns')),
                    'whois': bool(metadata.get('rdap') or metadata.get('whois'))
                }
            }

        # PRIORITY 4: Check PARKED (parking nameservers detected)
        dns_str = metadata.get('dns', '{}')
        try:
            dns = json.loads(dns_str) if isinstance(dns_str, str) else dns_str
            ns_list = dns.get('NS', [])

            # Check for parking nameservers
            is_parked = False
            parking_ns = None
            for ns in ns_list:
                ns_lower = ns.lower()
                for parking_domain in self.PARKING_NAMESERVERS:
                    if parking_domain in ns_lower:
                        is_parked = True
                        parking_ns = parking_domain
                        break
                if is_parked:
                    break

            # If parking NS detected + (new/unknown age domain OR no MX)
            if is_parked:
                domain_age = metadata.get('domain_age_days')
                mx_count = metadata.get('mx_count', 0)

                if domain_age is None or domain_age < 365 or mx_count == 0:
                    logger.info(f"Domain {domain} identified as PARKED (parking NS: {parking_ns})")
                    return {
                        'domain': domain,
                        'verdict': 'PARKED',
                        'confidence': 0.85,
                        'risk_score': 40,
                        'reason': f'Parked domain (parking nameserver: {parking_ns})',
                        'source': 'aiml_fallback_metadata',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'data_availability': {
                            'html': metadata.get('html_size', 0) > 0,
                            'screenshot': bool(metadata.get('screenshot_path')),
                            'ocr': metadata.get('ocr_text_length', 0) > 0,
                            'dns': bool(metadata.get('dns')),
                            'whois': bool(metadata.get('rdap') or metadata.get('whois'))
                        }
                    }
        except (json.JSONDecodeError, TypeError):
            pass  # Continue to normal risk scoring

        # PRIORITY 5: Heuristic-based parking detection (for domains without content/parking NS)
        # Detect premium/for-sale domains based on patterns
        domain_age = metadata.get('domain_age_days')
        mx_count = metadata.get('mx_count', 0)
        html_size = metadata.get('html_size', 0)

        # Premium domain indicators:
        # - Short domain (2-4 chars) with premium TLD (.co, .io, .ai, .me)
        # - No MX, minimal/no HTML, no infrastructure
        premium_tlds = ['.co', '.io', '.ai', '.me', '.vc', '.ly']
        is_premium_tld = any(domain.endswith(tld) for tld in premium_tlds)
        base_domain = domain.split('.')[0]  # Get domain without TLD

        if is_premium_tld and len(base_domain) <= 4 and mx_count == 0 and html_size < 5000:
            logger.info(f"Domain {domain} appears to be premium for-sale domain (short premium TLD, no infrastructure)")
            return {
                'domain': domain,
                'verdict': 'PARKED',
                'confidence': 0.75,
                'risk_score': 35,
                'reason': f'Likely for-sale premium domain (short {base_domain}.{domain.split(".")[-1]}, no email/content)',
                'source': 'aiml_fallback_heuristic',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'data_availability': {
                    'html': metadata.get('html_size', 0) > 0,
                    'screenshot': bool(metadata.get('screenshot_path')),
                    'ocr': metadata.get('ocr_text_length', 0) > 0,
                    'dns': bool(metadata.get('dns')),
                    'whois': bool(metadata.get('rdap') or metadata.get('whois'))
                }
            }

        # ============ STANDARD RISK SCORING ============

        # Collect all risk signals
        signals = {}
        reasons = []

        # 0. Typosquatting Risk (if detected earlier)
        if typosquat_risk > 0:
            signals['typosquat_risk'] = typosquat_risk
            reasons.append(f"Similar to CSE domain {typosquat_target} (similarity={typosquat_similarity:.2%})")

        # 1. DNS Analysis
        dns_risk, dns_reasons = self._analyze_dns(metadata)
        signals['dns_infrastructure'] = dns_risk
        reasons.extend(dns_reasons)

        # 2. Domain Characteristics
        domain_risk, domain_reasons = self._analyze_domain_characteristics(metadata)
        signals['domain_characteristics'] = domain_risk
        reasons.extend(domain_reasons)

        # 3. Network Intelligence
        network_risk, network_reasons = self._analyze_network(metadata)
        signals['network_reputation'] = network_risk
        reasons.extend(network_reasons)

        # 4. WHOIS/Registration Data
        whois_risk, whois_reasons = self._analyze_whois(metadata)
        signals['whois_signals'] = whois_risk
        reasons.extend(whois_reasons)

        # 5. TLD Risk
        tld_risk, tld_reason = self._analyze_tld(metadata)
        signals['tld_risk'] = tld_risk
        if tld_reason:
            reasons.append(tld_reason)

        # Calculate weighted risk score
        risk_score = self._calculate_risk_score(signals)

        # Determine verdict and confidence
        verdict, confidence = self._classify_verdict(risk_score)

        # Build result
        result = {
            'domain': domain,
            'verdict': verdict,
            'confidence': round(confidence, 2),
            'risk_score': risk_score,
            'reason': ', '.join(reasons[:5]) if reasons else 'Metadata analysis completed',
            'fallback_signals': signals,
            'source': 'aiml_fallback_metadata',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data_availability': {
                'html': metadata.get('html_size', 0) > 0,
                'screenshot': bool(metadata.get('screenshot_path')),
                'ocr': metadata.get('ocr_text_length', 0) > 0,
                'dns': bool(metadata.get('dns')),
                'whois': bool(metadata.get('rdap') or metadata.get('whois'))
            }
        }

        logger.info(f"Fallback analysis complete for {domain}: {verdict} (risk={risk_score}, conf={confidence})")
        return result

    def _analyze_dns(self, metadata: Dict) -> Tuple[float, List[str]]:
        """
        Analyze DNS infrastructure for risk indicators

        Returns:
            (risk_score, reasons)
        """
        risk = 0.0
        reasons = []

        # Parse DNS data
        dns_str = metadata.get('dns', '{}')
        try:
            dns = json.loads(dns_str) if isinstance(dns_str, str) else dns_str
        except (json.JSONDecodeError, TypeError):
            dns = {}

        # Extract counts
        a_count = metadata.get('a_count', len(dns.get('A', [])))
        mx_count = metadata.get('mx_count', len(dns.get('MX', [])))
        ns_list = dns.get('NS', [])

        # Check for parking nameservers
        for ns in ns_list:
            ns_lower = ns.lower()
            for parking_domain in self.PARKING_NAMESERVERS:
                if parking_domain in ns_lower:
                    risk += 25
                    reasons.append(f"Parking nameserver detected ({parking_domain})")
                    break

        # No MX records (no email infrastructure)
        # REDUCED PENALTY: Many legitimate static sites don't need email
        if mx_count == 0:
            risk += 8  # Reduced from 15
            reasons.append("No MX records (no email infrastructure)")

        # Single A record + no infrastructure = likely parked/suspicious
        # REDUCED PENALTY: Less aggressive for established domains
        if a_count == 1 and mx_count == 0:
            risk += 10  # Reduced from 20
            reasons.append("Minimal DNS infrastructure")

        # No A records at all
        if a_count == 0:
            risk += 20
            reasons.append("No A records")

        return min(risk, 100), reasons

    def _analyze_domain_characteristics(self, metadata: Dict) -> Tuple[float, List[str]]:
        """
        Analyze domain string characteristics for risk

        Returns:
            (risk_score, reasons)
        """
        risk = 0.0
        reasons = []

        domain = metadata.get('registrable', '')
        domain_length = metadata.get('domain_length', len(domain))
        domain_entropy = metadata.get('domain_entropy', 0)

        # Domain age analysis
        domain_age_days = metadata.get('domain_age_days')

        # CRITICAL FIX: If domain age is missing, treat as suspicious
        # Legitimate established domains have WHOIS data. Missing age = suspicious.
        if domain_age_days is None:
            risk += 20
            reasons.append("Domain age unknown (data unavailable)")
            logger.warning(f"Domain {domain}: Missing domain_age_days - adding +20 risk")
        elif domain_age_days < self.config['age_thresholds']['very_new']:
            risk += 30
            reasons.append(f"Very new domain ({domain_age_days} days)")
        elif domain_age_days < self.config['age_thresholds']['new']:
            risk += 25
            reasons.append(f"Recently registered ({domain_age_days} days)")
        elif domain_age_days < self.config['age_thresholds']['recent']:
            risk += 10
            reasons.append(f"Recent domain ({domain_age_days} days)")

        # Check if marked as newly registered
        if metadata.get('is_newly_registered'):
            risk += 20
            reasons.append("Flagged as newly registered")

        # Entropy analysis (very high or very low can be suspicious)
        if domain_entropy > 4.5:
            risk += 10
            reasons.append(f"High domain entropy ({domain_entropy:.2f})")
        # REMOVED: Low entropy with long domain (descriptive names like "shecareswomenshealth.com" are legitimate)
        # Only flag low entropy if it's ALSO a new domain or high-risk TLD
        elif domain_entropy < 2.0 and domain_length > 20:
            # Very low entropy + very long = potential keyword stuffing
            # But only if domain is new or suspicious TLD
            if (domain_age_days is not None and domain_age_days < 90) or metadata.get('is_high_risk_tld'):
                risk += 5
                reasons.append("Low entropy with very long domain (new/high-risk TLD)")

        # Very long domains (potential typosquatting)
        if domain_length > 30:
            risk += 10
            reasons.append(f"Very long domain ({domain_length} chars)")

        # Check for repeated digits (common in generated phishing domains)
        if metadata.get('has_repeated_digits'):
            risk += 5
            reasons.append("Repeated digits in domain")

        # IDN/punycode domains
        idn_str = metadata.get('idn', '{}')
        try:
            idn = json.loads(idn_str) if isinstance(idn_str, str) else idn_str
            if idn.get('is_idn'):
                risk += 10
                reasons.append("IDN/Punycode domain")
            if idn.get('confusable_count', 0) > 0:
                risk += 15
                reasons.append(f"Confusable characters detected ({idn['confusable_count']})")
        except (json.JSONDecodeError, TypeError):
            pass

        return min(risk, 100), reasons

    def _analyze_network(self, metadata: Dict) -> Tuple[float, List[str]]:
        """
        Analyze network/hosting reputation

        Returns:
            (risk_score, reasons)
        """
        risk = 0.0
        reasons = []

        asn = metadata.get('asn', '')
        asn_org = metadata.get('asn_org', '')
        country = metadata.get('country', '')
        domain_age_days = metadata.get('domain_age_days')

        # Get domain age for context-aware scoring
        is_established = domain_age_days is not None and domain_age_days >= 365  # 1+ year old
        has_infrastructure = metadata.get('mx_count', 0) > 0  # Has email

        # Check for high-risk ASNs (but reduce penalty for established domains)
        if asn in self.HIGH_RISK_ASNS:
            if is_established and has_infrastructure:
                # Established domain with infrastructure - reduce penalty
                risk += 8
                reasons.append(f"ASN {asn_org or asn} (established domain)")
            else:
                # New domain or no infrastructure - full penalty
                risk += 20
                reasons.append(f"High-risk ASN ({asn_org or asn})")

        # Check for bullet-proof hosting indicators in ASN org name
        high_risk_keywords = ['bulletproof', 'offshore', 'anonymous']
        if asn_org:
            asn_org_lower = asn_org.lower()
            for keyword in high_risk_keywords:
                if keyword in asn_org_lower:
                    risk += 25
                    reasons.append(f"Suspicious hosting provider ({keyword})")
                    break

        # High-risk countries (reduce penalty for established domains)
        high_risk_countries = {'RU', 'CN', 'KP', 'IR'}
        if country in high_risk_countries:
            if is_established and has_infrastructure:
                # Established domain with infrastructure - minimal penalty
                risk += 3
                reasons.append(f"Country: {country} (established)")
            else:
                # New domain or no infrastructure - higher penalty
                risk += 10
                reasons.append(f"High-risk country ({country})")

        return min(risk, 100), reasons

    def _analyze_whois(self, metadata: Dict) -> Tuple[float, List[str]]:
        """
        Analyze WHOIS/RDAP data

        Returns:
            (risk_score, reasons)
        """
        risk = 0.0
        reasons = []

        domain_age_days = metadata.get('domain_age_days')
        is_established = domain_age_days is not None and domain_age_days >= 365

        # Registrar analysis (reduce penalty for established domains)
        registrar = metadata.get('registrar', '').lower()

        # Known low-reputation registrars
        low_rep_registrars = ['namecheap', 'namesilo', 'freenom']
        for low_reg in low_rep_registrars:
            if low_reg in registrar:
                if is_established:
                    # Established domain - minimal penalty
                    risk += 3
                    reasons.append(f"Registrar: {low_reg} (established domain)")
                else:
                    # New domain - higher penalty
                    risk += 10
                    reasons.append(f"Registrar with history of abuse ({registrar})")
                break

        # Days until expiry (domains registered for short periods)
        days_until_expiry = metadata.get('days_until_expiry')
        if days_until_expiry is not None and days_until_expiry < 90:
            risk += 8
            reasons.append(f"Short registration period ({days_until_expiry} days until expiry)")

        # RDAP privacy protection detection (parse RDAP JSON if available)
        # Only penalize privacy protection for new domains
        rdap_str = metadata.get('rdap', '{}')
        try:
            rdap = json.loads(rdap_str) if isinstance(rdap_str, str) else rdap_str
            # Check for privacy protection keywords in RDAP
            rdap_text = json.dumps(rdap).lower()
            if 'privacy' in rdap_text or 'redacted' in rdap_text or 'whoisguard' in rdap_text:
                if not is_established:
                    risk += 15
                    reasons.append("WHOIS privacy protection enabled")
                # Established domains often use privacy protection legitimately - no penalty
        except (json.JSONDecodeError, TypeError):
            pass

        return min(risk, 100), reasons

    def _analyze_tld(self, metadata: Dict) -> Tuple[float, Optional[str]]:
        """
        Analyze TLD risk

        Returns:
            (risk_score, reason or None)
        """
        risk = 0.0
        reason = None

        domain = metadata.get('registrable', '').lower()

        # Check trusted TLDs first (early exit with 0 risk)
        for trusted_tld in self.TRUSTED_TLDS:
            if domain.endswith(trusted_tld):
                return 0.0, None

        # Check high-risk TLDs
        for high_risk_tld in self.HIGH_RISK_TLDS:
            if domain.endswith(high_risk_tld):
                risk = 25
                reason = f"High-risk TLD ({high_risk_tld})"
                break

        # Generic risky TLDs
        if domain.endswith('.info'):
            risk = 15
            reason = "Risky TLD (.info)"
        elif domain.endswith('.biz'):
            risk = 10
            reason = "Moderate-risk TLD (.biz)"

        return risk, reason

    def _calculate_risk_score(self, signals: Dict[str, float]) -> int:
        """
        Calculate weighted risk score from all signals

        Args:
            signals: Dict of signal_name -> raw_score

        Returns:
            Final risk score (0-100)
        """
        weights = self.config['weights']

        weighted_sum = 0.0
        for signal_name, raw_score in signals.items():
            weight = weights.get(signal_name, 1.0)
            weighted_sum += raw_score * weight

        # Normalize and cap at 100
        # Apply slight amplification for multiple weak signals
        signal_count = len([s for s in signals.values() if s > 0])
        amplification = 1.0 + (signal_count * 0.05)  # +5% per additional signal

        final_score = min(100, int(weighted_sum * amplification))

        return final_score

    def _classify_verdict(self, risk_score: int) -> Tuple[str, float]:
        """
        Classify verdict based on risk score and calculate confidence

        Args:
            risk_score: Calculated risk score (0-100)

        Returns:
            (verdict, confidence)
        """
        thresholds = self.config['thresholds']
        conf_ranges = self.config['confidence_ranges']

        if risk_score >= thresholds['likely_phishing']:
            verdict = 'PHISHING'
            conf_min, conf_max = conf_ranges['phishing']
        elif risk_score >= thresholds['suspicious']:
            verdict = 'LIKELY_PHISHING'
            conf_min, conf_max = conf_ranges['likely_phishing']
        elif risk_score >= thresholds['benign']:
            verdict = 'SUSPICIOUS'
            conf_min, conf_max = conf_ranges['suspicious']
        else:
            verdict = 'BENIGN'
            conf_min, conf_max = conf_ranges['benign']

        # Scale confidence within range based on risk score position
        if verdict == 'BENIGN':
            # Lower risk = higher confidence
            progress = 1.0 - (risk_score / thresholds['benign'])
        else:
            # Higher risk = higher confidence
            if verdict == 'SUSPICIOUS':
                progress = (risk_score - thresholds['benign']) / (thresholds['suspicious'] - thresholds['benign'])
            elif verdict == 'LIKELY_PHISHING':
                progress = (risk_score - thresholds['suspicious']) / (thresholds['likely_phishing'] - thresholds['suspicious'])
            else:  # PHISHING
                progress = (risk_score - thresholds['likely_phishing']) / (100 - thresholds['likely_phishing'])

        confidence = conf_min + (progress * (conf_max - conf_min))

        return verdict, confidence
