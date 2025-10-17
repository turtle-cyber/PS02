"""Feature extraction from ChromaDB to ML models"""
import pandas as pd
from typing import Dict

# Required features (align with your trained models)
REQUIRED_FEATURES = [
    'url_length', 'url_entropy', 'num_subdomains', 'domain_age_days',
    'is_newly_registered', 'is_very_new', 'is_self_signed', 'cert_age_days',
    'has_credential_form', 'keyword_count', 'form_count', 'password_fields',
    'a_count', 'mx_count', 'ns_count', 'html_size', 'external_links',
    'iframe_count', 'js_obfuscated', 'js_keylogger', 'suspicious_form_count'
]

def extract_features_from_chromadb(metadata: Dict) -> Dict:
    """Convert ChromaDB metadata to feature dict"""
    features = {}
    for col in REQUIRED_FEATURES:
        val = metadata.get(col, 0)
        # Convert bool to int
        features[col] = int(val) if isinstance(val, bool) else (val or 0)
    return features

def extract_text_from_chromadb(document: str, metadata: Dict) -> str:
    """Extract text for text model"""
    url = metadata.get('url', '')
    # Combine URL + document, truncate to 256 chars
    return f"{url} {document}"[:256]
