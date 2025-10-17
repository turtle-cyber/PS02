"""Load actual CSE data from folders"""
import json, pandas as pd
from pathlib import Path

def load_cse_metadata(jsonl_path):
    """Load all CSE domains from dump_all.jsonl"""
    records = []
    with open(jsonl_path, encoding='utf-8') as f:
        for line in f:
            records.append(json.loads(line))
    return records

def extract_cse_features(records):
    """Extract ALL features from CSE metadata + document"""
    features = []
    text_data = []  # For text model training

    for rec in records:
        meta = rec.get('metadata', {})
        doc = rec.get('document', '')

        # Extract ALL available features for better anomaly detection
        feat = {
            # URL/Domain features
            'url': meta.get('url', ''),
            'registrable': meta.get('registrable', ''),
            'url_length': meta.get('url_length', 0),
            'url_entropy': meta.get('url_entropy', 0),
            'num_subdomains': meta.get('num_subdomains', 0),
            'is_idn': int(meta.get('is_idn', False)),
            'has_repeated_digits': int(meta.get('has_repeated_digits', False)),
            'mixed_script': int(meta.get('mixed_script', False)),

            # Domain age/WHOIS features
            'domain_age_days': meta.get('domain_age_days', 9999),
            'is_newly_registered': int(meta.get('is_newly_registered', False)),
            'is_very_new': int(meta.get('is_very_new', False)),
            'registrar': meta.get('registrar', ''),
            'country': meta.get('country', ''),
            'days_until_expiry': meta.get('days_until_expiry', 0),

            # Certificate features
            'is_self_signed': int(meta.get('is_self_signed', False)),
            'cert_age_days': meta.get('cert_age_days', 999),

            # Form/credential features
            'has_credential_form': int(meta.get('has_credential_form', False)),
            'form_count': meta.get('form_count', 0),
            'password_fields': meta.get('password_fields', 0),
            'email_fields': meta.get('email_fields', 0),
            'has_suspicious_forms': int(meta.get('has_suspicious_forms', False)),
            'suspicious_form_count': meta.get('suspicious_form_count', 0),

            # Content features
            'keyword_count': meta.get('keyword_count', 0),
            'html_size': meta.get('html_size', 0),
            'external_links': meta.get('external_links', 0),
            'iframe_count': meta.get('iframe_count', 0),

            # JavaScript features
            'js_obfuscated': int(meta.get('js_obfuscated', False)),
            'js_keylogger': int(meta.get('js_keylogger', False)),
            'js_form_manipulation': int(meta.get('js_form_manipulation', False)),
            'js_eval_usage': int(meta.get('js_eval_usage', False)),
            'js_risk_score': meta.get('js_risk_score', 0),

            # Redirect features
            'redirect_count': meta.get('redirect_count', 0),
            'had_redirects': int(meta.get('had_redirects', False)),

            # DNS features
            'a_count': meta.get('a_count', 0),
            'mx_count': meta.get('mx_count', 0),
            'ns_count': meta.get('ns_count', 0),

            # Visual/Favicon features (hashes for similarity matching)
            'favicon_md5': meta.get('favicon_md5', ''),
            'favicon_sha256': meta.get('favicon_sha256', ''),
        }
        features.append(feat)

        # Store text data (URL + document) for text model
        text_data.append({
            'url': meta.get('url', ''),
            'registrable': meta.get('registrable', ''),
            'text': f"{meta.get('url', '')} {doc}"[:512],  # Truncate to 512 chars
        })

    return pd.DataFrame(features), pd.DataFrame(text_data)

def main():
    # Load CSE data
    cse_jsonl = Path("CSE/dump_all.jsonl")
    if not cse_jsonl.exists():
        print(f"Error: {cse_jsonl} not found")
        return

    records = load_cse_metadata(cse_jsonl)
    print(f"Loaded {len(records)} CSE records")

    # Extract features
    df_benign, df_text = extract_cse_features(records)
    print(f"Extracted features for {len(df_benign)} benign samples")

    # Save features (no label column for anomaly detection)
    Path("data").mkdir(exist_ok=True)
    df_benign.to_csv("data/cse_benign.csv", index=False)
    df_text.to_csv("data/cse_text.csv", index=False)

    print(f"\nSaved:")
    print(f"  Tabular features: data/cse_benign.csv (shape: {df_benign.shape})")
    print(f"  Text data: data/cse_text.csv (shape: {df_text.shape})")
    print(f"\nTabular features: {list(df_benign.columns)}")

    # Show favicon hash stats
    has_favicon = (df_benign['favicon_md5'] != '').sum()
    print(f"\nDomains with favicon: {has_favicon}/{len(df_benign)}")

if __name__ == "__main__":
    main()
