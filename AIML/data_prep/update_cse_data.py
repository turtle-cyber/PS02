"""Update CSE data with new dump_all.jsonl from project root"""
import json, pandas as pd
from pathlib import Path
import shutil

def load_cse_metadata(jsonl_path):
    """Load all CSE domains from dump_all.jsonl"""
    records = []
    with open(jsonl_path, encoding='utf-8') as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"Warning: Skipping malformed JSON line: {e}")
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
    # Load new CSE data from project root
    possible_paths = [
        Path("/app/dump_all.jsonl"),  # Docker copied location
        Path("../dump_all.jsonl"),    # Relative path
        Path("dump_all.jsonl"),       # Current directory
    ]

    new_dump = None
    for path in possible_paths:
        if path.exists():
            new_dump = path
            break

    if new_dump is None:
        print(f"Error: dump_all.jsonl not found")
        print(f"Tried paths: {possible_paths}")
        return

    print(f"Loading new CSE data from: {new_dump}")
    new_records = load_cse_metadata(new_dump)
    print(f"Loaded {len(new_records)} new CSE records")

    # Extract features from new data
    df_new_benign, df_new_text = extract_cse_features(new_records)
    print(f"Extracted features for {len(df_new_benign)} new benign samples")

    # Load existing data if available and merge
    existing_benign = Path("data/cse_benign.csv")
    existing_text = Path("data/cse_text.csv")

    if existing_benign.exists():
        old_benign = pd.read_csv(existing_benign)
        print(f"Found existing data: {len(old_benign)} old records")

        # Merge and deduplicate by registrable domain
        df_benign = pd.concat([old_benign, df_new_benign], ignore_index=True)
        df_benign = df_benign.drop_duplicates(subset=['registrable'], keep='last')
        print(f"After merge: {len(df_benign)} unique domains (added {len(df_benign) - len(old_benign)} new)")
    else:
        df_benign = df_new_benign
        print(f"No existing data, using {len(df_benign)} new records")

    if existing_text.exists():
        old_text = pd.read_csv(existing_text)
        df_text = pd.concat([old_text, df_new_text], ignore_index=True)
        df_text = df_text.drop_duplicates(subset=['registrable'], keep='last')
    else:
        df_text = df_new_text

    # Save merged features
    Path("data").mkdir(exist_ok=True)
    df_benign.to_csv("data/cse_benign.csv", index=False)
    df_text.to_csv("data/cse_text.csv", index=False)

    print(f"\nSaved:")
    print(f"  Tabular features: data/cse_benign.csv (shape: {df_benign.shape})")
    print(f"  Text data: data/cse_text.csv (shape: {df_text.shape})")

    # Show favicon hash stats
    has_favicon = (df_benign['favicon_md5'] != '').sum()
    print(f"\nDomains with favicon: {has_favicon}/{len(df_benign)}")

    return df_benign

if __name__ == "__main__":
    main()
