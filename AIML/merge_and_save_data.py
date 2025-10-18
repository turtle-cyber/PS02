"""Merge CSE data and save - fixed version for Docker volumes"""
import json, pandas as pd
from pathlib import Path

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
    text_data = []

    for rec in records:
        meta = rec.get('metadata', {})
        doc = rec.get('document', '')

        feat = {
            'url': meta.get('url', ''),
            'registrable': meta.get('registrable', ''),
            'url_length': meta.get('url_length', 0),
            'url_entropy': meta.get('url_entropy', 0),
            'num_subdomains': meta.get('num_subdomains', 0),
            'is_idn': int(meta.get('is_idn', False)),
            'has_repeated_digits': int(meta.get('has_repeated_digits', False)),
            'mixed_script': int(meta.get('mixed_script', False)),
            'domain_age_days': meta.get('domain_age_days', 9999),
            'is_newly_registered': int(meta.get('is_newly_registered', False)),
            'is_very_new': int(meta.get('is_very_new', False)),
            'registrar': meta.get('registrar', ''),
            'country': meta.get('country', ''),
            'days_until_expiry': meta.get('days_until_expiry', 0),
            'is_self_signed': int(meta.get('is_self_signed', False)),
            'cert_age_days': meta.get('cert_age_days', 999),
            'has_credential_form': int(meta.get('has_credential_form', False)),
            'form_count': meta.get('form_count', 0),
            'password_fields': meta.get('password_fields', 0),
            'email_fields': meta.get('email_fields', 0),
            'has_suspicious_forms': int(meta.get('has_suspicious_forms', False)),
            'suspicious_form_count': meta.get('suspicious_form_count', 0),
            'keyword_count': meta.get('keyword_count', 0),
            'html_size': meta.get('html_size', 0),
            'external_links': meta.get('external_links', 0),
            'iframe_count': meta.get('iframe_count', 0),
            'js_obfuscated': int(meta.get('js_obfuscated', False)),
            'js_keylogger': int(meta.get('js_keylogger', False)),
            'js_form_manipulation': int(meta.get('js_form_manipulation', False)),
            'js_eval_usage': int(meta.get('js_eval_usage', False)),
            'js_risk_score': meta.get('js_risk_score', 0),
            'redirect_count': meta.get('redirect_count', 0),
            'had_redirects': int(meta.get('had_redirects', False)),
            'a_count': meta.get('a_count', 0),
            'mx_count': meta.get('mx_count', 0),
            'ns_count': meta.get('ns_count', 0),
            'favicon_md5': meta.get('favicon_md5', ''),
            'favicon_sha256': meta.get('favicon_sha256', ''),
        }
        features.append(feat)

        text_data.append({
            'url': meta.get('url', ''),
            'registrable': meta.get('registrable', ''),
            'text': f"{meta.get('url', '')} {doc}"[:512],
        })

    return pd.DataFrame(features), pd.DataFrame(text_data)

# Load new data
print("Loading dump_all.jsonl...")
new_records = load_cse_metadata("dump_all.jsonl")
print(f"Loaded {len(new_records)} new records")

df_new_benign, df_new_text = extract_cse_features(new_records)

# Load existing
existing_path = "AIML/data/cse_benign.csv"
if Path(existing_path).exists():
    old_benign = pd.read_csv(existing_path)
    print(f"Existing: {len(old_benign)} records")

    df_benign = pd.concat([old_benign, df_new_benign], ignore_index=True)
    df_benign = df_benign.drop_duplicates(subset=['registrable'], keep='last')
    print(f"Merged: {len(df_benign)} total ({len(df_benign) - len(old_benign)} new)")
else:
    df_benign = df_new_benign

existing_text_path = "AIML/data/cse_text.csv"
if Path(existing_text_path).exists():
    old_text = pd.read_csv(existing_text_path)
    df_text = pd.concat([old_text, df_new_text], ignore_index=True)
    df_text = df_text.drop_duplicates(subset=['registrable'], keep='last')
else:
    df_text = df_new_text

# Save
df_benign.to_csv("AIML/data/cse_benign.csv", index=False)
df_text.to_csv("AIML/data/cse_text.csv", index=False)

print(f"\nSaved:")
print(f"  {len(df_benign)} domains to AIML/data/cse_benign.csv")
print(f"  {len(df_text)} text records to AIML/data/cse_text.csv")

has_favicon = (df_benign['favicon_md5'] != '').sum()
print(f"\nFavicons: {has_favicon}/{len(df_benign)}")
