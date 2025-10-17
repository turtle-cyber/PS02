"""Extract structured features from document field in dump_all.jsonl"""
import json
import pandas as pd
from pathlib import Path
import re

def parse_document_field(document):
    """Extract structured information from document text"""
    features = {
        'doc_has_verdict': 0,
        'doc_verdict': '',
        'doc_risk_score': 0,
        'doc_form_count': 0,
        'doc_submit_buttons': '',
        'doc_has_login_keywords': 0,
        'doc_has_verify_keywords': 0,
        'doc_has_password_keywords': 0,
        'doc_has_credential_keywords': 0,
        'doc_length': len(document)
    }

    if not document:
        return features

    # Extract verdict line: "VERDICT: BENIGN (Risk Score: 0/100"
    verdict_match = re.search(r'VERDICT:\s*(\w+)\s*\(Risk Score:\s*(\d+)/100', document)
    if verdict_match:
        features['doc_has_verdict'] = 1
        features['doc_verdict'] = verdict_match.group(1).lower()
        features['doc_risk_score'] = int(verdict_match.group(2))

    # Extract form count: "Total Forms: 1"
    form_match = re.search(r'Total Forms:\s*(\d+)', document)
    if form_match:
        features['doc_form_count'] = int(form_match.group(1))

    # Extract submit buttons: "Submit Buttons: Search, Login, ..."
    buttons_match = re.search(r'Submit Buttons?:\s*([^\n]+)', document)
    if buttons_match:
        buttons = buttons_match.group(1).strip()
        features['doc_submit_buttons'] = buttons

        # Check for phishing keywords in button text
        buttons_lower = buttons.lower()
        if any(kw in buttons_lower for kw in ['login', 'signin', 'sign in', 'log in']):
            features['doc_has_login_keywords'] = 1
        if any(kw in buttons_lower for kw in ['verify', 'confirm', 'authenticate']):
            features['doc_has_verify_keywords'] = 1
        if any(kw in buttons_lower for kw in ['password', 'pwd', 'pass']):
            features['doc_has_password_keywords'] = 1
        if any(kw in buttons_lower for kw in ['credential', 'account', 'secure']):
            features['doc_has_credential_keywords'] = 1

    # Check for keywords in entire document
    doc_lower = document.lower()
    if not features['doc_has_login_keywords']:
        features['doc_has_login_keywords'] = int(any(kw in doc_lower for kw in ['login', 'signin', 'sign in']))
    if not features['doc_has_verify_keywords']:
        features['doc_has_verify_keywords'] = int(any(kw in doc_lower for kw in ['verify', 'confirm', 'authenticate']))

    return features

def main():
    print("Extracting structured features from document field...")

    # Load CSE data
    cse_jsonl = Path("CSE/dump_all.jsonl")

    records = []
    with open(cse_jsonl, encoding='utf-8') as f:
        for line in f:
            rec = json.loads(line)
            metadata = rec.get('metadata', {})
            document = rec.get('document', '')

            # Extract document features
            doc_features = parse_document_field(document)

            # Combine with basic info
            row = {
                'registrable': metadata.get('registrable', ''),
                'url': metadata.get('url', ''),
                **doc_features
            }
            records.append(row)

    df = pd.DataFrame(records)

    # Save
    Path("data").mkdir(exist_ok=True)
    df.to_csv("data/cse_document_features.csv", index=False)

    print(f"\nExtracted document features from {len(df)} records")
    print(f"Saved to: data/cse_document_features.csv")
    print(f"\nFeatures extracted:")
    for col in df.columns:
        if col not in ['registrable', 'url', 'doc_submit_buttons', 'doc_verdict']:
            print(f"  {col}: {df[col].sum() if df[col].dtype in ['int64', 'float64'] else 'text'}")

    print(f"\nDocument statistics:")
    print(f"  With verdict: {df['doc_has_verdict'].sum()}/{len(df)}")
    print(f"  With forms: {(df['doc_form_count'] > 0).sum()}/{len(df)}")
    print(f"  With login keywords: {df['doc_has_login_keywords'].sum()}/{len(df)}")
    print(f"  Avg document length: {df['doc_length'].mean():.0f} chars")

    # Show examples of submit buttons
    print(f"\nExample submit button texts:")
    buttons = df[df['doc_submit_buttons'] != '']['doc_submit_buttons'].head(10)
    for i, btn in enumerate(buttons, 1):
        print(f"  {i}. {btn}")

if __name__ == "__main__":
    main()
