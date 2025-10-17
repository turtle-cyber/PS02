"""Merge tabular, text, and visual features into unified datasets"""
import pandas as pd
from pathlib import Path

def main():
    print("Merging all CSE features...")

    # Load all feature files
    tabular = pd.read_csv("data/cse_benign.csv")
    text = pd.read_csv("data/cse_text.csv")

    # Load document features
    doc_features_path = Path("data/cse_document_features.csv")
    if doc_features_path.exists():
        doc_features = pd.read_csv(doc_features_path)
        print(f"Loaded document features: {doc_features.shape}")
    else:
        print("⚠️  Document features not found. Run: python data_prep/extract_document_features.py")
        doc_features = None

    # Deduplicate tabular data (keep first occurrence)
    tabular = tabular.drop_duplicates(subset=['registrable'], keep='first')
    print(f"Tabular features: {len(tabular)} unique domains")

    # Load visual features if available
    visual_path = Path("data/cse_visual_features.csv")
    if visual_path.exists():
        visual = pd.read_csv(visual_path)
        print(f"Loaded visual features: {visual.shape}")
    else:
        print("⚠️  Visual features not found. Run: python data_prep/extract_visual_features.py")
        visual = None

    # Merge on domain/registrable
    merged = tabular.copy()

    # Add text data
    text_subset = text[['registrable', 'text']].rename(columns={'text': 'document_text'})
    merged = merged.merge(text_subset, on='registrable', how='left')

    # Add document features
    if doc_features is not None:
        doc_subset = doc_features.drop(columns=['url'], errors='ignore')
        merged = merged.merge(doc_subset, on='registrable', how='left')

    # Add visual features if available
    if visual is not None:
        # Visual features already have 'registrable' column
        visual_subset = visual[['registrable', 'screenshot_phash', 'ocr_text', 'ocr_length',
                               'ocr_has_login_keywords', 'ocr_has_verify_keywords']]
        merged = merged.merge(visual_subset, on='registrable', how='left')

    # Save merged dataset
    merged.to_csv("data/cse_all_features.csv", index=False)
    print(f"\nSaved merged features: data/cse_all_features.csv")
    print(f"Shape: {merged.shape}")
    print(f"Columns: {list(merged.columns)}")

    # Stats
    print(f"\nFeature Coverage:")
    print(f"  Domains: {len(merged)}")
    print(f"  With text: {merged['document_text'].notna().sum()}")
    if 'screenshot_phash' in merged.columns:
        print(f"  With screenshots: {merged['screenshot_phash'].notna().sum()}")
        print(f"  With OCR text: {(merged['ocr_length'] > 0).sum()}")
        print(f"  With favicons: {(merged['favicon_md5'] != '').sum()}")

if __name__ == "__main__":
    main()
