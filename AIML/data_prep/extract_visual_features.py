"""Extract OCR text and perceptual hashes from screenshots and favicons"""
import argparse
import json
import pandas as pd
from pathlib import Path
from PIL import Image
import imagehash
from tqdm import tqdm

try:
    import pytesseract
    HAS_OCR = True
except ImportError:
    HAS_OCR = False
    print("WARNING: pytesseract not installed. OCR will be skipped.")
    print("Install: pip install pytesseract")

def compute_phash(img_path):
    """Compute perceptual hash for image"""
    try:
        img = Image.open(img_path)
        return str(imagehash.phash(img))
    except Exception as e:
        print(f"Error computing phash for {img_path}: {e}")
        return None

def extract_ocr_text(img_path, lang='eng'):
    """Extract OCR text from screenshot"""
    if not HAS_OCR:
        return ""

    try:
        img = Image.open(img_path)
        text = pytesseract.image_to_string(img, lang=lang)
        return text.strip()
    except Exception as e:
        print(f"Error extracting OCR from {img_path}: {e}")
        return ""

def process_screenshots(screenshot_dir, output_csv):
    """Process all screenshots and extract visual features"""
    screenshot_dir = Path(screenshot_dir)
    screenshots = list(screenshot_dir.glob("*.png")) + list(screenshot_dir.glob("*.jpg"))

    print(f"Found {len(screenshots)} screenshots")

    results = []
    for img_path in tqdm(screenshots, desc="Processing screenshots"):
        # Extract domain from filename (format: domain_hash_full.png)
        domain = img_path.stem.rsplit('_', 1)[0]

        # Compute perceptual hash
        phash = compute_phash(img_path)

        # Extract OCR text
        ocr_text = extract_ocr_text(img_path) if HAS_OCR else ""
        ocr_length = len(ocr_text)
        ocr_has_login = int(any(word in ocr_text.lower() for word in ['login', 'sign in', 'password', 'username']))
        ocr_has_verify = int(any(word in ocr_text.lower() for word in ['verify', 'confirm', 'authenticate']))

        results.append({
            'domain': domain,
            'screenshot_path': str(img_path),
            'screenshot_phash': phash,
            'ocr_text': ocr_text[:500],  # Truncate long text
            'ocr_length': ocr_length,
            'ocr_has_login_keywords': ocr_has_login,
            'ocr_has_verify_keywords': ocr_has_verify,
        })

    df = pd.DataFrame(results)
    df.to_csv(output_csv, index=False)
    print(f"\nSaved visual features to {output_csv}")
    print(f"Shape: {df.shape}")

    return df

def process_favicons(html_dir, output_csv):
    """Extract favicons from HTML files and compute phash"""
    # Note: This is simplified - actual favicon extraction needs HTTP fetch or HTML parsing
    # For now, we'll use existing favicon hashes from metadata
    print("Favicon phash extraction requires actual favicon images")
    print("Using existing MD5/SHA256 hashes from metadata instead")
    return None

def main():
    ap = argparse.ArgumentParser(description="Extract visual features from screenshots")
    ap.add_argument("--screenshots", default="CSE/out/screenshots", help="Screenshot directory")
    ap.add_argument("--output", default="data/cse_visual_features.csv", help="Output CSV")
    ap.add_argument("--lang", default="eng", help="OCR language (eng, hin, etc)")
    args = ap.parse_args()

    if not HAS_OCR:
        print("\n" + "="*70)
        print("INSTALL TESSERACT FOR OCR:")
        print("  Windows: Download from https://github.com/UB-Mannheim/tesseract/wiki")
        print("  Linux: sudo apt-get install tesseract-ocr")
        print("  Mac: brew install tesseract")
        print("  Then: pip install pytesseract")
        print("="*70 + "\n")

    # Process screenshots
    df = process_screenshots(args.screenshots, args.output)

    # Stats
    print(f"\nVisual Features Summary:")
    print(f"  Domains with OCR text: {(df['ocr_length'] > 0).sum()}/{len(df)}")
    print(f"  Domains with login keywords: {df['ocr_has_login_keywords'].sum()}")
    print(f"  Domains with verify keywords: {df['ocr_has_verify_keywords'].sum()}")
    print(f"  Unique phashes: {df['screenshot_phash'].nunique()}")

    # Check for duplicate phashes (identical screenshots)
    dup_phashes = df[df.duplicated(subset=['screenshot_phash'], keep=False)]
    if len(dup_phashes) > 0:
        print(f"\n[WARNING] Found {len(dup_phashes)} screenshots with duplicate phashes")

if __name__ == "__main__":
    main()
