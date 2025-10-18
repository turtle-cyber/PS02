"""Extract OCR text and perceptual hashes from screenshots and favicons
Works with dump_all.jsonl format and Pipeline/out/screenshots directory
"""
import argparse
import json
from pathlib import Path
from PIL import Image
import imagehash

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

def process_screenshots(jsonl_path, screenshot_dir, output_jsonl):
    """Process all screenshots and extract visual features

    Reads from dump_all.jsonl and matches with screenshots in screenshot_dir
    Outputs enriched JSONL with visual features added to metadata
    """
    screenshot_dir = Path(screenshot_dir)

    # Load domains from JSONL
    print(f"Loading domains from {jsonl_path}...")
    domains = []
    with open(jsonl_path, 'r') as f:
        for line in f:
            domains.append(json.loads(line))

    print(f"Found {len(domains)} domains in JSONL")

    results = []
    processed = 0
    with_screenshots = 0

    for idx, domain_data in enumerate(domains):
        domain_id = domain_data['id']
        metadata = domain_data['metadata']
        registrable = metadata.get('registrable', '')

        # Find screenshot file - try multiple patterns
        screenshot_file = None
        patterns = [
            f"{registrable.replace('.', '_')}*.png",
            f"{registrable}*.png",
            f"*{registrable}*.png"
        ]

        for pattern in patterns:
            matches = list(screenshot_dir.glob(pattern))
            if matches:
                screenshot_file = matches[0]
                break

        # Extract visual features if screenshot exists
        if screenshot_file and screenshot_file.exists():
            phash = compute_phash(screenshot_file)
            ocr_text = extract_ocr_text(screenshot_file) if HAS_OCR else ""
            ocr_length = len(ocr_text)
            ocr_has_login = int(any(word in ocr_text.lower() for word in ['login', 'sign in', 'password', 'username']))
            ocr_has_verify = int(any(word in ocr_text.lower() for word in ['verify', 'confirm', 'authenticate']))
            with_screenshots += 1
        else:
            # No screenshot available - use empty values
            phash = None
            ocr_text = ""
            ocr_length = 0
            ocr_has_login = 0
            ocr_has_verify = 0

        # Add visual features to metadata
        metadata_enriched = {
            **metadata,
            'screenshot_phash': phash,
            'ocr_text': ocr_text[:2000] if ocr_text else "",  # Limit to 2000 chars
            'ocr_length': ocr_length,
            'ocr_has_login_keywords': bool(ocr_has_login),
            'ocr_has_verify_keywords': bool(ocr_has_verify),
        }

        results.append({
            'id': domain_id,
            'metadata': metadata_enriched,
            'document': domain_data.get('document', '')
        })

        processed += 1

        # Progress indicator
        if (idx + 1) % 10 == 0:
            print(f"  Processed {idx + 1}/{len(domains)} domains...")

    # Write enriched JSONL
    with open(output_jsonl, 'w') as f:
        for result in results:
            f.write(json.dumps(result) + '\n')

    print(f"\n✓ Saved enriched data to {output_jsonl}")
    print(f"  Total domains: {processed}")
    print(f"  With screenshots: {with_screenshots}")
    print(f"  Without screenshots: {processed - with_screenshots}")

    return results

def process_favicons(html_dir, output_csv):
    """Extract favicons from HTML files and compute phash"""
    # Note: This is simplified - actual favicon extraction needs HTTP fetch or HTML parsing
    # For now, we'll use existing favicon hashes from metadata
    print("Favicon phash extraction requires actual favicon images")
    print("Using existing MD5/SHA256 hashes from metadata instead")
    return None

def main():
    ap = argparse.ArgumentParser(description="Extract visual features from screenshots")
    ap.add_argument("--jsonl", default="dump_all.jsonl", help="Input JSONL with domain data")
    ap.add_argument("--screenshots", default="Pipeline/out/screenshots", help="Screenshot directory")
    ap.add_argument("--output", default="AIML/data/visual_features.jsonl", help="Output JSONL")
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

    # Create output directory if needed
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    # Process screenshots
    print("="*70)
    print("VISUAL FEATURE EXTRACTION")
    print("="*70)
    results = process_screenshots(args.jsonl, args.screenshots, args.output)

    # Stats
    ocr_count = sum(1 for r in results if r['metadata'].get('ocr_length', 0) > 0)
    login_count = sum(1 for r in results if r['metadata'].get('ocr_has_login_keywords', False))
    verify_count = sum(1 for r in results if r['metadata'].get('ocr_has_verify_keywords', False))
    phashes = [r['metadata'].get('screenshot_phash') for r in results if r['metadata'].get('screenshot_phash')]

    print(f"\nVisual Features Summary:")
    print(f"  Domains with OCR text: {ocr_count}/{len(results)}")
    print(f"  Domains with login keywords: {login_count}")
    print(f"  Domains with verify keywords: {verify_count}")
    print(f"  Unique phashes: {len(set(phashes))}")

    # Check for duplicate phashes (identical screenshots)
    if len(phashes) != len(set(phashes)):
        print(f"\n[WARNING] Found duplicate phashes (visually similar screenshots)")

if __name__ == "__main__":
    main()
