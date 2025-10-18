"""Extract visual features from Pipeline/out/screenshots"""
import pandas as pd
from pathlib import Path
from PIL import Image
import imagehash
from tqdm import tqdm

def compute_phash(img_path):
    """Compute perceptual hash"""
    try:
        img = Image.open(img_path)
        return str(imagehash.phash(img))
    except Exception as e:
        print(f"Error: {img_path}: {e}")
        return None

# Process screenshots from new pipeline
screenshot_dir = Path("Pipeline/out/screenshots")
screenshots = list(screenshot_dir.glob("*.png")) + list(screenshot_dir.glob("*.jpg"))

print(f"Found {len(screenshots)} new screenshots")

results = []
for img_path in tqdm(screenshots, desc="Computing phashes"):
    # Extract domain from filename: domain_hash_full.png -> domain_hash
    stem = img_path.stem  # e.g., "bankofbaroda.in_e8d308eb_full"
    if stem.endswith("_full"):
        domain_with_hash = stem[:-5]  # Remove "_full"
    else:
        domain_with_hash = stem

    # Extract just the domain (remove hash suffix)
    parts = domain_with_hash.rsplit('_', 1)
    if len(parts) == 2:
        domain = parts[0]
    else:
        domain = domain_with_hash

    phash = compute_phash(img_path)

    results.append({
        'domain': domain,
        'registrable': domain,
        'screenshot_path': str(img_path),
        'screenshot_phash': phash,
        'ocr_text': '',
        'ocr_length': 0,
        'ocr_has_login_keywords': 0,
        'ocr_has_verify_keywords': 0,
    })

df_new_visual = pd.DataFrame(results)

# Load existing visual features
existing_path = Path("AIML/data/cse_visual_features.csv")
if existing_path.exists():
    old_visual = pd.read_csv(existing_path)
    print(f"Existing visual features: {len(old_visual)} records")

    # Merge and deduplicate
    df_visual = pd.concat([old_visual, df_new_visual], ignore_index=True)
    df_visual = df_visual.drop_duplicates(subset=['registrable'], keep='last')
    print(f"After merge: {len(df_visual)} total ({len(df_visual) - len(old_visual)} new)")
else:
    df_visual = df_new_visual

# Save
df_visual.to_csv("AIML/data/cse_visual_features.csv", index=False)
print(f"\nSaved {len(df_visual)} visual features to AIML/data/cse_visual_features.csv")
