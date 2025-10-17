"""Fix domain names in visual features CSV"""
import pandas as pd
import re

# Load visual features
df = pd.read_csv("data/cse_visual_features.csv")

# Fix domain column: remove _hash_full pattern
# Pattern: domain_8charhash_full
def extract_domain(filename):
    # Remove _full.png suffix
    name = filename.replace('_full.png', '')
    # Pattern: domain_hash where hash is 8 hex chars
    # Split from right, remove last part (hash)
    parts = name.rsplit('_', 1)
    if len(parts) == 2 and len(parts[1]) == 8:
        return parts[0]  # Return domain without hash
    return name  # Fallback

df['registrable'] = df['domain'].apply(extract_domain)

# Save
df[['registrable', 'screenshot_path', 'screenshot_phash', 'ocr_text',
    'ocr_length', 'ocr_has_login_keywords', 'ocr_has_verify_keywords']].to_csv(
    "data/cse_visual_features.csv", index=False
)

print(f"Fixed {len(df)} domain names")
print("\nSample mappings:")
for i in range(min(5, len(df))):
    print(f"  {df.iloc[i]['domain']} -> {df.iloc[i]['registrable']}")
