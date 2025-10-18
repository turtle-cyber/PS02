"""Rebuild favicon and phash databases from cse_all_features.csv"""
import pandas as pd
from pathlib import Path

print("Rebuilding hash databases...")

# Load merged features
df = pd.read_csv("AIML/data/cse_all_features.csv")
print(f"Loaded {len(df)} CSE domains")

# 1. Favicon hash database
favicon_db = df[df['favicon_md5'].notna() & (df['favicon_md5'] != '')][
    ['registrable', 'favicon_md5', 'favicon_sha256']
].drop_duplicates(subset=['favicon_md5'])

favicon_db.to_csv("AIML/data/cse_favicon_db.csv", index=False)
print(f"\nFavicon DB: {len(favicon_db)} unique favicons")

# 2. Screenshot phash database
phash_db = df[df['screenshot_phash'].notna() & (df['screenshot_phash'] != '')][
    ['registrable', 'screenshot_phash']
].drop_duplicates(subset=['screenshot_phash'])

phash_db.to_csv("AIML/data/cse_phash_db.csv", index=False)
print(f"Phash DB: {len(phash_db)} unique phashes")

print("\nSaved:")
print("  AIML/data/cse_favicon_db.csv")
print("  AIML/data/cse_phash_db.csv")
