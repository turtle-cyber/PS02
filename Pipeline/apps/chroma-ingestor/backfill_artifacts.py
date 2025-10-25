#!/usr/bin/env python3
"""
Backfill missing artifact paths (screenshot_path, html_path, pdf_path) in ChromaDB.

This script scans the /Pipeline/out/ directories for artifacts and updates ChromaDB
entries that are missing these paths.

Usage:
    python backfill_artifacts.py --dry-run  # Preview changes
    python backfill_artifacts.py            # Apply changes
"""

import os
import sys
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple
import chromadb
from chromadb.config import Settings

# Configuration
CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = os.getenv("CHROMA_PORT", "8000")
# Check if running in Docker container (artifacts at /data/out) or host (at /home/.../out)
if Path("/data/out").exists():
    ARTIFACTS_BASE = Path("/data/out")
else:
    ARTIFACTS_BASE = Path("/Pipeline/out")
VARIANTS_COLLECTION = "domains"
ORIGINALS_COLLECTION = "original_domains"


def scan_artifacts() -> Dict[str, Dict[str, str]]:
    """
    Scan /Pipeline/out/ directories and build a mapping of domains to artifact paths.

    Returns:
        Dict mapping domain_hash -> {screenshot_path, html_path, pdf_path}

    Example filename: www.example.com_abc123_full.png
    - domain: www.example.com
    - hash: abc123
    - key: www.example.com_abc123
    """
    artifacts = defaultdict(dict)

    # Scan screenshots
    screenshots_dir = ARTIFACTS_BASE / "screenshots"
    if screenshots_dir.exists():
        for file in screenshots_dir.iterdir():
            if file.is_file() and file.suffix == ".png":
                # Extract domain and hash from filename
                # Format: domain_hash_full.png or domain_hash.png
                filename = file.stem  # Remove .png
                if filename.endswith("_full"):
                    filename = filename[:-5]  # Remove _full suffix

                # Split by last underscore to separate hash
                parts = filename.rsplit("_", 1)
                if len(parts) == 2:
                    domain, hash_part = parts
                    key = f"{domain}_{hash_part}"
                    # Store paths in ChromaDB format (/workspace/out/...)
                    chroma_path = str(file.absolute()).replace("/data/out/", "/workspace/out/")
                    artifacts[key]["screenshot_path"] = chroma_path
                    artifacts[key]["domain"] = domain
                    artifacts[key]["hash"] = hash_part

    # Scan HTML files
    html_dir = ARTIFACTS_BASE / "html"
    if html_dir.exists():
        for file in html_dir.iterdir():
            if file.is_file() and file.suffix == ".html":
                filename = file.stem  # Remove .html
                parts = filename.rsplit("_", 1)
                if len(parts) == 2:
                    domain, hash_part = parts
                    key = f"{domain}_{hash_part}"
                    # Store paths in ChromaDB format (/workspace/out/...)
                    chroma_path = str(file.absolute()).replace("/data/out/", "/workspace/out/")
                    artifacts[key]["html_path"] = chroma_path
                    artifacts[key]["domain"] = domain
                    artifacts[key]["hash"] = hash_part

    # Scan PDF files
    pdfs_dir = ARTIFACTS_BASE / "pdfs"
    if pdfs_dir.exists():
        for file in pdfs_dir.iterdir():
            if file.is_file() and file.suffix == ".pdf":
                filename = file.stem  # Remove .pdf
                parts = filename.rsplit("_", 1)
                if len(parts) == 2:
                    domain, hash_part = parts
                    key = f"{domain}_{hash_part}"
                    # Store paths in ChromaDB format (/workspace/out/...)
                    chroma_path = str(file.absolute()).replace("/data/out/", "/workspace/out/")
                    artifacts[key]["pdf_path"] = chroma_path
                    artifacts[key]["domain"] = domain
                    artifacts[key]["hash"] = hash_part

    return dict(artifacts)


def extract_registrable_domain(domain: str) -> str:
    """
    Extract registrable domain from FQDN.

    Examples:
        www.example.com -> example.com
        example.co.uk -> example.co.uk
        www.example.co.in -> example.co.in
    """
    if not domain:
        return domain

    parts = domain.split('.')

    # Handle multi-part TLDs
    multi_part_tlds = ['co.in', 'org.in', 'gov.in', 'net.in', 'ac.in',
                       'co.uk', 'org.uk', 'ac.uk', 'com.au', 'co.za']

    if len(parts) >= 3:
        last_two = '.'.join(parts[-2:])
        if last_two in multi_part_tlds:
            return '.'.join(parts[-3:])

    if len(parts) >= 2:
        return '.'.join(parts[-2:])

    return domain


def backfill_collection(collection, artifacts: Dict[str, Dict[str, str]],
                       collection_name: str, dry_run: bool = True) -> Tuple[int, int]:
    """
    Backfill a ChromaDB collection with missing artifact paths.

    Args:
        collection: ChromaDB collection object
        artifacts: Dict mapping domain_hash -> artifact paths
        collection_name: Name of the collection (for logging)
        dry_run: If True, only preview changes without updating

    Returns:
        Tuple of (total_checked, total_updated)
    """
    print(f"\n{'='*60}")
    print(f"Processing collection: {collection_name}")
    print(f"{'='*60}")

    # Get all documents from collection
    print(f"Fetching all documents from {collection_name}...")
    results = collection.get(
        limit=100000,  # Get all documents
        include=['metadatas', 'documents']
    )

    total_docs = len(results['ids'])
    print(f"Found {total_docs} documents in {collection_name}")

    updates = []
    total_checked = 0
    total_updated = 0

    for idx, doc_id in enumerate(results['ids']):
        metadata = results['metadatas'][idx]
        document = results['documents'][idx]

        # Extract domain info from metadata
        registrable = metadata.get('registrable', '')
        url = metadata.get('url', '')

        # Strategy 1: Extract domain from ChromaDB ID (format: "domain:hash")
        id_domain = None
        if ':' in doc_id:
            id_domain = doc_id.split(':')[0]

        # Strategy 2: Extract domain from document text
        doc_domain = None
        if document:
            # Look for "Domain: example.com" pattern in document
            import re
            domain_match = re.search(r'Domain:\s+([a-zA-Z0-9.-]+)', document)
            if domain_match:
                doc_domain = domain_match.group(1)

        # Strategy 3: Try to extract domain from URL if available
        url_domain = None
        if url:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.hostname:
                    url_domain = parsed.hostname
            except:
                pass

        # Build comprehensive list of domains to check (priority order)
        domains_to_check = []

        # Add ID domain (highest priority - most specific)
        if id_domain:
            domains_to_check.append(id_domain)
            # Also check with www prefix
            if not id_domain.startswith('www.'):
                domains_to_check.append(f'www.{id_domain}')

        # Add document domain
        if doc_domain and doc_domain not in domains_to_check:
            domains_to_check.append(doc_domain)
            if not doc_domain.startswith('www.'):
                domains_to_check.append(f'www.{doc_domain}')

        # Add URL domain
        if url_domain and url_domain not in domains_to_check:
            domains_to_check.append(url_domain)

        # Add registrable domain (lowest priority - least specific)
        if registrable and registrable not in domains_to_check:
            domains_to_check.append(registrable)
            if not registrable.startswith('www.'):
                domains_to_check.append(f'www.{registrable}')

        # Check if this document is missing any artifact paths
        missing_paths = []
        if not metadata.get('screenshot_path'):
            missing_paths.append('screenshot_path')
        if not metadata.get('html_path'):
            missing_paths.append('html_path')
        if not metadata.get('pdf_path'):
            missing_paths.append('pdf_path')

        if not missing_paths:
            continue

        total_checked += 1

        # Try to find matching artifacts
        found_artifacts = None
        for domain in domains_to_check:
            for key, artifact_data in artifacts.items():
                if artifact_data.get('domain') == domain:
                    found_artifacts = artifact_data
                    break
            if found_artifacts:
                break

        if found_artifacts:
            # Build update metadata
            update_metadata = {}
            updated_fields = []

            if 'screenshot_path' in missing_paths and found_artifacts.get('screenshot_path'):
                update_metadata['screenshot_path'] = found_artifacts['screenshot_path']
                updated_fields.append('screenshot_path')

            if 'html_path' in missing_paths and found_artifacts.get('html_path'):
                update_metadata['html_path'] = found_artifacts['html_path']
                updated_fields.append('html_path')

            if 'pdf_path' in missing_paths and found_artifacts.get('pdf_path'):
                update_metadata['pdf_path'] = found_artifacts['pdf_path']
                updated_fields.append('pdf_path')

            if update_metadata:
                total_updated += 1

                if dry_run:
                    print(f"\n[DRY-RUN] Would update {doc_id}")
                    print(f"  Domains checked: {', '.join(domains_to_check[:3])}")  # Show first 3
                    print(f"  Fields to update: {', '.join(updated_fields)}")
                    for field, value in update_metadata.items():
                        print(f"    {field}: {value}")
                else:
                    # Merge with existing metadata
                    merged_metadata = {**metadata, **update_metadata}

                    # Update ChromaDB
                    collection.update(
                        ids=[doc_id],
                        metadatas=[merged_metadata]
                    )

                    print(f"✓ Updated {doc_id} (from {id_domain or registrable}) - fields: {', '.join(updated_fields)}")

        # Progress indicator
        if (idx + 1) % 1000 == 0:
            print(f"  Progress: {idx + 1}/{total_docs} documents processed...")

    return total_checked, total_updated


def main():
    parser = argparse.ArgumentParser(description='Backfill missing artifact paths in ChromaDB')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview changes without applying them')
    args = parser.parse_args()

    mode = "DRY-RUN MODE" if args.dry_run else "LIVE MODE"
    print(f"\n{'='*60}")
    print(f"ChromaDB Artifact Paths Backfill Script - {mode}")
    print(f"{'='*60}")

    # Step 1: Scan filesystem for artifacts
    print("\n[Step 1] Scanning filesystem for artifacts...")
    print(f"Artifacts directory: {ARTIFACTS_BASE}")

    artifacts = scan_artifacts()
    print(f"✓ Found {len(artifacts)} unique domain+hash combinations with artifacts")

    # Show sample artifacts
    print("\nSample artifacts found:")
    for i, (key, data) in enumerate(list(artifacts.items())[:5]):
        print(f"  {key}:")
        for field, value in data.items():
            if field not in ['domain', 'hash']:
                print(f"    - {field}: {Path(value).name if value else 'N/A'}")
        if i >= 4:
            break

    # Step 2: Connect to ChromaDB
    print(f"\n[Step 2] Connecting to ChromaDB at {CHROMA_HOST}:{CHROMA_PORT}...")
    try:
        client = chromadb.HttpClient(
            host=CHROMA_HOST,
            port=CHROMA_PORT
        )
        print("✓ Connected to ChromaDB")
    except Exception as e:
        print(f"✗ Failed to connect to ChromaDB: {e}")
        sys.exit(1)

    # Step 3: Get collections
    print("\n[Step 3] Getting collections...")
    try:
        variants_col = client.get_collection(name=VARIANTS_COLLECTION)
        print(f"✓ Got collection: {VARIANTS_COLLECTION}")

        originals_col = client.get_collection(name=ORIGINALS_COLLECTION)
        print(f"✓ Got collection: {ORIGINALS_COLLECTION}")
    except Exception as e:
        print(f"✗ Failed to get collections: {e}")
        sys.exit(1)

    # Step 4: Backfill variants collection
    print(f"\n[Step 4] Backfilling {VARIANTS_COLLECTION} collection...")
    variants_checked, variants_updated = backfill_collection(
        variants_col, artifacts, VARIANTS_COLLECTION, dry_run=args.dry_run
    )

    # Step 5: Backfill originals collection
    print(f"\n[Step 5] Backfilling {ORIGINALS_COLLECTION} collection...")
    originals_checked, originals_updated = backfill_collection(
        originals_col, artifacts, ORIGINALS_COLLECTION, dry_run=args.dry_run
    )

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Artifacts scanned: {len(artifacts)}")
    print(f"\n{VARIANTS_COLLECTION}:")
    print(f"  Documents with missing paths: {variants_checked}")
    print(f"  Documents updated: {variants_updated}")
    print(f"\n{ORIGINALS_COLLECTION}:")
    print(f"  Documents with missing paths: {originals_checked}")
    print(f"  Documents updated: {originals_updated}")
    print(f"\nTotal documents updated: {variants_updated + originals_updated}")

    if args.dry_run:
        print(f"\n⚠️  This was a DRY-RUN. No changes were made.")
        print(f"Run without --dry-run to apply changes.")
    else:
        print(f"\n✓ Backfill complete!")

    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
