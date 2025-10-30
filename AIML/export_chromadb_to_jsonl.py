"""
Export Complete Data from ChromaDB to JSONL

This script exports all domain data from ChromaDB to a complete JSONL file
that can be used with generate_submission.py.

Usage:
    python export_chromadb_to_jsonl.py --output dump_all_complete.jsonl
"""

import argparse
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import chromadb
from chromadb.config import Settings, DEFAULT_TENANT, DEFAULT_DATABASE

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ChromaDBExporter:
    """Export ChromaDB collection to JSONL format"""

    def __init__(self, host: str = 'localhost', port: int = 8000,
                 collection_name: str = 'domains'):
        """
        Initialize ChromaDB connection

        Args:
            host: ChromaDB host
            port: ChromaDB port
            collection_name: Collection to export
        """
        self.host = host
        self.port = port
        self.collection_name = collection_name
        self.client = None
        self.collection = None

    def connect(self):
        """Connect to ChromaDB"""
        try:
            logger.info(f"Connecting to ChromaDB at {self.host}:{self.port}")
            self.client = chromadb.HttpClient(
                host=self.host,
                port=self.port,
                settings=Settings(
                    chroma_client_auth_provider=None,
                    chroma_client_auth_credentials=None
                ),
                tenant=DEFAULT_TENANT,
                database=DEFAULT_DATABASE
            )

            # Test connection
            self.client.heartbeat()
            logger.info("✓ Connected to ChromaDB")

            # Get collection
            self.collection = self.client.get_collection(name=self.collection_name)
            count = self.collection.count()
            logger.info(f"✓ Collection '{self.collection_name}' loaded ({count} documents)")

            return True
        except Exception as e:
            logger.error(f"Failed to connect to ChromaDB: {e}")
            return False

    def export_to_jsonl(self, output_path: str, include_embeddings: bool = False):
        """
        Export collection to JSONL file

        Args:
            output_path: Output JSONL file path
            include_embeddings: Whether to include embeddings (large)
        """
        if not self.collection:
            logger.error("Not connected to ChromaDB collection")
            return False

        try:
            # Get all documents
            logger.info("Fetching all documents from ChromaDB...")
            results = self.collection.get(
                include=['metadatas', 'documents', 'embeddings' if include_embeddings else None]
            )

            ids = results['ids']
            metadatas = results['metadatas']
            documents = results['documents']
            embeddings = results.get('embeddings', [None] * len(ids)) if include_embeddings else [None] * len(ids)

            logger.info(f"Retrieved {len(ids)} documents")

            # Group by registrable domain to deduplicate
            domain_map = {}
            for i, (doc_id, metadata, document, embedding) in enumerate(zip(ids, metadatas, documents, embeddings)):
                registrable = metadata.get('registrable', 'unknown')

                # Keep the most complete entry for each domain
                if registrable not in domain_map:
                    domain_map[registrable] = {
                        'id': doc_id,
                        'metadata': metadata,
                        'document': document
                    }
                    if include_embeddings and embedding:
                        domain_map[registrable]['embedding'] = embedding
                else:
                    # Update with more complete data
                    existing = domain_map[registrable]['metadata']
                    # Prefer entries with more fields
                    if len(metadata) > len(existing):
                        domain_map[registrable] = {
                            'id': doc_id,
                            'metadata': metadata,
                            'document': document
                        }
                        if include_embeddings and embedding:
                            domain_map[registrable]['embedding'] = embedding

            logger.info(f"Deduplicated to {len(domain_map)} unique domains")

            # Write to JSONL
            output_file = Path(output_path)
            logger.info(f"Writing to {output_file}")

            written = 0
            with open(output_file, 'w') as f:
                for registrable, data in sorted(domain_map.items()):
                    # Create JSONL entry matching dump_all.jsonl format
                    entry = {
                        'id': data['id'],
                        'metadata': data['metadata'],
                        'document': data['document']
                    }
                    if include_embeddings and 'embedding' in data:
                        entry['embedding'] = data['embedding']

                    f.write(json.dumps(entry) + '\n')
                    written += 1

            logger.info(f"✓ Successfully exported {written} domains to {output_file}")
            logger.info(f"✓ File size: {output_file.stat().st_size / 1024 / 1024:.2f} MB")

            return True

        except Exception as e:
            logger.error(f"Export failed: {e}", exc_info=True)
            return False

    def print_summary(self):
        """Print summary of collection contents"""
        if not self.collection:
            logger.error("Not connected to ChromaDB collection")
            return

        try:
            # Get sample
            results = self.collection.get(limit=5, include=['metadatas'])

            logger.info("="*70)
            logger.info("CHROMADB COLLECTION SUMMARY")
            logger.info("="*70)
            logger.info(f"Collection: {self.collection_name}")
            logger.info(f"Total documents: {self.collection.count()}")

            if results['metadatas']:
                logger.info("\nSample metadata fields:")
                sample_meta = results['metadatas'][0]
                for key in sorted(sample_meta.keys())[:20]:
                    val = sample_meta[key]
                    val_str = str(val)[:50] if val else "N/A"
                    logger.info(f"  {key}: {val_str}")

            logger.info("="*70)

        except Exception as e:
            logger.error(f"Failed to print summary: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Export ChromaDB collection to JSONL format'
    )
    parser.add_argument(
        '--host',
        default='localhost',
        help='ChromaDB host (default: localhost)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='ChromaDB port (default: 8000)'
    )
    parser.add_argument(
        '--collection',
        default='domains',
        help='Collection name (default: domains)'
    )
    parser.add_argument(
        '--output',
        default='dump_all_complete.jsonl',
        help='Output JSONL file (default: dump_all_complete.jsonl)'
    )
    parser.add_argument(
        '--include-embeddings',
        action='store_true',
        help='Include embeddings in export (creates large file)'
    )
    parser.add_argument(
        '--summary-only',
        action='store_true',
        help='Only print collection summary, do not export'
    )

    args = parser.parse_args()

    # Create exporter
    exporter = ChromaDBExporter(
        host=args.host,
        port=args.port,
        collection_name=args.collection
    )

    # Connect
    if not exporter.connect():
        logger.error("Failed to connect to ChromaDB")
        return 1

    # Print summary
    exporter.print_summary()

    # Export if requested
    if not args.summary_only:
        logger.info("\nStarting export...")
        if exporter.export_to_jsonl(args.output, args.include_embeddings):
            logger.info("\n✓ Export completed successfully!")
            logger.info(f"\nYou can now use this file with generate_submission.py:")
            logger.info(f"  python generate_submission.py \\")
            logger.info(f"      --application-id AIGR-123456 \\")
            logger.info(f"      --jsonl-path {args.output}")
            return 0
        else:
            logger.error("\n✗ Export failed")
            return 1
    else:
        logger.info("\nSummary only mode - no export performed")
        return 0


if __name__ == '__main__':
    exit(main())
