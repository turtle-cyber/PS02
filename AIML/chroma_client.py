#!/usr/bin/env python3
"""
ChromaDB Client for AIML Detection System

Connects to ChromaDB to fetch domain features collected by the crawler pipeline
and runs AIML detection on them.
"""

import os
import json
import chromadb
from chromadb import HttpClient
from chromadb.config import DEFAULT_TENANT, DEFAULT_DATABASE, Settings
from typing import List, Dict, Optional
from pathlib import Path
import sys

# Import AIML detector
sys.path.append(str(Path(__file__).parent))
from unified_detector import UnifiedPhishingDetector


class ChromaDBClient:
    """Client to fetch domain data from ChromaDB and run AIML detection"""
    
    def __init__(self, 
                 chroma_host: str = "localhost",
                 chroma_port: int = 8000,
                 collection_name: str = "domains"):
        """
        Initialize ChromaDB client
        
        Args:
            chroma_host: ChromaDB server host
            chroma_port: ChromaDB server port
            collection_name: ChromaDB collection name
        """
        self.chroma_host = chroma_host
        self.chroma_port = chroma_port
        self.collection_name = collection_name
        self.client = None
        self.collection = None
        
        # Initialize AIML detector
        print("Initializing AIML detector...")
        self.detector = UnifiedPhishingDetector()
        self.detector.load_models()
        print("✓ AIML detector ready\n")
    
    def connect(self):
        """Connect to ChromaDB"""
        print(f"Connecting to ChromaDB at {self.chroma_host}:{self.chroma_port}...")
        try:
            self.client = chromadb.HttpClient(
                host=self.chroma_host,
                port=self.chroma_port,
                settings=Settings(),
                tenant=DEFAULT_TENANT,
                database=DEFAULT_DATABASE
            )
            
            # Get collection
            self.collection = self.client.get_collection(name=self.collection_name)
            
            count = self.collection.count()
            print(f"✓ Connected to ChromaDB collection '{self.collection_name}'")
            print(f"✓ Collection contains {count} domains\n")
            return True
            
        except Exception as e:
            print(f" Failed to connect to ChromaDB: {e}")
            return False
    
    def get_domain(self, domain: str) -> Optional[Dict]:
        """
        Fetch a single domain from ChromaDB
        
        Args:
            domain: Domain name to fetch
            
        Returns:
            Domain metadata or None
        """
        try:
            results = self.collection.get(
                ids=[domain],
                include=["metadatas", "documents"]
            )
            
            if results and results['ids']:
                metadata = results['metadatas'][0]
                return metadata
            else:
                print(f"  Domain '{domain}' not found in ChromaDB")
                return None
                
        except Exception as e:
            print(f" Error fetching domain '{domain}': {e}")
            return None
    
    def get_all_domains(self, limit: int = None) -> List[Dict]:
        """
        Fetch all domains from ChromaDB
        
        Args:
            limit: Maximum number of domains to fetch
            
        Returns:
            List of domain metadata dictionaries
        """
        try:
            count = self.collection.count()
            fetch_limit = min(limit, count) if limit else count
            
            print(f"Fetching {fetch_limit} domains from ChromaDB...")
            
            results = self.collection.get(
                limit=fetch_limit,
                include=["metadatas", "documents"]
            )
            
            domains = []
            for i, metadata in enumerate(results['metadatas']):
                domains.append(metadata)
            
            print(f"✓ Fetched {len(domains)} domains\n")
            return domains
            
        except Exception as e:
            print(f" Error fetching domains: {e}")
            return []
    
    def query_by_verdict(self, verdict: str, limit: int = 100) -> List[Dict]:
        """
        Query domains by verdict (from crawler/rule-scorer)
        
        Args:
            verdict: Verdict to filter by (benign, phishing, suspicious)
            limit: Maximum results
            
        Returns:
            List of matching domains
        """
        try:
            results = self.collection.get(
                where={"final_verdict": verdict},
                limit=limit,
                include=["metadatas", "documents"]
            )
            
            return results['metadatas']
            
        except Exception as e:
            print(f" Error querying by verdict: {e}")
            return []
    
    def transform_chroma_to_aiml(self, chroma_metadata: Dict) -> Dict:
        """
        Transform ChromaDB metadata format to AIML detection format

        Args:
            chroma_metadata: Metadata from ChromaDB

        Returns:
            Metadata in AIML format
        """
        # Read HTML content if path exists
        document_text = ""
        html_path = chroma_metadata.get('html_path', '')
        if html_path:
            # Try original path first
            path = Path(html_path)

            # If path doesn't exist, try mapping /workspace/out to local path
            if not path.exists() and html_path.startswith('/workspace/out/'):
                local_path = html_path.replace('/workspace/out/', '/home/turtleneck/Desktop/PS02/Pipeline/out/')
                path = Path(local_path)

            if path.exists():
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        document_text = f.read()
                        print(f"  Loaded HTML: {len(document_text)} bytes from {path}")
                except Exception as e:
                    print(f"  Failed to load HTML from {path}: {e}")

        # Read OCR text if available (use excerpt from crawler)
        ocr_text = chroma_metadata.get('ocr_text_excerpt', '')

        # Map fields
        aiml_metadata = {
            'registrable': chroma_metadata.get('registrable', ''),
            'document_text': document_text,
            'ocr_text': ocr_text,
            'screenshot_path': chroma_metadata.get('screenshot_path', ''),
            'doc_form_count': chroma_metadata.get('form_count', 0),
            'doc_length': len(document_text),

            # Check if inactive (crawl_failed indicates unreachable)
            'is_inactive': chroma_metadata.get('crawl_failed', False),
            'inactive_status': 'inactive' if chroma_metadata.get('crawl_failed') else 'active',
            'inactive_reason': 'connect_failed' if chroma_metadata.get('crawl_failed') else '',

            # Copy all other fields
            **chroma_metadata
        }

        return aiml_metadata
    
    def detect_domain(self, domain: str) -> Optional[Dict]:
        """
        Fetch domain from ChromaDB and run AIML detection
        
        Args:
            domain: Domain name
            
        Returns:
            AIML detection result
        """
        # Fetch from ChromaDB
        chroma_data = self.get_domain(domain)
        if not chroma_data:
            return None
        
        # Transform to AIML format
        aiml_metadata = self.transform_chroma_to_aiml(chroma_data)
        
        # Run detection
        result = self.detector.detect(aiml_metadata)
        
        return result
    
    def detect_all(self, limit: int = None, output_file: str = None) -> List[Dict]:
        """
        Run AIML detection on all domains in ChromaDB
        
        Args:
            limit: Max domains to process
            output_file: Optional file to save results
            
        Returns:
            List of detection results
        """
        # Fetch all domains
        domains = self.get_all_domains(limit=limit)
        
        if not domains:
            print("No domains to process")
            return []
        
        print(f"Running AIML detection on {len(domains)} domains...\n")
        
        results = []
        for i, chroma_data in enumerate(domains, 1):
            try:
                # Transform to AIML format
                aiml_metadata = self.transform_chroma_to_aiml(chroma_data)
                
                # Run detection
                result = self.detector.detect(aiml_metadata)
                
                # Convert to JSON-serializable
                result = self.detector._convert_to_json_serializable(result)
                results.append(result)
                
                # Progress
                if i % 10 == 0:
                    print(f"  Processed {i}/{len(domains)} domains...")
                    
            except Exception as e:
                print(f" Error processing domain {chroma_data.get('registrable')}: {e}")
                continue
        
        print(f"\n✓ Completed {len(results)} detections\n")
        
        # Save results if requested
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"✓ Results saved to {output_file}\n")
        
        # Generate summary
        self._print_summary(results)
        
        return results
    
    def _print_summary(self, results: List[Dict]):
        """Print detection summary"""
        verdicts = {}
        for r in results:
            verdict = r['verdict']
            verdicts[verdict] = verdicts.get(verdict, 0) + 1
        
        print("="*70)
        print("AIML DETECTION SUMMARY")
        print("="*70)
        print(f"\nTotal domains: {len(results)}\n")
        
        print("Verdicts:")
        for verdict, count in sorted(verdicts.items(), key=lambda x: x[1], reverse=True):
            pct = count/len(results)*100
            print(f"  {verdict:15s}: {count:4d} ({pct:5.1f}%)")
        
        print("="*70)


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AIML ChromaDB Integration')
    parser.add_argument('--host', default='localhost', help='ChromaDB host')
    parser.add_argument('--port', type=int, default=8000, help='ChromaDB port')
    parser.add_argument('--collection', default='domains', help='ChromaDB collection name')
    parser.add_argument('--domain', help='Detect single domain')
    parser.add_argument('--all', action='store_true', help='Detect all domains')
    parser.add_argument('--limit', type=int, help='Limit number of domains')
    parser.add_argument('--output', help='Output JSON file')
    
    args = parser.parse_args()
    
    # Create client
    client = ChromaDBClient(
        chroma_host=args.host,
        chroma_port=args.port,
        collection_name=args.collection
    )
    
    # Connect to ChromaDB
    if not client.connect():
        return
    
    # Single domain detection
    if args.domain:
        print(f"Detecting domain: {args.domain}\n")
        result = client.detect_domain(args.domain)
        
        if result:
            print(json.dumps(result, indent=2))
    
    # Batch detection
    elif args.all:
        client.detect_all(limit=args.limit, output_file=args.output)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
