
#!/usr/bin/env python3
"""
query_vi.py — Query ChromaDB for registrable-domain records (e.g., "vi.in").

This version supports:
  - Exact ID:                         --id myvi.in
  - Metadata filters (auto $and):     --registrable myvi.in --had-redirects true --min-redirects 10 ...
  - Brand filter:                     --brand VI
  - Semantic neighbors:               --semantic 15
  - LIKE filters (client-side):       --final-like lander --url-like login
  - **Dump entire collection**:       --dump-all [--page-size 1000] [--max-rows 0]
                                      Writes JSONL to --dump-path (default: dump_all.jsonl)

Notes:
- tenant/database/collection default to: default_tenant / default_database / domains
- Use --host chroma when running *inside* the Docker network; use --host localhost on the host.
"""

import argparse
import json
import sys
from datetime import datetime
from typing import Any, Dict, List

import chromadb
from chromadb import HttpClient
from chromadb.config import Settings

DEFAULT_HOST = "localhost"
DEFAULT_PORT = 8000
DEFAULT_TENANT = "default_tenant"
DEFAULT_DATABASE = "default_database"
DEFAULT_COLLECTION = "domains"
DEFAULT_OUTPUT = "vi_results.json"

def ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def connect_client(host: str, port: int, tenant: str, database: str) -> HttpClient:
    print(f"[{ts()}] Connecting to ChromaDB http://{host}:{port} (tenant={tenant}, db={database})")
    client: HttpClient = chromadb.HttpClient(
        host=host, port=port, settings=Settings(), tenant=tenant, database=database
    )
    try:
        cols = client.list_collections()
        print(f"[{ts()}] ✓ Connected. Collections: {', '.join([c.name for c in cols]) or '(none)'}")
    except Exception as e:
        print(f"[{ts()}] Warning: couldn't list collections ({e}). Proceeding.")
    return client

def get_collection(client: HttpClient, name: str):
    try:
        col = client.get_collection(name=name)
        print(f"[{ts()}] Using collection: {name}")
        return col
    except Exception as e:
        raise SystemExit(f"[{ts()}] ERROR: Could not get collection '{name}': {e}")

def flatten_get_result(res: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    ids = res.get("ids", [])
    metas = res.get("metadatas", [])
    docs = res.get("documents", [])
    for i, _id in enumerate(ids):
        out.append({
            "id": _id,
            "metadata": metas[i] if i < len(metas) else {},
            "document": docs[i] if i < len(docs) else None,
        })
    return out

def flatten_query_result(res: Dict[str, Any]) -> List[Dict[str, Any]]:
    ids = res.get("ids", [[]])
    metas = res.get("metadatas", [[]])
    docs = res.get("documents", [[]])
    dists = res.get("distances", [[]])
    out = []
    if not ids or not ids[0]:
        return out
    for i, _id in enumerate(ids[0]):
        out.append({
            "id": _id,
            "metadata": metas[0][i] if i < len(metas[0]) else {},
            "document": docs[0][i] if i < len(docs[0]) else None,
            "distance": dists[0][i] if (dists and dists[0] and i < len(dists[0])) else None,
        })
    return out

def print_row_summary(row: Dict[str, Any], expanded: bool = False):
    """Print a row summary. If expanded=True, show all metadata and document."""
    meta = row.get("metadata", {}) or {}
    doc = row.get("document")
    
    if not expanded:
        # Compact summary (original behavior)
        fields = [
            ("ID", row.get("id")),
            ("Registrable", meta.get("registrable")),
            ("Record Type", meta.get("record_type")),
            ("Enrichment Level", meta.get("enrichment_level")),
            ("URL", meta.get("url")),
            ("Verdict", meta.get("verdict")),
            ("Risk Score", meta.get("risk_score")),
            ("Confidence", meta.get("confidence")),
            ("Has Features", meta.get("has_features")),
            ("Has Verdict", meta.get("has_verdict")),
        ]
        parts = [f"{k}: {v}" for k, v in fields if v not in (None, "", [])]
        print("  • " + " | ".join(parts))
    else:
        # Expanded view - show everything
        print(f"\n{'='*80}")
        print(f"ID: {row.get('id')}")
        print(f"{'='*80}")
        
        # Metadata section
        print("\n📋 METADATA:")
        print("-" * 80)
        if meta:
            # Group related fields
            identity = {k: v for k, v in meta.items() if k in ("registrable", "url", "cse_id", "seed_registrable")}
            enrichment = {k: v for k, v in meta.items() if k in ("record_type", "enrichment_level", "has_features", "has_verdict", "crawl_failed")}
            verdict = {k: v for k, v in meta.items() if k in ("verdict", "risk_score", "confidence", "reasons")}
            domain_info = {k: v for k, v in meta.items() if k in ("domain_age_days", "is_newly_registered", "is_very_new", "days_until_expiry", "registrar", "country")}
            features = {k: v for k, v in meta.items() if k in ("url_length", "url_entropy", "num_subdomains", "form_count", "password_fields", "email_fields", "has_credential_form", "keyword_count", "phishing_keywords")}
            network = {k: v for k, v in meta.items() if k in ("a_count", "mx_count", "ns_count")}
            ssl = {k: v for k, v in meta.items() if k.startswith(("is_self_signed", "cert_", "is_newly_issued"))}
            categories = {k: v for k, v in meta.items() if k.startswith("cat_")}
            other = {k: v for k, v in meta.items() if k not in {**identity, **enrichment, **verdict, **domain_info, **features, **network, **ssl, **categories}}
            
            if identity:
                print("\n  🎯 Identity:")
                for k, v in identity.items():
                    print(f"     {k}: {v}")
            
            if enrichment:
                print("\n  📊 Enrichment Status:")
                for k, v in enrichment.items():
                    print(f"     {k}: {v}")
            
            if verdict:
                print("\n  🚨 Verdict:")
                for k, v in verdict.items():
                    print(f"     {k}: {v}")
            
            if domain_info:
                print("\n  🌐 Domain Info:")
                for k, v in domain_info.items():
                    flag = ""
                    if k == "is_very_new" and v:
                        flag = " ⚠️"
                    elif k == "is_newly_registered" and v:
                        flag = " ⚠️"
                    print(f"     {k}: {v}{flag}")
            
            if features:
                print("\n  🔍 Page Features:")
                for k, v in features.items():
                    flag = ""
                    if k == "has_credential_form" and v:
                        flag = " 🚨"
                    print(f"     {k}: {v}{flag}")
            
            if network:
                print("\n  📡 Network:")
                for k, v in network.items():
                    print(f"     {k}: {v}")
            
            if ssl:
                print("\n  🔒 SSL/TLS:")
                for k, v in ssl.items():
                    flag = ""
                    if k == "is_self_signed" and v:
                        flag = " 🚨"
                    print(f"     {k}: {v}{flag}")
            
            if categories:
                print("\n  📈 Risk Categories:")
                for k, v in categories.items():
                    cat_name = k.replace("cat_", "")
                    print(f"     {cat_name}: {v}")
            
            if other:
                print("\n  📎 Other:")
                for k, v in other.items():
                    print(f"     {k}: {v}")
        
        # Document section
        if doc:
            print("\n📄 SEARCHABLE DOCUMENT:")
            print("-" * 80)
            print(doc)
        
        print(f"\n{'='*80}\n")

def parse_where_kv(pairs: List[str]) -> List[Dict[str, Any]]:
    clauses: List[Dict[str, Any]] = []
    for p in pairs or []:
        if "=" not in p:
            continue
        k, v = p.split("=", 1)
        vl = v.strip()
        if vl.lower() in ("true", "false"):
            clauses.append({k: (vl.lower() == "true")})
        else:
            try:
                clauses.append({k: int(vl)})
            except ValueError:
                try:
                    clauses.append({k: float(vl)})
                except ValueError:
                    clauses.append({k: vl})
    return clauses

def build_where(args: argparse.Namespace) -> Dict[str, Any]:
    clauses: List[Dict[str, Any]] = []

    if args.registrable:
        clauses.append({"registrable": args.registrable})
    if args.had_redirects is not None:
        clauses.append({"had_redirects": args.had_redirects})

    if args.min_redirects is not None and args.max_redirects is not None:
        clauses.append({"redirect_count": {"$gte": args.min_redirects, "$lte": args.max_redirects}})
    elif args.min_redirects is not None:
        clauses.append({"redirect_count": {"$gte": args.min_redirects}})
    elif args.max_redirects is not None:
        clauses.append({"redirect_count": {"$lte": args.max_redirects}})

    clauses.extend(parse_where_kv(args.where_kv))

    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    return {"$and": clauses}

def match_like(meta: Dict[str, Any], key: str, needle: str) -> bool:
    if not needle:
        return True
    val = meta.get(key)
    if not val or not isinstance(val, str):
        return False
    return needle.lower() in val.lower()

def dump_all(col, page_size: int, max_rows: int, dump_path: str):
    """
    Dump the entire collection to JSONL.
    Uses offset-based pagination if supported; otherwise falls back to repeated get(limit=page_size).
    """
    print(f"[{ts()}] Dumping entire collection to {dump_path} (page_size={page_size}, max_rows={max_rows or 'unlimited'})")
    total = 0
    offset = 0
    wrote = 0

    with open(dump_path, "w", encoding="utf-8") as fh:
        while True:
            try:
                # Try with offset first (newer servers)
                res = col.get(include=["metadatas", "documents"], limit=page_size, offset=offset)
            except TypeError:
                # Older servers don't support offset; just fetch page_size repeatedly
                res = col.get(include=["metadatas", "documents"], limit=page_size)
            rows = flatten_get_result(res)
            if not rows:
                break
            for r in rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            wrote += len(rows)
            total += len(rows)
            print(f"[{ts()}]  … wrote {wrote} rows so far")
            if 0 < max_rows <= total:
                break
            offset += len(rows)
            if len(rows) < page_size:
                break
    print(f"[{ts()}] ✓ Dump complete. Wrote {wrote} rows to {dump_path}")

def main():
    ap = argparse.ArgumentParser(description="Query ChromaDB for registrable-domain records")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--tenant", default=DEFAULT_TENANT)
    ap.add_argument("--database", default=DEFAULT_DATABASE)
    ap.add_argument("--collection", default=DEFAULT_COLLECTION)

    # query modes
    ap.add_argument("--id", help="Exact ID to fetch (registrable domain)")
    ap.add_argument("--registrable", help="Filter by metadata registrable (e.g., vi.in)")
    ap.add_argument("--brand", help="Filter by brand/CSE id in metadata (e.g., SBI)")
    ap.add_argument("--semantic", type=int, default=0, help="Also run a semantic search (neighbors)")

    # feature filters
    ap.add_argument("--had-redirects", type=lambda s: s.lower() == "true" if isinstance(s, str) else bool(s), help="true/false")
    ap.add_argument("--min-redirects", type=int, help="Minimum redirect_count")
    ap.add_argument("--max-redirects", type=int, help="Maximum redirect_count")
    ap.add_argument("--final-like", help="Substring to match in metadata.final_url (client-side)")
    ap.add_argument("--url-like", help="Substring to match in metadata.url (client-side)")
    ap.add_argument("--where-kv", action="append", default=[], help="Extra metadata equality filters, key=value (repeatable)")

    # dump-all mode
    ap.add_argument("--dump-all", action="store_true", help="Dump the entire collection to JSONL")
    ap.add_argument("--page-size", type=int, default=1000, help="Fetch this many rows per page")
    ap.add_argument("--max-rows", type=int, default=0, help="Stop after writing this many rows (0 = unlimited)")
    ap.add_argument("--dump-path", default="dump_all.jsonl", help="Where to write JSONL")

    ap.add_argument("--limit", type=int, default=1000, help="Max rows to fetch in filtered modes")
    ap.add_argument("--output", default=DEFAULT_OUTPUT, help="Write full JSON summary to this file")
    ap.add_argument("--expanded", action="store_true", help="Show full expanded output with all fields")
    ap.add_argument("--export-json", action="store_true", help="Export full records as pretty JSON")
    args = ap.parse_args()

    client = connect_client(args.host, args.port, args.tenant, args.database)
    col = get_collection(client, args.collection)

    # DUMP-ALL short-circuit
    if args.dump_all:
        dump_all(col, page_size=args.page_size, max_rows=args.max_rows, dump_path=args.dump_path)
        return 0

    results = {
        "timestamp": datetime.now().isoformat(),
        "server": f"http://{args.host}:{args.port}",
        "tenant": args.tenant,
        "database": args.database,
        "collection": args.collection,
        "queries": {},
        "summary": {},
    }
    
    # Before writing results
    if args.export_json:
        # Pretty print each record
        for query_name, rows in results["queries"].items():
            if rows:
                print(f"\n{'='*80}")
                print(f"Query: {query_name}")
                print('='*80)
                for r in rows:
                    print(json.dumps(r, indent=2, ensure_ascii=False))

    if args.id:
        print(f"\n[{ts()}] Strategy 1 — get(ids=[{args.id!r}])")
        try:
            res = col.get(ids=[args.id], include=["metadatas", "documents"])
            rows = flatten_get_result(res)
            print(f"[{ts()}] Found {len(rows)} rows by id.")
            for r in rows[:3]:
                rint_row_summary(r, expanded=args.expanded)
            results["queries"]["by_id"] = rows
        except Exception as e:
            print(f"[{ts()}] ERROR in get(ids): {e}")
            results["queries"]["by_id"] = []

    where = build_where(args)
    if where:
        print(f"\n[{ts()}] Strategy 2 — get(where={where}) limit={args.limit}")
        try:
            res = col.get(where=where, include=["metadatas", "documents"], limit=args.limit)
            rows = flatten_get_result(res)
            if args.final_like:
                rows = [r for r in rows if match_like(r.get("metadata", {}), "final_url", args.final_like)]
            if args.url_like:
                rows = [r for r in rows if match_like(r.get("metadata", {}), "url", args.url_like)]
            print(f"[{ts()}] Found {len(rows)} rows by metadata filters.")
            for r in rows[:5]:
                print_row_summary(r)
            results["queries"]["by_where"] = rows
        except Exception as e:
            print(f"[{ts()}] ERROR in get(where): {e}")
            results["queries"]["by_where"] = []

    if args.brand:
        print(f"\n[{ts()}] Strategy 3 — get(where={{'cse_id': {args.brand!r}}})")
        try:
            res = col.get(where={"cse_id": args.brand}, include=["metadatas", "documents"], limit=args.limit)
            rows = flatten_get_result(res)
            print(f"[{ts()}] Found {len(rows)} rows by metadata.cse_id.")
            for r in rows[:3]:
                rint_row_summary(r, expanded=args.expanded)
            results["queries"]["by_brand"] = rows
        except Exception as e:
            print(f"[{ts()}] ERROR in brand get(where): {e}")
            results["queries"]["by_brand"] = []

    if args.semantic and (args.registrable or args.id):
        text = args.registrable or args.id
        print(f"\n[{ts()}] Strategy 4 — semantic query for '{text}' (n_results={args.semantic})")
        try:
            qr = col.query(
                query_texts=[f"{text} domain registrable features whois"],
                include=["metadatas", "documents", "distances"],
                n_results=args.semantic,
            )
            qrows = flatten_query_result(qr)
            print(f"[{ts()}] Found {len(qrows)} semantically similar rows.")
            for r in qrows[:3]:
                d = r.get("distance")
                print(f"  • distance={d:.4f} | ", end=""); print_row_summary(r)
            results["queries"]["semantic"] = qrows
        except Exception as e:
            print(f"[{ts()}] ERROR in semantic query(): {e}")
            results["queries"]["semantic"] = []

    results["summary"] = {k: len(v) for k, v in results["queries"].items()}
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    print(f"\n[{ts()}] ✓ Wrote full JSON to {args.output}")

    total = sum(results["summary"].values())
    if total == 0:
        print("\n[HINT] No matches found. Check host/tenant/database/collection or that ingestion completed.")
        print("       If running inside Docker, try: --host chroma")

    return 0

if __name__ == "__main__":
    sys.exit(main())
