#!/usr/bin/env python3
"""
scripts/train_models.py — NexShield Unified Model & Knowledge Training Script
=============================================================================
Trains both the Threat Severity ML Ensemble Classifier and the RAG Knowledge
Base vector index from local CVE datasets, historical scan threats, and MITRE
compliance baselines.

Usage:
    python scripts/train_models.py --all
    python scripts/train_models.py --ml-only --cve-limit 2000
    python scripts/train_models.py --rag-only --cve-limit 5000
"""

import sys
import os
import argparse
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "nexshield"))
sys.path.insert(0, str(_ROOT))

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass


def print_banner():
    banner = r"""
 ================================================================
    _   _           ____  _     _      _     _ 
   | \ | | _____  _/ ___|| |__ (_) ___| | __| |
   |  \| |/ _ \ \/ /\___ \| '_ \| |/ _ \ |/ _` |
   | |\  |  __/>  <  ___) | | | | |  __/ | (_| |
   |_| \_|\___/_/\_\|____/|_| |_|_|\___|_|\__,_|
            AI & KNOWLEDGE TRAINING PIPELINE
 ================================================================
"""
    print(banner)


def format_bytes(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:3.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def train_ml(cve_limit: int = 5000, evaluate: bool = True) -> bool:
    print(f"\n[+] --- [1/2] Training Threat Severity ML Model ---")
    start = time.time()
    from ai_logic import train_ml_model, MODEL_PATH, VECTORIZER_PATH
    success = train_ml_model(cve_limit=cve_limit, evaluate=evaluate)
    elapsed = time.time() - start
    
    if success:
        m_size = os.path.getsize(MODEL_PATH) if os.path.exists(MODEL_PATH) else 0
        v_size = os.path.getsize(VECTORIZER_PATH) if os.path.exists(VECTORIZER_PATH) else 0
        print(f"\n[✓] ML Model Training Complete in {elapsed:.1f}s!")
        print(f"    - Model Path:      {MODEL_PATH} ({format_bytes(m_size)})")
        print(f"    - Vectorizer Path: {VECTORIZER_PATH} ({format_bytes(v_size)})")
        return True
    else:
        print("\n[X] ML Model Training failed or was aborted.")
        return False


def train_rag(cve_limit: int = 5000) -> bool:
    print(f"\n[+] --- [2/2] Building RAG Knowledge Vector Store ---")
    start = time.time()
    from rag_engine import build_and_export_rag_index, INDEX_CACHE_PATH
    stats = build_and_export_rag_index(max_cves=cve_limit)
    elapsed = time.time() - start
    
    cache_path = Path(stats.get("cache_path", INDEX_CACHE_PATH))
    c_size = cache_path.stat().st_size if cache_path.exists() else 0
    print(f"\n[✓] RAG Knowledge Base Indexed in {elapsed:.1f}s!")
    print(f"    - Total Documents:  {stats.get('total_documents', 0)}")
    print(f"    - Ingested CVEs:    {stats.get('ingested_cves', 0)}")
    print(f"    - Categories:       {stats.get('categories', {})}")
    print(f"    - Cache File:       {cache_path} ({format_bytes(c_size)})")
    return bool(stats.get("saved_to_cache"))


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="NexShield AI Model & Knowledge Store Trainer")
    parser.add_argument("--all", action="store_true", default=False, help="Train both ML model and RAG knowledge store (default)")
    parser.add_argument("--ml-only", action="store_true", default=False, help="Train only the ML ensemble threat predictor")
    parser.add_argument("--rag-only", action="store_true", default=False, help="Build only the RAG knowledge store vector index")
    parser.add_argument("--cve-limit", type=int, default=5000, help="Maximum number of CVE JSON files to ingest (default: 5000)")
    parser.add_argument("--no-eval", action="store_true", default=False, help="Skip out-of-sample test evaluation split")

    args = parser.parse_args()

    # Default to --all if neither --ml-only nor --rag-only was specified
    run_ml = args.all or args.ml_only or (not args.ml_only and not args.rag_only)
    run_rag = args.all or args.rag_only or (not args.ml_only and not args.rag_only)

    overall_start = time.time()
    ml_ok = True
    rag_ok = True

    if run_ml:
        ml_ok = train_ml(cve_limit=args.cve_limit, evaluate=not args.no_eval)

    if run_rag:
        rag_ok = train_rag(cve_limit=args.cve_limit)

    total_elapsed = time.time() - overall_start

    print("\n" + "=" * 64)
    if ml_ok and rag_ok:
        print(f" [✓] ALL REQUESTED SUBSYSTEMS SUCCESSFULLY TRAINED IN {total_elapsed:.1f}s!")
    else:
        print(f" [!] TRAINING FINISHED WITH ISSUES (ML: {'OK' if ml_ok else 'FAILED'}, RAG: {'OK' if rag_ok else 'FAILED'})")
    print("=" * 64 + "\n")

    sys.exit(0 if (ml_ok and rag_ok) else 1)


if __name__ == "__main__":
    main()
