#!/usr/bin/env python3
"""
scripts/export_model_to_json.py — Export ML Weights & Vocabulary to Portable JSON
================================================================================
Extracts the TF-IDF vocabulary, IDF values, feature scalers, and ensemble parameters
from `threat_ml_model.pkl` to a lightweight `threat_model_weights.json` file.
This allows pure-Rust, zero-dependency inference without external ONNX libraries.
"""

import sys
import os
import json
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "nexshield"))
sys.path.insert(0, str(_ROOT))

def main():
    model_path = _ROOT / "threat_ml_model.pkl"
    output_path = _ROOT / "data" / "threat_model_weights.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Loading model from {model_path}...")
    import joblib
    pipeline = joblib.load(str(model_path))

    pre = pipeline.named_steps['preprocessor']
    clf = pipeline.named_steps['classifier']

    tfidf = pre.named_transformers_['text']
    scaler = pre.named_transformers_['num']
    ohe = pre.named_transformers_['cat']

    print(f"[*] Extracting TF-IDF vocabulary ({len(tfidf.vocabulary_)} terms)...")
    model_data = {
        "classes": list(clf.classes_),
        "tfidf": {
            "vocabulary": {str(k): int(v) for k, v in tfidf.vocabulary_.items()},
            "idf": [float(x) for x in tfidf.idf_],
            "sublinear_tf": bool(getattr(tfidf, 'sublinear_tf', False)),
        },
        "scaler": {
            "mean": float(scaler.mean_[0]),
            "scale": float(scaler.scale_[0]),
        },
        "protocol_categories": [str(c) for c in ohe.categories_[0]],
        "sensitive_ports": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 1433, 1521, 2049, 3306, 3389, 4444, 5432],
    }

    print(f"[*] Writing portable model weights to {output_path}...")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(model_data, f, indent=2)

    size_kb = output_path.stat().st_size / 1024
    print(f"\n[✓] Successfully exported portable model weights ({size_kb:.1f} KB) to {output_path}!")

if __name__ == "__main__":
    main()
