#!/usr/bin/env python3
"""
scripts/export_to_onnx.py — Export Scikit-Learn Threat Pipeline to ONNX
======================================================================
Converts `threat_ml_model.pkl` to `threat_ml_model.onnx` for native,
thread-safe, high-performance inference in Rust (via the `ort` crate).

Prerequisites:
    pip install skl2onnx onnx onnxruntime

Usage:
    python scripts/export_to_onnx.py [--model-path threat_ml_model.pkl] [--output threat_ml_model.onnx]
"""

import sys
import os
import argparse
from pathlib import Path

# Add project root and nexshield to sys.path so custom unpicklers work
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "nexshield"))
sys.path.insert(0, str(_ROOT))

def main():
    parser = argparse.ArgumentParser(description="Export NexShield Scikit-Learn Pipeline to ONNX")
    parser.add_argument("--model-path", default=str(_ROOT / "threat_ml_model.pkl"), help="Path to input .pkl model")
    parser.add_argument("--output", default=str(_ROOT / "threat_ml_model.onnx"), help="Path to output .onnx file")
    args = parser.parse_args()

    model_path = Path(args.model_path)
    if not model_path.exists():
        print(f"[!] Error: Model file not found at {model_path}")
        sys.exit(1)

    print(f"[*] Loading Scikit-Learn pipeline from: {model_path}")
    import joblib
    try:
        pipeline = joblib.load(str(model_path))
        print(f"[+] Successfully loaded pipeline: {type(pipeline).__name__}")
    except Exception as e:
        print(f"[!] Error unpickling model: {e}")
        sys.exit(1)

    try:
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import StringTensorType, FloatTensorType
        import onnx
    except ImportError:
        print("\n[!] Missing ONNX export packages.")
        print("    Please run: pip install skl2onnx onnx onnxruntime")
        sys.exit(1)

    print("[*] Specifying input tensor schemas for ColumnTransformer...")
    initial_types = [
        ('text', StringTensorType([None, 1])),
        ('port', FloatTensorType([None, 1])),
        ('protocol', StringTensorType([None, 1]))
    ]

    print("[*] Converting pipeline to ONNX representation...")
    try:
        onnx_model = convert_sklearn(
            pipeline,
            'NexShieldThreatSeverityClassifier',
            initial_types=initial_types,
            target_opset=17
        )
        
        output_path = Path(args.output)
        with open(output_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        
        out_size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"\n[✓] ONNX Model Exported Successfully!")
        print(f"    - Output: {output_path} ({out_size_mb:.2f} MB)")
        print(f"    - Target Opset: 17")
        print(f"    - Input Signatures: text(string), port(float), protocol(string)")
        print(f"    - Output Signatures: output_label(string), output_probability(map)")
    except Exception as e:
        print(f"[!] ONNX conversion failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
