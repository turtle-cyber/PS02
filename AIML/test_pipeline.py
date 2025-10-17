"""Test complete CSE training pipeline"""
import subprocess
import sys
from pathlib import Path

def run_command(cmd, description):
    """Run command and check result"""
    print(f"\n{'='*70}")
    print(f"Testing: {description}")
    print(f"Command: {cmd}")
    print('='*70)

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"[FAIL] {description}")
        print(f"Error: {result.stderr}")
        return False
    else:
        print(f"[PASS] {description}")
        if result.stdout:
            print(result.stdout[:500])  # First 500 chars
        return True

def check_files(files, description):
    """Check if files exist"""
    print(f"\n{'='*70}")
    print(f"Checking: {description}")
    print('='*70)

    all_exist = True
    for f in files:
        path = Path(f)
        if path.exists():
            size = path.stat().st_size / 1024  # KB
            print(f"[OK] {f} ({size:.1f} KB)")
        else:
            print(f"[MISSING] {f}")
            all_exist = False

    return all_exist

def main():
    print("\n" + "="*70)
    print("CSE TRAINING PIPELINE VALIDATION")
    print("="*70)

    results = []

    # Step 1: Data extraction
    results.append(run_command(
        "python data_prep/load_cse_data.py",
        "Extract CSE features"
    ))

    results.append(check_files([
        "data/cse_benign.csv",
        "data/cse_text.csv"
    ], "Data extraction outputs"))

    # Step 2: Tabular training
    results.append(run_command(
        "python models/tabular/train_anomaly.py --csv data/cse_benign.csv --outdir models/tabular/anomaly",
        "Train tabular anomaly detector"
    ))

    results.append(check_files([
        "models/tabular/anomaly/anomaly_detector.joblib",
        "models/tabular/anomaly/metadata.json"
    ], "Tabular model outputs"))

    # Step 3: Visual index (requires dependencies)
    print(f"\n{'='*70}")
    print("Visual Index (CLIP) - Skipping (requires open_clip_torch)")
    print("To run: pip install open_clip_torch torch")
    print("Then: python models/vision/build_cse_index.py")
    print('='*70)

    # Step 4: Visual features (optional)
    print(f"\n{'='*70}")
    print("Visual Features (OCR + phash) - Skipping (requires pytesseract, imagehash)")
    print("To run: pip install pytesseract pillow imagehash")
    print("Then: python data_prep/extract_visual_features.py")
    print('='*70)

    # Summary
    print(f"\n{'='*70}")
    print("VALIDATION SUMMARY")
    print('='*70)
    passed = sum(results)
    total = len(results)
    print(f"Tests passed: {passed}/{total}")

    if passed == total:
        print("\n[SUCCESS] ALL CORE PIPELINE TESTS PASSED")
        print("\nYour CSE training pipeline is working correctly!")
        print("\nNext steps:")
        print("  1. Install visual dependencies:")
        print("     pip install open_clip_torch torch pillow imagehash pytesseract")
        print("  2. Run visual training:")
        print("     python models/vision/build_cse_index.py")
        print("     python data_prep/extract_visual_features.py")
        print("  3. Test detection:")
        print("     python integration/chromadb_similarity_detection.py")
    else:
        print(f"\n⚠️  {total - passed} TESTS FAILED")
        print("Check the errors above and fix issues")

    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
