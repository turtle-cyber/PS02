# ============================================================
# PHASE 6: TEST UNIFIED DETECTION
# ============================================================

# Test on a CSE domain (should be BENIGN)
python detect_phishing.py --domain kotakbank.com --screenshot CSE/out/screenshots/kotakbank.com_cd628abc_full.png --features_csv data/cse_all_features.csv

# Test on suspicious domain (you can add your own)
python detect_phishing.py --domain suspicious-domain.com --screenshot path/to/screenshot.png --favicon_md5 abc123...
Complete Summary of All Commands:
# STEP-BY-STEP COMPLETE PIPELINE

# 1. Install dependencies
pip install torch torchvision open-clip-torch pillow imagehash pytesseract tqdm

# 2. Extract all features
python data_prep/load_cse_data.py
python data_prep/extract_visual_features.py
python data_prep/fix_visual_domains.py
python data_prep/merge_all_features.py

# 3. Train all models
python models/tabular/train_anomaly.py --csv data/cse_all_features.csv --outdir models/tabular/anomaly_all
python models/vision/build_cse_index.py
python models/vision/train_cse_autoencoder.py --epochs 50

# 4. Build databases
python -c "import pandas as pd; df=pd.read_csv('data/cse_all_features.csv'); favicon_db=df[['registrable','favicon_md5','favicon_sha256']].dropna(); favicon_db=favicon_db[favicon_db['favicon_md5']!=''];favicon_db.to_csv('data/cse_favicon_db.csv',index=False)"
python -c "import pandas as pd; df=pd.read_csv('data/cse_visual_features.csv'); phash_db=df[['registrable','screenshot_phash']].dropna(); phash_db.to_csv('data/cse_phash_db.csv',index=False)"

# 5. Test detection
python detect_phishing.py --domain kotakbank.com --screenshot CSE/out/screenshots/kotakbank.com_cd628abc_full.png --features_csv data/cse_all_features.csv

# 6. Text data
python models/tabular/train_xgb_with_text.py --csv data/cse_all_features.csv --outdir models/saved/xgb_text