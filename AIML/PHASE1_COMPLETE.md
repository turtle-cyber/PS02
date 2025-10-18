# Phase 1 Complete: Feature Extraction & Model Training

## Summary

Successfully completed Phase 1 of the phishing detection model rebuild using the new dataset from `dump_all.jsonl`. All features have been extracted, training data prepared, and initial anomaly detection model trained.

---

## Data Pipeline

### Input Data
- **Source**: `/home/turtleneck/Desktop/PS02/dump_all.jsonl`
- **Domains**: 128 benign CSE (Critical Sector Entity) domains
- **HTML files**: 56 available in `Pipeline/out/html/`
- **Screenshots**: 83 available in `Pipeline/out/screenshots/`

### Feature Extraction Scripts Created

#### 1. Text Feature Extractor
- **File**: [AIML/data_prep/extract_text_features.py](AIML/data_prep/extract_text_features.py)
- **Function**: Extracts features from HTML content
- **Features Added**:
  - `document_text` - Cleaned HTML text
  - `doc_length` - Text length
  - `doc_form_count` - Number of forms
  - `doc_has_login_keywords`, `doc_has_verify_keywords`, `doc_has_password_keywords`, `doc_has_credential_keywords`
  - `doc_risk_score`, `doc_verdict`, `doc_has_verdict`
  - `doc_submit_buttons` - Submit button text
- **Coverage**: 56/128 domains (43.75%)

#### 2. Visual Feature Extractor
- **File**: [AIML/data_prep/extract_visual_features.py](AIML/data_prep/extract_visual_features.py)
- **Function**: Extracts perceptual hashes and OCR from screenshots
- **Features Added**:
  - `screenshot_phash` - Perceptual hash for visual similarity
  - `ocr_text`, `ocr_length` - Text extracted from screenshots
  - `ocr_has_login_keywords`, `ocr_has_verify_keywords`
- **Coverage**: 83/128 domains with phash (64.84%)
- **Note**: OCR extraction completed (tesseract now installed)

#### 3. URL Feature Extractor
- **File**: [AIML/data_prep/extract_url_features.py](AIML/data_prep/extract_url_features.py)
- **Function**: Comprehensive URL analysis per Problem Statement Annexure A
- **Features Added** (38 features):
  - URL structure: `url_length`, `domain_length`, `registrable_length`
  - Special chars: `dot_count`, `dash_count`, `underscore_count`, `at_count`, etc.
  - Subdomain: `subdomain_depth`, `has_subdomain`, `subdomain_has_digits`
  - TLD analysis: `tld`, `is_high_risk_tld`, `is_trusted_tld`, `is_numeric_tld`
  - Path/query: `path_length`, `path_depth`, `query_param_count`
  - Security: `url_entropy`, `domain_entropy`, `is_idn`, `has_homograph`
  - Phishing patterns: `has_cse_keyword`, `has_typo_pattern`, `url_has_phishing_keyword`
  - Risk indicators: `is_ip_address`, `has_custom_port`
- **Coverage**: 128/128 domains (100%)

---

## Training Data

### Prepared Dataset
- **Location**: [AIML/data/training/](AIML/data/training/)
- **Total Samples**: 128 (all benign CSE)
- **Total Features**: 99 numeric features
- **Label Distribution**: 128 benign, 0 phishing

### Files Generated
1. **features.csv** - Feature matrix (128 × 99)
2. **labels.csv** - Labels (all benign)
3. **domain_ids.csv** - Domain identifiers
4. **feature_names.txt** - List of all 99 features
5. **feature_stats.csv** - Statistical summary of features
6. **metadata.json** - Dataset metadata
7. **cse_baseline_profile.json** - CSE baseline profile for detection
   - CSE whitelist: 128 domains
   - Visual hashes: 83 unique phashes

---

## Model Training

### Anomaly Detection Model
- **Location**: [AIML/models/anomaly/](AIML/models/anomaly/)
- **Algorithm**: Isolation Forest
- **Purpose**: Detect deviations from CSE baseline as potential phishing
- **Configuration**:
  - Contamination: 5%
  - N estimators: 100
  - Preprocessing: SimpleImputer → StandardScaler → IsolationForest

### Model Performance on CSE Baseline
- **Anomalies detected in training**: 7/128 (5.5%)
- **Score range**: [-0.203, 0.183]
- **Mean score**: 0.114 (higher = more normal)
- **Std score**: 0.064

### Most Anomalous CSE Domains (Outliers)
These domains are still CSE but have unusual feature patterns:
1. pnb.bank.in (score: -0.001)
2. gailonline.com (score: -0.006)
3. www.npci.org.in (score: -0.015)
4. thdc.co.in (score: -0.017)
5. www.idfcfirstbank.com (score: -0.066)

---

## Complete Feature Set (99 Features)

### DNS Features (3)
- ns_count, mx_count, a_count

### Crawl Status (3)
- inactive_status, is_inactive, has_features, redirect_count

### OCR Features (3)
- ocr_length, ocr_has_login_keywords, ocr_has_verify_keywords

### Document Features (7)
- doc_length, doc_form_count
- doc_has_login_keywords, doc_has_verify_keywords, doc_has_password_keywords, doc_has_credential_keywords
- doc_risk_score

### URL Structure (9)
- url_length, domain_length, registrable_length
- dot_count, dash_count, underscore_count, at_count, slash_count, question_count, equal_count, ampersand_count, digit_count

### Subdomain Analysis (5)
- subdomain_depth, has_subdomain, subdomain_length, subdomain_has_digits, subdomain_has_hyphen

### TLD Analysis (4)
- tld_length, is_high_risk_tld, is_trusted_tld, is_numeric_tld

### Path & Query (6)
- path_length, path_depth, has_query, query_length, query_param_count, path_has_phishing_keyword

### Entropy & Security (4)
- url_entropy, domain_entropy, is_idn, has_homograph

### Phishing Patterns (5)
- has_cse_keyword, has_typo_pattern, has_suspicious_hyphen, url_has_phishing_keyword, is_ip_address, has_custom_port

---

## Key Achievements

✅ **Complete Feature Extraction Pipeline**
- Text extraction from HTML (BeautifulSoup)
- Visual extraction from screenshots (imagehash, pytesseract)
- Comprehensive URL analysis (38 custom features)

✅ **Training Data Prepared**
- 128 CSE domains with 99 features each
- CSE baseline profile created
- Feature statistics computed

✅ **Anomaly Detection Model Trained**
- Isolation Forest model ready
- Can detect deviations from CSE baseline
- Handles missing values automatically

✅ **Alignment with Problem Statement**
- URL features per Annexure A
- IDN detection implemented
- Typo-squatting pattern detection
- Visual similarity baseline (phash)
- No third-party APIs used

---

## Next Steps (Phase 2-4)

### Phase 2: Multi-Modal Detection Modules

1. **Visual Similarity Detector**
   - Use screenshot_phash for visual matching
   - Detect CSE impersonation attempts
   - Favicon similarity comparison

2. **Content-Based Phishing Detector**
   - Enhanced keyword detection
   - Form analysis for credential harvesting
   - Urgency/scam language detection

3. **Domain Reputation Analyzer**
   - Typo-squatting detection
   - IDN homograph detection
   - TLD risk scoring

### Phase 3: Unified Detection Engine
- Combine anomaly model + visual + content + domain checks
- Weighted verdict system
- Confidence scoring
- Multi-category classification (CSE phishing, parking, generic phishing, etc.)

### Phase 4: Monitoring & Reporting
- Suspected domain tracker (3+ months)
- Alert generation
- Report formatting per Problem Statement Annexure B

---

## Data Quality Notes

### Coverage Analysis
- **HTML content**: 56/128 (43.75%) - Many government sites block crawlers
- **Screenshots**: 83/128 (64.84%) - Good visual coverage
- **URL features**: 128/128 (100%) - Complete coverage

### Missing Values
- 3,432 missing values filled with 0 (SimpleImputer)
- Primary cause: HTML not available for all domains
- OCR features empty where screenshots missing

### Visual Similarity Findings
- 83 screenshots processed
- 59 unique perceptual hashes
- **24 duplicate/similar screenshots** - Some CSE sites share visual templates (expected for government sites)

---

## Files Created

### Data Preparation Scripts
1. `/home/turtleneck/Desktop/PS02/AIML/data_prep/extract_text_features.py`
2. `/home/turtleneck/Desktop/PS02/AIML/data_prep/extract_visual_features.py`
3. `/home/turtleneck/Desktop/PS02/AIML/data_prep/extract_url_features.py`
4. `/home/turtleneck/Desktop/PS02/AIML/data_prep/prepare_training_dataset.py`

### Model Training
5. `/home/turtleneck/Desktop/PS02/AIML/train_anomaly_detector.py`

### Data Files
6. `/home/turtleneck/Desktop/PS02/AIML/data/visual_features.jsonl`
7. `/home/turtleneck/Desktop/PS02/AIML/data/text_and_visual_features.jsonl`
8. `/home/turtleneck/Desktop/PS02/AIML/data/complete_features.jsonl`
9. `/home/turtleneck/Desktop/PS02/AIML/data/training/*` (7 files)

### Trained Models
10. `/home/turtleneck/Desktop/PS02/AIML/models/anomaly/anomaly_detector.pkl`
11. `/home/turtleneck/Desktop/PS02/AIML/models/anomaly/feature_names.txt`
12. `/home/turtleneck/Desktop/PS02/AIML/models/anomaly/model_metadata.json`

---

## Usage

### Extract Features from New Domains
```bash
# 1. Extract visual features
python AIML/data_prep/extract_visual_features.py \
  --jsonl dump_all.jsonl \
  --screenshots Pipeline/out/screenshots \
  --output AIML/data/visual_features.jsonl

# 2. Extract text features
python AIML/data_prep/extract_text_features.py \
  --jsonl AIML/data/visual_features.jsonl \
  --html-dir Pipeline/out/html \
  --output AIML/data/text_and_visual_features.jsonl

# 3. Extract URL features
python AIML/data_prep/extract_url_features.py \
  --jsonl AIML/data/text_and_visual_features.jsonl \
  --output AIML/data/complete_features.jsonl

# 4. Prepare training data
python AIML/data_prep/prepare_training_dataset.py \
  --input AIML/data/complete_features.jsonl \
  --output AIML/data/training
```

### Train Anomaly Model
```bash
python AIML/train_anomaly_detector.py \
  --data-dir AIML/data/training \
  --output-dir AIML/models/anomaly \
  --contamination 0.05
```

---

**Phase 1 Status**: ✅ **COMPLETE**
**Date**: October 18, 2025
**Total Time**: Feature extraction → Training data preparation → Model training
