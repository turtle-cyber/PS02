# AIML Phishing Detection - Data Statistics & Training Methodology

## Executive Summary

Your phishing detection system uses **anomaly-based machine learning** trained exclusively on **128 benign CSE (Critical Sector Entities) samples** from **116 unique domains**. The system employs **unsupervised learning** (no phishing samples needed for training) across multiple modalities: tabular features, visual (CLIP + autoencoder), text, and domain metadata.

---

## 1. Overall Data Statistics

### 1.1 Total Dataset

| Metric | Value | Source |
|--------|-------|--------|
| **Total Training Samples** | 128 | `AIML/data/training/metadata.json` |
| **Unique Domains** | 116 | `AIML/data/training/cse_baseline_profile.json` |
| **Label Distribution** | 100% BENIGN (0% phishing) | Anomaly detection approach |
| **Data Source** | `dump_all.jsonl` | CSE domain crawl output |
| **Screenshots Available** | ~100-116 | `AIML/data/training/screenshot_metadata.json` |

### 1.2 Why No Phishing Data?

**Training Approach**: **One-Class Anomaly Detection**
- ✅ Train **only on benign CSE examples**
- ✅ Learn what "normal" looks like
- ✅ Flag deviations as **anomalies (phishing)**
- ✅ **No phishing samples needed** for training
- ✅ Detects **novel/zero-day phishing** attacks

**Rationale**:
1. Hard to get labeled phishing data for Indian CSE domains
2. Phishing evolves rapidly - supervised models get stale
3. Anomaly detection generalizes better to new attacks
4. CSE baseline is stable and well-defined

---

## 2. Tabular Anomaly Detection Model

### 2.1 Training Data

```
Source: AIML/data/training/features.csv
Total Samples: 128
Total Features: 99
Missing Values: 0 (imputed with 0)
Label: All BENIGN
```

### 2.2 Feature Categories (99 Total)

| Category | Features | Examples |
|----------|----------|----------|
| **URL Features** | 20 | `url_length`, `url_entropy`, `num_subdomains`, `has_repeated_digits` |
| **Domain/WHOIS** | 10 | `domain_age_days`, `is_newly_registered`, `is_very_new`, `days_until_expiry` |
| **DNS** | 3 | `a_count`, `mx_count`, `ns_count` |
| **HTML** | 5 | `html_size`, `external_links`, `iframe_count`, `external_scripts` |
| **Forms** | 8 | `form_count`, `password_fields`, `email_fields`, `has_credential_form` |
| **JavaScript** | 11 | `js_obfuscated`, `js_keylogger`, `js_eval_usage`, `js_risk_score` |
| **Certificate** | 3 | `is_self_signed`, `cert_age_days`, `trusted_issuer` |
| **Document/OCR** | 12 | `doc_length`, `ocr_length`, `doc_has_login_keywords`, `ocr_has_verify_keywords` |
| **Redirect** | 2 | `redirect_count`, `had_redirects` |
| **Other** | 25 | `is_idn`, `mixed_script`, `inactive_status`, `favicon_size` |

**Full Feature List**: See `AIML/data/training/feature_names.txt`

### 2.3 Model Architecture

```python
Model: sklearn.ensemble.IsolationForest
Algorithm: Unsupervised anomaly detection
n_estimators: 100  # Number of trees
contamination: 0.05  # Expected 5% anomalies
max_samples: 'auto'  # 256 or n_samples
bootstrap: False
random_state: 42  # Reproducibility
```

**How It Works**:
1. Build 100 isolation trees on benign CSE data
2. Each tree randomly partitions feature space
3. Anomalies are easier to isolate (shorter path length)
4. Assign anomaly score: lower score = more anomalous
5. Threshold at 5th percentile to flag phishing

### 2.4 Training Process

```bash
# Data preparation
python AIML/prepare_cse_training_data.py \
  --input dump_all.jsonl \
  --output AIML/data/training/

# Model training
python AIML/train_anomaly_detector.py \
  --data-dir AIML/data/training \
  --output-dir AIML/models/anomaly \
  --contamination 0.05
```

**No Train/Val/Test Split**:
- Anomaly detection trains on **all 128 benign samples**
- Evaluated on **real-world phishing domains** during inference
- Performance measured via precision/recall on production data

### 2.5 Training Output

```
Input: 128 CSE samples × 99 features
Output:
  - models/anomaly/anomaly_detector.pkl (trained model)
  - models/anomaly/feature_names.txt (feature order)
  - models/anomaly/model_metadata.json (config)

Training Stats:
  - Detected 6-7 anomalies in training set (5%)
  - Score range: [-0.15, 0.25]
  - Mean score: 0.10
```

---

## 3. Visual Detection Models

### 3.1 CLIP-Based Visual Similarity Detector

#### 3.1.1 Training Data

```
Source: CSE screenshot directory
Total Screenshots: ~100-116 screenshots
Format: PNG full-page screenshots (1920×1080 or similar)
Label: All BENIGN CSE domains
```

**Example Domains**:
- `airtel.in` (telecom)
- `sbi.co.in`, `icicibank.com`, `hdfcbank.com` (banks)
- `pnbindia.in`, `axisbank.com`, `kotak.com` (banks)
- `uidai.gov.in`, `incometaxindia.gov.in` (government)

#### 3.1.2 Model Architecture

```
Model: CLIP ViT-B-32
Pretrained: OpenAI CLIP (laion2b_s34b_b79k)
Embedding Dimension: 512
Training: Zero-shot (no fine-tuning)
Purpose: Semantic visual similarity matching
```

**How It Works**:
1. Load pre-trained CLIP model (trained on 2B image-text pairs)
2. Encode all CSE screenshots into 512-dim embeddings
3. Store embeddings in index (`cse_embeddings.npy`)
4. During inference:
   - Encode new screenshot with same CLIP model
   - Compute cosine similarity to all CSE embeddings
   - If similarity > 0.85 to CSE but domain mismatch → PHISHING

**No Retraining Required**: Uses pre-trained CLIP out-of-the-box

#### 3.1.3 Index Building

```bash
# Build CLIP embedding index
python AIML/models/vision/build_cse_index.py \
  --img_dir CSE/out/screenshots \
  --outdir models/vision/cse_index_updated \
  --model ViT-B-32
```

**Output**:
```
models/vision/cse_index_updated/
  ├── cse_embeddings.npy      # Shape: [N, 512]
  ├── cse_metadata.json       # Domain names, filenames
  └── index_stats.json        # Statistics
```

**Index Statistics** (example):
```json
{
  "n_screenshots": 116,
  "embedding_dim": 512,
  "model_name": "ViT-B-32",
  "avg_pairwise_similarity": 0.65,
  "similarity_min": 0.12,
  "similarity_max": 0.98
}
```

#### 3.1.4 No Train/Val/Test Split

- **No training**: Uses frozen pre-trained CLIP model
- **Validation**: Pairwise similarity among CSE screenshots (should be distinct)
- **Testing**: Real-world phishing attempts during inference

### 3.2 Autoencoder-Based Anomaly Detection

#### 3.2.1 Training Data

```
Source: CSE screenshot directory
Total Screenshots: ~100-116 PNG screenshots
Image Size: Resized to 224×224
Normalization: ImageNet mean/std
Label: All BENIGN
```

#### 3.2.2 Model Architecture

```python
Encoder: ResNet18 (pretrained on ImageNet)
  - Input: [B, 3, 224, 224]
  - Output: [B, 512, 7, 7] feature maps

Decoder: Transposed Convolutions
  - 7×7 → 14×14 → 28×28 → 56×56 → 112×112 → 224×224
  - Channels: 512 → 256 → 128 → 64 → 32 → 3
  - Activation: ReLU (Tanh at output)

Loss: MSE (Mean Squared Error)
Optimizer: Adam (lr=1e-4)
```

**How It Works**:
1. Train autoencoder to **reconstruct CSE screenshots**
2. Learn compressed representation of "normal" CSE appearance
3. During inference:
   - Pass phishing screenshot through autoencoder
   - Measure reconstruction error (MSE)
   - High error → doesn't look like CSE → ANOMALY/PHISHING

#### 3.2.3 Training Process

```bash
python AIML/models/vision/train_cse_autoencoder.py \
  --img_dir CSE/out/screenshots \
  --outdir models/vision/autoencoder_new \
  --epochs 50 \
  --batch_size 16 \
  --lr 1e-4
```

**Training Configuration**:
```
Total Data: ~100-116 screenshots
Train/Val Split: None (trains on all data)
Epochs: 50
Batch Size: 16
Learning Rate: 1e-4
Early Stopping: Save best model (lowest reconstruction loss)
```

**Training Output**:
```
Best Reconstruction Loss: ~0.015-0.025
Saved: models/vision/autoencoder_new/autoencoder_best.pth

Usage Threshold: 3.5
  - Reconstruction error < 3.5 → BENIGN/NORMAL
  - Reconstruction error >= 3.5 → ANOMALY/PHISHING
```

#### 3.2.4 No Val/Test Split

- **Training**: All CSE screenshots
- **Validation**: Monitor reconstruction loss convergence
- **Testing**: Real phishing screenshots during inference

---

## 4. Data Preparation Pipeline

### 4.1 Source Data: `dump_all.jsonl`

```json
{
  "domain": "airtel.in",
  "metadata": {
    "registrable": "airtel.in",
    "url": "https://www.airtel.in/",
    "cse_id": "BULK_IMPORT",
    "screenshot_path": "/workspace/out/screenshots/www.airtel.in_xyz.png",
    "html_size": 52341,
    "a_count": 4,
    "mx_count": 10,
    "domain_age_days": 7300,
    "form_count": 2,
    "js_risk_score": 0.1,
    ... (99 total features)
  }
}
```

### 4.2 Feature Extraction

**Script**: `AIML/prepare_cse_training_data.py`

```python
# Extract tabular features
df = extract_tabular_features(data)
# 128 samples × 99 features → features.csv

# Generate baseline profile
profile = generate_baseline_profile(df, data)
# Statistics, domain whitelist → cse_baseline_profile.json

# Extract screenshot paths
screenshots = extract_screenshot_paths(data)
# Screenshot metadata → screenshot_metadata.json
```

**Feature Preprocessing**:
1. **Boolean → Int**: `True/False → 1/0`
2. **Missing → 0**: `None → 0`
3. **NaN/Inf → 0**: Invalid values replaced
4. **All Numeric**: Ensure float/int types

**Output Files**:
```
AIML/data/training/
  ├── features.csv                   # 128×99 tabular features
  ├── feature_names.txt              # Feature order
  ├── domain_ids.csv                 # Domain names
  ├── cse_baseline_profile.json      # Whitelist + statistics
  ├── screenshot_metadata.json       # Screenshot paths
  └── metadata.json                  # Dataset summary
```

### 4.3 CSE Baseline Profile Structure

```json
{
  "version": "2.0",
  "source": "dump_all.jsonl",
  "n_domains": 116,
  "domains": [
    "airtel.in",
    "sbi.co.in",
    "icicibank.com",
    ...116 total CSE domains
  ],
  "feature_statistics": {
    "html_size": {
      "mean": 45123.5,
      "std": 12345.6,
      "min": 1024,
      "max": 250000,
      "median": 42000,
      "q25": 30000,
      "q75": 60000
    },
    ... (statistics for all 99 features)
  },
  "screenshots": {
    "airtel.in": {
      "path": "/workspace/out/screenshots/www.airtel.in_xyz.png",
      "phash": "abc123..."
    },
    ...
  },
  "metadata": {
    "total_samples": 128,
    "label": "benign"
  }
}
```

---

## 5. Data Flow: Training → Inference

### 5.1 Training Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                     TRAINING PIPELINE                        │
└─────────────────────────────────────────────────────────────┘

1. DATA COLLECTION
   dump_all.jsonl (128 CSE samples)
         ↓
2. FEATURE EXTRACTION (prepare_cse_training_data.py)
   ├─→ Tabular features (99 features) → features.csv
   ├─→ Screenshot paths → screenshot_metadata.json
   └─→ Baseline profile → cse_baseline_profile.json
         ↓
3. MODEL TRAINING
   ├─→ Tabular: train_anomaly_detector.py
   │      └─→ Isolation Forest on 128×99 features
   │          └─→ Output: anomaly_detector.pkl
   │
   ├─→ Visual CLIP: build_cse_index.py
   │      └─→ Encode 116 screenshots with CLIP ViT-B-32
   │          └─→ Output: cse_embeddings.npy (116×512)
   │
   └─→ Visual Autoencoder: train_cse_autoencoder.py
          └─→ Train ResNet18 autoencoder on 116 screenshots
              └─→ Output: autoencoder_best.pth

4. MODEL ARTIFACTS SAVED
   ├─→ models/anomaly/anomaly_detector.pkl
   ├─→ models/vision/cse_index_updated/cse_embeddings.npy
   └─→ models/vision/autoencoder_new/autoencoder_best.pth
```

### 5.2 Inference Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                     INFERENCE PIPELINE                       │
└─────────────────────────────────────────────────────────────┘

1. NEW DOMAIN (e.g., suspicious-airtel.in)
         ↓
2. FEATURE EXTRACTION (ChromaDB metadata)
   ├─→ Extract 99 tabular features
   ├─→ Load screenshot (if available)
   └─→ Extract OCR text, HTML content
         ↓
3. MULTI-DETECTOR ENSEMBLE
   ├─→ Anomaly Detector (Isolation Forest)
   │      └─→ Score: -0.15 (anomaly) → PHISHING: 0.75
   │
   ├─→ Visual CLIP Detector
   │      └─→ Similarity to airtel.in screenshot: 0.92
   │          └─→ Domain mismatch → PHISHING: 0.95
   │
   ├─→ Visual Autoencoder
   │      └─→ Reconstruction error: 4.2 (> threshold 3.5)
   │          └─→ ANOMALY: 0.70
   │
   ├─→ Content Detector (text analysis)
   │      └─→ Phishing keywords detected → PHISHING: 0.80
   │
   └─→ Domain Analyzer (metadata)
          └─→ New domain, no MX records → SUSPICIOUS: 0.60
         ↓
4. WEIGHTED AGGREGATION (unified_detector.py)
   Weights: {anomaly: 0.25, visual: 0.20, content: 0.20,
             domain: 0.15, autoencoder: 0.20}

   Risk Score = Σ(detector_score × weight × confidence) / Σ(weight × confidence)
              = 0.82 (high risk)
         ↓
5. VERDICT CLASSIFICATION
   Risk >= 0.70 → PHISHING (confidence: 0.88)
         ↓
6. POST-VALIDATION (aiml_service.py)
   ├─→ Check visual impersonation (similarity >= 0.85)
   │      └─→ OVERRIDE to PHISHING (priority 0)
   │
   ├─→ Check typosquatting (string similarity to CSE)
   │      └─→ Add +20-30 risk points
   │
   └─→ Check metadata risk (fallback_detector)
          └─→ If risk >= 40, override BENIGN → SUSPICIOUS
         ↓
7. FINAL VERDICT: PHISHING (confidence: 0.95)
```

---

## 6. Model Deployment & Loading

### 6.1 Models Loaded in `aiml_service.py`

```python
# Initialize UnifiedPhishingDetector
detector_config = {
    'anomaly_model_path': 'models/anomaly/anomaly_detector.pkl',
    'feature_names_path': 'models/anomaly/feature_names.txt',
    'cse_baseline_path': 'data/training/cse_baseline_profile.json',
    'clip_index_path': 'models/vision/cse_index_updated',
    'autoencoder_path': 'models/vision/autoencoder_new/autoencoder_best.pth',
    'use_clip': True,
    'use_autoencoder': True,
    'autoencoder_threshold': 3.5
}

detector = UnifiedPhishingDetector(config=detector_config)
detector.load_models()  # Loads all models into memory
```

### 6.2 Ensemble Weights

```python
weights = {
    'anomaly': 0.25,       # Isolation Forest (tabular features)
    'visual': 0.20,        # CLIP similarity
    'content': 0.20,       # Text/HTML analysis
    'domain': 0.15,        # Domain reputation
    'autoencoder': 0.20    # Visual reconstruction
}
```

**Weight Adjustment**:
- Trusted TLDs (.gov, .edu): domain weight ×2, visual weight ×0.5
- High-risk TLDs: domain weight ×1.5

---

## 7. Summary Statistics Table

| Component | Training Data | Model Type | Train/Val/Test | Output |
|-----------|--------------|------------|----------------|--------|
| **Tabular Anomaly** | 128 samples, 99 features | Isolation Forest | All train (no split) | Anomaly score |
| **CLIP Visual** | 116 screenshots | Pre-trained ViT-B-32 | Zero-shot (no train) | 512-dim embeddings |
| **Autoencoder** | 116 screenshots | ResNet18 encoder/decoder | All train (no split) | Reconstruction error |
| **Fallback Detector** | Metadata rules | Heuristic scoring | N/A (rule-based) | Risk score 0-100 |
| **CSE Baseline** | 116 domains | Whitelist | N/A (lookup) | BENIGN if exact match |

---

## 8. Why No Traditional Train/Val/Test Split?

### 8.1 Anomaly Detection Paradigm

**Traditional Supervised Learning**:
```
Data: 70% train (BENIGN + PHISHING)
      15% validation (BENIGN + PHISHING)
      15% test (BENIGN + PHISHING)

Problem: Need labeled phishing examples
         → Hard to collect for Indian CSE domains
         → Phishing evolves → training data gets stale
```

**Anomaly Detection (Your Approach)**:
```
Data: 100% train (BENIGN only)
      0% labeled phishing needed

Validation: Monitor reconstruction loss, pairwise similarities
Test: Real-world production performance (precision/recall)

Benefits:
  ✅ No phishing samples needed
  ✅ Detects novel/zero-day attacks
  ✅ Generalizes to unseen phishing techniques
  ✅ Stable baseline (CSE domains don't change much)
```

### 8.2 Evaluation Strategy

**Training Phase**:
- Ensure anomaly detector captures CSE distribution
- Validate CLIP embeddings are distinct
- Monitor autoencoder reconstruction quality

**Production Phase**:
- Measure precision/recall on real phishing detections
- Collect false positives/negatives for analysis
- Periodically retrain with updated CSE baseline

---

## 9. Data Limitations & Mitigations

### 9.1 Limitations

| Limitation | Impact | Mitigation |
|-----------|--------|------------|
| **Small dataset** (128 samples) | Limited feature diversity | Use pre-trained models (CLIP, ResNet18) |
| **No phishing examples** | Can't learn phishing patterns directly | Anomaly detection + heuristic rules |
| **Imbalanced domains** | Some CSE sectors underrepresented | Metadata-based fallback detector |
| **Screenshot quality** | Some screenshots may be incomplete | Combine visual + tabular features |
| **Domain age missing** | Many domains lack WHOIS data | Treat missing age as suspicious (+20 risk) |

### 9.2 Mitigation Strategies

1. **Multi-modal ensemble**: Combine 5+ detectors to compensate for weaknesses
2. **Pre-trained models**: Leverage CLIP (trained on 2B images) for visual understanding
3. **Rule-based fallbacks**: Heuristic scoring when ML models have insufficient data
4. **Post-validation**: Override ML verdicts with high-confidence metadata signals
5. **Continuous learning**: Update CSE baseline as new legitimate domains emerge

---

## 10. Future Improvements

### 10.1 Data Collection

- [ ] Expand CSE baseline to 200-300 domains
- [ ] Collect phishing examples for semi-supervised training
- [ ] Add temporal data (track domain changes over time)
- [ ] Improve WHOIS data coverage

### 10.2 Model Enhancements

- [ ] Fine-tune CLIP on phishing vs. legitimate screenshots
- [ ] Add BERT-based text classification for HTML content
- [ ] Incorporate graph-based analysis (link structure)
- [ ] Ensemble with external threat intelligence feeds

### 10.3 Evaluation

- [ ] Implement continuous evaluation pipeline
- [ ] Track false positive/negative rates
- [ ] A/B test different detector configurations
- [ ] Benchmark against commercial phishing detectors

---

## Appendix A: Key File Locations

```
AIML/
├── data/training/
│   ├── features.csv                        # 128×99 tabular features
│   ├── feature_names.txt                   # 99 feature names
│   ├── domain_ids.csv                      # 128 domain IDs
│   ├── cse_baseline_profile.json           # 116 CSE domains + statistics
│   ├── screenshot_metadata.json            # Screenshot paths
│   └── metadata.json                       # Dataset summary
│
├── models/
│   ├── anomaly/
│   │   ├── anomaly_detector.pkl            # Isolation Forest model
│   │   ├── feature_names.txt               # Feature order
│   │   └── model_metadata.json             # Model config
│   │
│   └── vision/
│       ├── cse_index_updated/
│       │   ├── cse_embeddings.npy          # 116×512 CLIP embeddings
│       │   ├── cse_metadata.json           # Domain names
│       │   └── index_stats.json            # Statistics
│       │
│       └── autoencoder_new/
│           └── autoencoder_best.pth        # Trained autoencoder weights
│
├── prepare_cse_training_data.py            # Feature extraction script
├── train_anomaly_detector.py               # Anomaly model training
├── models/vision/build_cse_index.py        # CLIP index builder
└── models/vision/train_cse_autoencoder.py  # Autoencoder training
```

---

## Appendix B: Training Commands

```bash
# 1. Prepare training data from dump_all.jsonl
cd /home/turtleneck/Desktop/PS02
python AIML/prepare_cse_training_data.py \
  --input dump_all.jsonl \
  --output AIML/data/training/

# 2. Train anomaly detection model
python AIML/train_anomaly_detector.py \
  --data-dir AIML/data/training \
  --output-dir AIML/models/anomaly \
  --contamination 0.05

# 3. Build CLIP visual index
python AIML/models/vision/build_cse_index.py \
  --img_dir CSE/out/screenshots \
  --outdir AIML/models/vision/cse_index_updated \
  --model ViT-B-32

# 4. Train autoencoder (optional)
python AIML/models/vision/train_cse_autoencoder.py \
  --img_dir CSE/out/screenshots \
  --outdir AIML/models/vision/autoencoder_new \
  --epochs 50 \
  --batch_size 16
```

---

**Document Version**: 1.0
**Last Updated**: 2025-10-27
**Author**: Claude AI
**Contact**: For questions about data or models, consult the training scripts
