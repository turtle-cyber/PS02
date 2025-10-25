# AIML Model Retraining Guide

## Overview
This guide shows how to retrain all AIML models with the new CSE data from `dump_all.jsonl`.

## Data Sources
- **Features & Metadata**: `/home/turtleneck/Desktop/PS02/dump_all.jsonl` (120 CSE samples)
- **Screenshots**: `/home/turtleneck/Desktop/PS02/Pipeline/out/screenshots/`
- **HTML**: `/home/turtleneck/Desktop/PS02/Pipeline/out/html/`

## Step-by-Step Instructions

### Prerequisites
```bash
cd /home/turtleneck/Desktop/PS02/AIML
pip3 install pandas numpy torch torchvision open-clip-torch scikit-learn joblib Pillow tqdm
```

### Step 1: Prepare Training Data
Convert `dump_all.jsonl` to the format expected by training scripts:

```bash
python3 prepare_cse_training_data.py \
    --input /home/turtleneck/Desktop/PS02/dump_all.jsonl \
    --outdir data/training
```

**Output:**
- `data/training/cse_features.csv` - Tabular features
- `data/training/feature_names.txt` - Feature column names
- `data/training/cse_baseline_profile.json` - CSE baseline statistics
- `data/training/screenshot_metadata.json` - Screenshot paths

### Step 2: Train Anomaly Detector
Train Isolation Forest on CSE baseline features:

```bash
python3 train_anomaly_detector.py \
    --data-dir data/training \
    --output-dir models/anomaly \
    --contamination 0.05
```

**Output:**
- `models/anomaly/anomaly_detector.pkl` - Trained model
- `models/anomaly/feature_names.txt` - Feature names
- `models/anomaly/model_metadata.json` - Training metadata

### Step 3: Build CLIP Visual Index
Generate CLIP embeddings for CSE screenshots:

```bash
python3 models/vision/build_cse_index.py \
    --img_dir /home/turtleneck/Desktop/PS02/Pipeline/out/screenshots \
    --outdir models/vision/cse_index_updated \
    --model ViT-B-32
```

**Output:**
- `models/vision/cse_index_updated/cse_embeddings.npy` - CLIP embeddings
- `models/vision/cse_index_updated/cse_metadata.json` - Domain mappings
- `models/vision/cse_index_updated/index_stats.json` - Statistics

### Step 4: Train Visual Autoencoder
Train autoencoder for visual anomaly detection:

```bash
python3 models/vision/train_cse_autoencoder.py \
    --img_dir /home/turtleneck/Desktop/PS02/Pipeline/out/screenshots \
    --outdir models/vision/autoencoder_new \
    --epochs 50 \
    --batch_size 16 \
    --lr 0.0001
```

**Output:**
- `models/vision/autoencoder_new/autoencoder_best.pth` - Trained autoencoder weights

### Step 5: Train Text Semantic Anomaly Detector (NEW)
Train Sentence-BERT based text anomaly detector:

```bash
python3 models/text/train_text_anomaly.py \
    --input /home/turtleneck/Desktop/PS02/dump_all.jsonl \
    --outdir models/text/semantic_anomaly \
    --model_name all-MiniLM-L6-v2
```

**Dependencies:**
```bash
pip3 install sentence-transformers
```

**Output:**
- `models/text/semantic_anomaly/knn_model.joblib` - KNN model
- `models/text/semantic_anomaly/cse_embeddings.npy` - CSE text embeddings
- `models/text/semantic_anomaly/model_config.json` - Model configuration

**What it does:**
- Embeds CSE text using Sentence-BERT
- Builds K-Nearest Neighbors baseline
- Detects phishing via semantic distance from CSE baseline
- NO phishing labels required (one-class learning)

### Step 6: Train URL Anomaly Detector (NEW)
Train Isolation Forest on URL patterns:

```bash
python3 models/url/train_url_anomaly.py \
    --input /home/turtleneck/Desktop/PS02/dump_all.jsonl \
    --outdir models/url/url_anomaly \
    --contamination 0.05
```

**Output:**
- `models/url/url_anomaly/url_anomaly_detector.joblib` - Trained model
- `models/url/url_anomaly/feature_names.txt` - Feature names
- `models/url/url_anomaly/model_metadata.json` - Model metadata

**What it does:**
- Extracts URL features (n-grams, structure, patterns)
- Trains Isolation Forest on CSE URL baseline
- Detects suspicious URL patterns
- NO phishing labels required

### Step 7: Train JavaScript Behavior Anomaly Detector (NEW)
Train One-Class SVM on JavaScript features:

```bash
python3 models/js/train_js_anomaly.py \
    --input /home/turtleneck/Desktop/PS02/dump_all.jsonl \
    --outdir models/js/js_anomaly \
    --nu 0.05
```

**Output:**
- `models/js/js_anomaly/js_anomaly_detector.joblib` - Trained model
- `models/js/js_anomaly/feature_names.txt` - Feature names
- `models/js/js_anomaly/model_metadata.json` - Model metadata

**What it does:**
- Uses existing JS features (obfuscation, keyloggers, eval usage)
- Trains One-Class SVM on CSE benign JS baseline
- Detects malicious JavaScript patterns
- NO phishing labels required

## Verification

Check that all models were created:

```bash
# Original 4 models
ls -lh models/anomaly/anomaly_detector.pkl
ls -lh models/vision/cse_index_updated/cse_embeddings.npy
ls -lh models/vision/autoencoder_new/autoencoder_best.pth
ls -lh data/training/cse_baseline_profile.json

# NEW: 3 additional anomaly detectors
ls -lh models/text/semantic_anomaly/knn_model.joblib
ls -lh models/url/url_anomaly/url_anomaly_detector.joblib
ls -lh models/js/js_anomaly/js_anomaly_detector.joblib
```

**Total Models**: 8 detection models
- 5 Original: Anomaly, CLIP, Autoencoder, Content, Domain
- 3 NEW: Text Semantic, URL Anomaly, JS Anomaly

## Testing

Test the unified detector:

```bash
python3 unified_detector.py --input test_sample.jsonl --output results.json
```

## Docker Deployment

After training, rebuild and restart the Docker service:

```bash
cd /home/turtleneck/Desktop/PS02/Pipeline/infra
docker-compose build aiml-detector
docker-compose up -d aiml-detector
docker-compose logs -f aiml-detector
```

## Model Paths (in Docker Container)

The docker-compose mounts these directories:
- Host `AIML/models/` → Container `/app/models/` (read-only)
- Host `AIML/data/` → Container `/app/data/` (read-only)

The service expects models at:
- `/app/models/anomaly/anomaly_detector.pkl`
- `/app/models/vision/cse_index_updated/`
- `/app/models/vision/autoencoder_new/autoencoder_best.pth`
- `/app/data/training/cse_baseline_profile.json`

## Troubleshooting

### Issue: Module not found
```bash
pip3 install <missing-module>
```

### Issue: CUDA out of memory (autoencoder training)
Reduce batch size:
```bash
python3 models/vision/train_cse_autoencoder.py --batch_size 8 ...
```

### Issue: No screenshots found
Check the screenshots directory:
```bash
ls -lh /home/turtleneck/Desktop/PS02/Pipeline/out/screenshots/
```

## Summary

**Required scripts** (already exist):
1. ✅ `prepare_cse_training_data.py` - Data preparation
2. ✅ `train_anomaly_detector.py` - Anomaly detector training
3. ✅ `models/vision/build_cse_index.py` - CLIP index building
4. ✅ `models/vision/train_cse_autoencoder.py` - Autoencoder training

**All scripts use your existing code** - no shell scripts needed!
