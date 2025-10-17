# AIML Phishing Detection - Docker Integration

## Overview

This AIML service integrates with the phishing detection pipeline to provide advanced machine learning-based phishing detection using both **tabular** and **vision** models.

## Architecture

```
Feature Crawler → ChromaDB Ingestor → ChromaDB
                                        ↓
                                  AIML Service
                                        ↓
                              JSON Verdict Files
                                    (/out)
```

## How It Works

1. **Feature Crawler** extracts features from URLs (screenshots, HTML, forms, etc.)
2. **ChromaDB Ingestor** stores enriched data with metadata in ChromaDB vector database
3. **AIML Service** (this service):
   - Queries ChromaDB for domains with features
   - Fetches enriched metadata (domain age, SSL info, forms, etc.)
   - Runs multi-modal phishing detection:
     - **Tabular Model**: Anomaly detection using IsolationForest
     - **Vision Models**: CLIP similarity, favicon matching, phash comparison
   - Generates verdict: `PHISHING`, `SUSPICIOUS`, or `BENIGN`
   - Saves results as JSON files in `/out` directory

## Models Used

### 1. Tabular Anomaly Detection
- **Model**: IsolationForest (scikit-learn)
- **Features**: 52 tabular features (URL structure, domain age, SSL, forms, etc.)
- **Baseline**: Trained on verified CSE (benign) domains
- **Detection**: Flags domains that deviate from benign baseline

### 2. Vision-Based Detection
- **CLIP Similarity**: Detects visual clones of legitimate sites
- **Favicon Matching**: MD5/SHA256 hash comparison with CSE database
- **Phash Matching**: Perceptual hash comparison of screenshots
- **Autoencoder**: Anomaly detection via reconstruction error

### 3. Registrar Validation
- Reduces false positives by checking if registrar matches legitimate sites
- Distinguishes between legitimate subdomains and phishing clones

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CHROMA_HOST` | `chroma` | ChromaDB host |
| `CHROMA_PORT` | `8000` | ChromaDB port |
| `CHROMA_COLLECTION` | `domains` | ChromaDB collection name |
| `OUTPUT_DIR` | `/out` | Directory for JSON verdict files |
| `CHECK_INTERVAL_SECONDS` | `30` | Polling interval for new domains |
| `BATCH_SIZE` | `10` | Number of domains to process per batch |
| `MODEL_DIR` | `/app/models` | Path to trained models |
| `DATA_DIR` | `/app/data` | Path to CSE baseline data |

## File Outputs

### Individual Verdicts
- **File**: `/out/aiml_verdict_{domain}_{timestamp}.json`
- **Format**:
```json
{
  "domain": "suspicious-site.com",
  "verdict": "PHISHING",
  "confidence": 0.95,
  "signals": [
    {
      "signal": "favicon_match",
      "verdict": "PHISHING",
      "confidence": 0.95,
      "reason": "Favicon matches sbi.co.in but domain is different",
      "matched_cse": "sbi.co.in"
    }
  ],
  "signal_count": 1,
  "timestamp": "2025-10-16T17:00:00.000Z",
  "source": "aiml_service",
  "chroma_metadata": {
    "cse_id": "SBI",
    "url": "https://suspicious-site.com",
    "country": "RU",
    "registrar": "Namecheap"
  }
}
```

### Aggregated Log
- **File**: `/out/aiml_verdicts_all.jsonl`
- **Format**: JSONL (one JSON object per line)
- **Usage**: Batch analysis, reporting, statistics

### Service Log
- **File**: `/out/aiml_service.log`
- **Contents**: Service activity, errors, processed domains

## Running the Service

### With Docker Compose

```bash
cd /home/turtleneck/Desktop/PS02/Pipeline/infra
docker-compose up -d aiml-detector
```

### View Logs

```bash
docker logs -f aiml-detector
```

### Check Output

```bash
ls -lh /home/turtleneck/Desktop/PS02/Pipeline/out/aiml_*.json
tail -f /home/turtleneck/Desktop/PS02/Pipeline/out/aiml_verdicts_all.jsonl
```

## Dependencies

The service requires:
- **ChromaDB**: Running and accessible at `chroma:8000`
- **Feature Crawler**: Must have processed domains with screenshots/features
- **ChromaDB Ingestor**: Must have ingested features into ChromaDB
- **Trained Models**: Models in `/app/models/` directory
- **CSE Data**: Baseline data in `/app/data/` directory

## Model Training

Before running the service, ensure models are trained:

1. **Tabular Anomaly Detector**:
   ```bash
   python models/tabular/train_anomaly.py
   ```

2. **CLIP Index**:
   ```bash
   python models/vision/build_cse_index.py
   ```

3. **Favicon/Phash Database**:
   ```bash
   python data_prep/extract_visual_features.py
   ```

## Troubleshooting

### Service not starting
- Check ChromaDB is running: `docker ps | grep chroma`
- Check logs: `docker logs aiml-detector`
- Verify model files exist in `AIML/models/`

### No verdicts generated
- Verify ChromaDB has data: Check ChromaDB collection count
- Check feature-crawler has processed URLs
- Increase `CHECK_INTERVAL_SECONDS` if needed

### Out of memory
- Reduce `BATCH_SIZE`
- Increase Docker memory limit in docker-compose.yml
- Close unused models in detect_phishing.py

## Integration with Pipeline

The AIML service works alongside the rule-based scorer:

1. **Rule Scorer** (rule-scorer service):
   - Fast, heuristic-based
   - Checks 30+ indicators
   - Generates verdicts: phishing/suspicious/parked/benign

2. **AIML Service** (this service):
   - ML-based, similarity detection
   - Visual cloning detection
   - Anomaly detection
   - Higher confidence verdicts

Both services write to `/out` directory and can be used independently or combined for enhanced detection.

## Performance

- **Throughput**: ~10 domains per batch (30s interval) = ~20 domains/minute
- **Latency**: 2-5 seconds per domain (includes ML inference)
- **Memory**: ~1-2GB (depends on model sizes)
- **CPU**: 1-2 cores recommended

## Future Enhancements

- [ ] Kafka integration for real-time detection
- [ ] Verdict publishing back to ChromaDB
- [ ] Model retraining pipeline
- [ ] A/B testing with rule-based scorer
- [ ] Ensemble voting (AIML + rule-based)
