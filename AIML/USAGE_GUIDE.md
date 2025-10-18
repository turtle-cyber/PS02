# AIML Enhanced Detection System - Usage Guide

## Quick Start

### 1. Retrain the Model (Required for NaN Fix)

The model needs to be retrained with the new SimpleImputer pipeline:

```bash
cd AIML

# Retrain tabular anomaly detector with imputation
python models/tabular/train_anomaly.py \
    --csv data/cse_benign.csv \
    --outdir models/tabular/anomaly_all \
    --contamination 0.05
```

This will create a new model with:
- SimpleImputer (handles NaN values)
- StandardScaler
- IsolationForest

### 2. Test the Improvements

```bash
# Run test suite
python test_improvements.py
```

Expected output:
```
TEST RESULTS: 5 passed, 0 failed
```

### 3. Use in Production

The enhanced detector works exactly like before:

```python
from detect_phishing import UnifiedPhishingDetector

# Initialize detector
detector = UnifiedPhishingDetector(
    model_dir="models",
    data_dir="data"
)

# Detect threats
result = detector.detect(
    domain="suspicious-domain.com",
    features=features_dict,
    screenshot_path="/path/to/screenshot.png",
    favicon_md5="abc123...",
    registrar="NameCheap, Inc."
)

# Check result
print(f"Verdict: {result['verdict']}")
print(f"Confidence: {result['confidence']:.2f}")
print(f"Signals: {result['signals']}")
```

---

## New Verdict Categories

The system now returns expanded verdict categories:

### CSE-Related
- **PHISHING** - CSE brand impersonation (favicon/visual match)
- **BENIGN** - Legitimate site (whitelisted or no threats)
- **PARKED** - Domain parking page
- **INACTIVE** - Unregistered or inactive domain
- **UNREGISTERED** - Domain not registered in DNS

### Non-CSE Threats (NEW)
- **PHISHING_FINANCIAL** - Financial phishing (bank, payment, wallet)
- **PHISHING_CRYPTO** - Cryptocurrency scam
- **PHISHING_GENERIC** - Generic credential harvesting
- **GAMBLING** - Online casino/betting site
- **ADULT_CONTENT** - Adult/inappropriate content
- **MALWARE** - Malware distribution indicators
- **SUSPICIOUS** - Multiple weak indicators

### Error States
- **ERROR** - Detection failed (should be rare now)
- **INSUFFICIENT_DATA** - Not enough features for analysis

---

## Verdict Priority

When multiple signals are detected, the system uses this priority order:

```
1. GAMBLING
2. ADULT_CONTENT
3. MALWARE
4. PHISHING_FINANCIAL
5. PHISHING_CRYPTO
6. PHISHING_GENERIC
7. PHISHING (CSE)
8. PARKED
9. SUSPICIOUS
10. BENIGN
```

Example: If a domain triggers both GAMBLING and SUSPICIOUS signals, the verdict will be GAMBLING.

---

## Understanding Signals

Each detection result includes a list of signals that contributed to the verdict:

```python
{
    'domain': 'example.com',
    'verdict': 'PHISHING_GENERIC',
    'confidence': 0.82,
    'signals': [
        {
            'signal': 'content_risk_phishing',
            'verdict': 'PHISHING_GENERIC',
            'confidence': 0.82,
            'reason': 'Credential form + urgency keywords ([urgent, verify])',
            'risk_score': 6,
            'category': 'PHISHING_GENERIC'
        },
        {
            'signal': 'high_risk_tld',
            'verdict': 'SUSPICIOUS',
            'confidence': 0.70,
            'reason': 'Domain uses high-risk TLD: .tk',
            'tld': '.tk'
        },
        {
            'signal': 'new_domain_credential_form',
            'verdict': 'SUSPICIOUS',
            'confidence': 0.68,
            'reason': 'Newly registered domain (5 days) with credential form',
            'domain_age_days': 5
        }
    ],
    'signal_count': 3
}
```

---

## Detection Examples

### Example 1: Parking Domain (No NaN Error)

```python
features = {
    'html_size': 5000,
    'mx_count': 0,
    'form_count': 0,
    'document_text': 'parked domain for sale',
    'ocr_text': 'premium domain available at sedo',
    # Many features missing (previously caused NaN error)
}

result = detector.detect('fitnessforshapes.com', features=features)
# Result: PARKED (no error!)
```

**What happens**:
1. Feature completeness check: <50% complete
2. Parking detection: OCR keywords detected
3. Return PARKED before reaching tabular model
4. No NaN error!

### Example 2: Generic Phishing (Non-CSE)

```python
features = {
    'domain_age_days': 3,
    'is_very_new': True,
    'has_credential_form': True,
    'password_fields': 1,
    'document_text': 'urgent: verify your paypal account',
    'js_risk_score': 0.7
}

result = detector.detect('paypal-secure.tk', features=features)
# Result: PHISHING_FINANCIAL
```

**What happens**:
1. Content classifier: Financial keywords + credential form + urgency
2. Domain reputation: High-risk TLD (.tk) + very new domain
3. Combined signals → PHISHING_FINANCIAL

### Example 3: Gambling Site

```python
features = {
    'html_size': 50000,
    'document_text': 'casino betting poker slots jackpot roulette',
    'ocr_text': 'online gambling'
}

result = detector.detect('online-casino.bet', features=features)
# Result: GAMBLING
```

**What happens**:
1. Content classifier: 6 gambling keywords detected
2. Domain reputation: Medium-risk TLD (.bet)
3. Combined signals → GAMBLING

### Example 4: CSE Phishing (Visual Clone)

```python
features = {
    'favicon_md5': 'abc123...',  # Matches SBI favicon
    'registrar': 'Different Corp'
}

result = detector.detect('sbi-login.com', features=features, favicon_md5='abc123...')
# Result: PHISHING
```

**What happens**:
1. CSE whitelist: Not in whitelist
2. Favicon match: Matches sbi.co.in
3. Registrar check: Different registrar
4. Combined signals → PHISHING (CSE impersonation)

---

## Feature Requirements

### Minimum Features for Detection

The system gracefully handles incomplete data:

| Detection Type | Required Features |
|----------------|-------------------|
| **Parking** | `mx_count`, `form_count`, `document_text` OR `ocr_text` |
| **Content Risk** | `document_text` OR `ocr_text`, form features |
| **Domain Reputation** | Domain name only (basic checks), `domain_age_days` (advanced) |
| **CSE Similarity** | `favicon_md5` OR `screenshot_path` |
| **Tabular Anomaly** | At least 50% of 52 features (26+ features) |

### Recommended Feature Set

For best results, provide:
- All URL features (length, entropy, subdomains)
- Domain/WHOIS features (age, registrar, country)
- HTML features (size, forms, links)
- JavaScript features (risk score, obfuscation flags)
- Visual features (screenshot, favicon)
- Text features (document_text, ocr_text)

---

## Error Handling

### Graceful Degradation

The system handles errors gracefully:

1. **Missing content modules**: Falls back to CSE-only detection
2. **Missing CLIP model**: Visual similarity disabled
3. **Missing autoencoder**: Anomaly detection disabled
4. **Incomplete features**: Skips tabular model, uses other signals
5. **NaN values**: Automatically imputed to 0

### Error Logs

Watch for these warnings:

```
⚠ Warning: Feature completeness too low (25%), skipping tabular anomaly detection
⚠ Warning: Content/reputation modules not available
⚠ CLIP model not available
```

These are informational - detection will continue with available modules.

---

## Performance Tips

### 1. Batch Processing

For bulk detection, reuse the detector instance:

```python
detector = UnifiedPhishingDetector()

for domain, features in domains_to_check:
    result = detector.detect(domain, features)
    # Process result
```

### 2. Feature Caching

Cache expensive feature extraction:

```python
# Extract features once
features = extract_all_features(domain)

# Use multiple times
result1 = detector.detect(domain, features, screenshot_path=path1)
result2 = detector.detect(domain, features, favicon_md5=hash1)
```

### 3. GPU Acceleration

If CUDA is available, CLIP model will use GPU automatically:

```
✓ CLIP model loaded on GPU
```

---

## Troubleshooting

### Issue: Still getting NaN errors

**Solution**: Retrain the model with SimpleImputer:
```bash
python models/tabular/train_anomaly.py --outdir models/tabular/anomaly_all
```

### Issue: Content modules not loading

**Check**:
```bash
ls AIML/models/content/risk_classifier.py
ls AIML/models/domain/reputation_checker.py
```

**Solution**: Ensure files exist and Python path is correct

### Issue: Low detection accuracy for non-CSE threats

**Check**: Feature completeness
```python
completeness, missing = detector.check_feature_completeness(features)
print(f"Feature completeness: {completeness:.1%}")
```

**Solution**: Provide more features, especially `document_text` and form features

---

## Integration with AIML Service

The `aiml_service.py` automatically uses the enhanced detector. No changes needed!

Just ensure the new model is trained:
```bash
cd AIML
python models/tabular/train_anomaly.py \
    --csv data/cse_benign.csv \
    --outdir models/tabular/anomaly_all
```

Then restart the service:
```bash
docker-compose restart aiml
# OR
python aiml_service.py
```

---

## Monitoring

### Key Metrics to Track

1. **Verdict Distribution**
   ```python
   verdict_counts = {}
   for result in results:
       verdict = result['verdict']
       verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
   ```

2. **Feature Completeness**
   ```python
   completeness_scores = [
       detector.check_feature_completeness(features)[0]
       for features in all_features
   ]
   avg_completeness = sum(completeness_scores) / len(completeness_scores)
   ```

3. **Signal Counts**
   ```python
   avg_signals = sum(r['signal_count'] for r in results) / len(results)
   ```

### Expected Distributions (Normal Operation)

- BENIGN: 60-70%
- PARKED: 15-20%
- PHISHING*: 5-10%
- GAMBLING/ADULT: 3-5%
- SUSPICIOUS: 5-10%
- ERROR: <1%

If ERROR > 5%, investigate feature quality or model issues.

---

## Support

For issues or questions:
1. Check logs for warnings
2. Run test suite: `python test_improvements.py`
3. Verify model is retrained with SimpleImputer
4. Check feature completeness for failing domains

---

## Changelog

### Version 2.0 (Current)
- ✅ Fixed NaN error crashes
- ✅ Added generic phishing detection
- ✅ Added gambling/adult/malware detection
- ✅ Added domain reputation checks
- ✅ Enhanced parking detection (OCR)
- ✅ Multi-category verdict system
- ✅ Feature completeness validation

### Version 1.0 (Previous)
- CSE brand impersonation detection only
- Visual similarity (favicon, phash, CLIP)
- Tabular anomaly detection
- Basic parking detection
