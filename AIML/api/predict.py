"""
Similarity-Based Phishing Detection API

Uses CSE baseline (benign-only) for:
- Tabular anomaly detection (IsolationForest)
- Visual similarity (CLIP embeddings)
- Favicon/phash matching
- Registrar validation
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, validator, Field
import joblib
import json
import numpy as np
from pathlib import Path
import pandas as pd
from typing import Optional, Dict, List
import logging
from datetime import datetime
import sys
from PIL import Image
import torch

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('api_predictions.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Phishing Detection Ensemble API",
    description="Multi-modal ensemble for phishing detection with tabular, text, and vision models",
    version="2.0.0"
)


class Config:
    """Configuration manager"""

    def __init__(self, config_path: str = "models/ensemble/config.json"):
        self.config_path = Path(config_path)
        self.load_config()

    def load_config(self):
        """Load configuration from JSON file"""
        try:
            if self.config_path.exists():
                with open(self.config_path) as f:
                    config = json.load(f)
                logger.info(f"Loaded configuration from {self.config_path}")
            else:
                # Default configuration for similarity-based detection
                config = {
                    "model_paths": {
                        "anomaly_detector": "models/saved/anomaly/anomaly_detector.joblib",
                        "visual_index": "models/vision/cse_index",
                        "favicon_db": "data/cse_favicon_db.csv",
                        "phash_db": "data/cse_phash_db.csv"
                    },
                    "thresholds": {
                        "anomaly_threshold": -0.1,
                        "visual_sim_threshold": 0.80,
                        "favicon_match_threshold": 0.95,
                        "phash_threshold": 10
                    },
                    "weights": {
                        "anomaly": 0.4,
                        "visual_clip": 0.3,
                        "favicon": 0.2,
                        "phash": 0.1
                    }
                }
                logger.warning(f"Config file not found at {self.config_path}, using defaults")

            self.model_paths = config.get("model_paths", {})
            self.weights = config.get("weights", {})
            self.thresholds = config.get("thresholds", {})

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise


class ModelManager:
    """Manages model loading and caching"""

    def __init__(self, config: Config):
        self.config = config
        self.models = {}
        self.load_models()

    def load_models(self):
        """Load all models into memory"""
        try:
            # Load anomaly detector
            anomaly_path = Path(self.config.model_paths.get("anomaly_detector"))
            if anomaly_path.exists():
                self.models["anomaly"] = joblib.load(anomaly_path)
                logger.info(f"Loaded anomaly detector from {anomaly_path}")
            else:
                logger.warning(f"Anomaly detector not found at {anomaly_path}")
                self.models["anomaly"] = None

            # Load CLIP visual index
            visual_dir = Path(self.config.model_paths.get("visual_index"))
            emb_path = visual_dir / "cse_embeddings.npy"
            meta_path = visual_dir / "cse_metadata.json"

            if emb_path.exists() and meta_path.exists():
                self.models["cse_embeddings"] = np.load(emb_path)
                with open(meta_path) as f:
                    self.models["cse_metadata"] = json.load(f)
                logger.info(f"Loaded {len(self.models['cse_embeddings'])} CLIP embeddings")
            else:
                logger.warning("CLIP visual index not found")
                self.models["cse_embeddings"] = None
                self.models["cse_metadata"] = None

            # Load favicon DB
            favicon_path = Path(self.config.model_paths.get("favicon_db"))
            if favicon_path.exists():
                self.models["favicon_db"] = pd.read_csv(favicon_path)
                logger.info(f"Loaded favicon DB with {len(self.models['favicon_db'])} entries")
            else:
                logger.warning("Favicon DB not found")
                self.models["favicon_db"] = None

            # Load phash DB
            phash_path = Path(self.config.model_paths.get("phash_db"))
            if phash_path.exists():
                self.models["phash_db"] = pd.read_csv(phash_path)
                logger.info(f"Loaded phash DB with {len(self.models['phash_db'])} entries")
            else:
                logger.warning("Phash DB not found")
                self.models["phash_db"] = None

        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            raise

    def get_anomaly_detector(self):
        return self.models.get("anomaly")

    def get_visual_index(self):
        return self.models.get("cse_embeddings"), self.models.get("cse_metadata")

    def get_favicon_db(self):
        return self.models.get("favicon_db")

    def get_phash_db(self):
        return self.models.get("phash_db")


class ScanRequest(BaseModel):
    """Request model with validation"""

    url: str = Field(..., description="URL to scan")
    domain: str = Field(..., description="Domain name")
    features: Dict = Field(..., description="Tabular feature vector")
    screenshot_path: Optional[str] = Field(None, description="Path to screenshot")
    favicon_hash: Optional[str] = Field(None, description="Favicon MD5/SHA256 hash")
    phash: Optional[str] = Field(None, description="Screenshot perceptual hash")
    registrar: Optional[str] = Field(None, description="Domain registrar")
    return_explanation: Optional[bool] = Field(False, description="Return detailed explanation")

    @validator('url')
    def validate_url(cls, v):
        if not v or len(v) < 3:
            raise ValueError("URL must be at least 3 characters")
        return v

    @validator('features')
    def validate_features(cls, v):
        if not v or not isinstance(v, dict):
            raise ValueError("Features must be a non-empty dictionary")
        return v


class ScanResponse(BaseModel):
    """Response model"""

    url: str
    label: str
    confidence: float
    risk_score: float
    signals: Dict[str, float]
    matched_cse_domain: Optional[str] = None
    timestamp: str
    reasons: List[str]
    explanation: Optional[Dict] = None


# Initialize global objects
config = Config()
model_manager = ModelManager(config)


def detect_anomaly(features: Dict, model) -> tuple:
    """Detect tabular anomalies vs CSE baseline"""
    try:
        if model is None:
            return 0.0, False

        X = pd.DataFrame([features])
        X = X.fillna(0)

        for c in X.columns:
            if not pd.api.types.is_numeric_dtype(X[c]):
                X[c] = X[c].astype("category").cat.codes

        score = float(model.decision_function(X.values)[0])
        prediction = model.predict(X.values)[0]
        is_anomaly = (prediction == -1)

        return score, is_anomaly
    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        return 0.0, False


def check_favicon_match(favicon_hash: str, domain: str, favicon_db: pd.DataFrame, registrar: str = None) -> tuple:
    """Check if favicon matches CSE database"""
    if favicon_db is None or not favicon_hash:
        return 0.0, None, False

    # Check for hash match
    matches = favicon_db[
        (favicon_db['favicon_md5'] == favicon_hash) |
        (favicon_db['favicon_sha256'] == favicon_hash)
    ]

    if len(matches) == 0:
        return 0.0, None, False

    matched_domain = matches.iloc[0]['registrable']

    # If domains match, not phishing
    if matched_domain == domain:
        return 1.0, matched_domain, False

    # If registrar same, likely benign (e.g., subdomain)
    if registrar and 'registrar' in matches.columns:
        matched_registrar = matches.iloc[0].get('registrar')
        if registrar == matched_registrar:
            return 0.9, matched_domain, False

    # Different domain + same favicon = phishing
    return 0.95, matched_domain, True


def check_phash_match(phash: str, domain: str, phash_db: pd.DataFrame, threshold: int = 10) -> tuple:
    """Check screenshot phash similarity"""
    if phash_db is None or not phash:
        return 0.0, None, False

    # Simple hamming distance check (implement actual phash comparison)
    matches = phash_db[phash_db['screenshot_phash'] == phash]

    if len(matches) == 0:
        return 0.0, None, False

    matched_domain = matches.iloc[0]['registrable']

    if matched_domain == domain:
        return 1.0, matched_domain, False

    return 0.90, matched_domain, True


def compute_risk_score(signals: Dict[str, float], weights: Dict) -> float:
    """Compute weighted risk score from all signals"""
    score = (
        weights.get('anomaly', 0.4) * signals.get('anomaly_score', 0.0) +
        weights.get('visual_clip', 0.3) * signals.get('visual_similarity', 0.0) +
        weights.get('favicon', 0.2) * signals.get('favicon_match', 0.0) +
        weights.get('phash', 0.1) * signals.get('phash_match', 0.0)
    )
    return np.clip(score, 0.0, 1.0)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "models_loaded": {
            "anomaly_detector": model_manager.get_anomaly_detector() is not None,
            "visual_index": model_manager.get_visual_index()[0] is not None,
            "favicon_db": model_manager.get_favicon_db() is not None,
            "phash_db": model_manager.get_phash_db() is not None
        },
        "version": "2.0.0-similarity"
    }


@app.get("/config")
async def get_config():
    """Return current configuration"""
    return {
        "weights": config.weights,
        "thresholds": config.thresholds,
        "approach": "similarity-based"
    }


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    """Scan URL using similarity-based detection"""
    start_time = datetime.now()

    try:
        logger.info(f"Scanning URL: {req.url}")

        signals = {}
        reasons = []
        matched_domain = None

        # 1. Tabular anomaly detection
        anomaly_model = model_manager.get_anomaly_detector()
        anomaly_score, is_anomaly = detect_anomaly(req.features, anomaly_model)
        signals['anomaly_score'] = abs(anomaly_score) if is_anomaly else 0.0

        if is_anomaly:
            reasons.append(f"Features deviate from CSE baseline (score={anomaly_score:.3f})")

        # 2. Favicon matching
        favicon_db = model_manager.get_favicon_db()
        fav_sim, fav_matched, is_fav_suspicious = check_favicon_match(
            req.favicon_hash, req.domain, favicon_db, req.registrar
        )
        signals['favicon_match'] = fav_sim

        if is_fav_suspicious:
            reasons.append(f"Favicon matches {fav_matched} but domain differs")
            matched_domain = fav_matched

        # 3. Screenshot phash matching
        phash_db = model_manager.get_phash_db()
        phash_sim, phash_matched, is_phash_suspicious = check_phash_match(
            req.phash, req.domain, phash_db
        )
        signals['phash_match'] = phash_sim

        if is_phash_suspicious:
            reasons.append(f"Screenshot similar to {phash_matched} but domain differs")
            if not matched_domain:
                matched_domain = phash_matched

        # 4. Visual similarity (placeholder for CLIP)
        signals['visual_similarity'] = 0.0  # TODO: Implement CLIP similarity

        # 5. Compute final risk score
        risk_score = compute_risk_score(signals, config.weights)

        # 6. Classify
        if is_fav_suspicious or is_phash_suspicious:
            label = "phishing"
            confidence = 0.90
        elif is_anomaly and risk_score > 0.5:
            label = "suspicious"
            confidence = 0.65
        elif is_anomaly:
            label = "suspicious"
            confidence = 0.50
        else:
            label = "benign"
            confidence = 0.85
            reasons.append("No anomalies detected")

        # Build response
        response = ScanResponse(
            url=req.url,
            label=label,
            confidence=round(confidence, 4),
            risk_score=round(risk_score, 4),
            signals={k: round(v, 4) for k, v in signals.items()},
            matched_cse_domain=matched_domain,
            timestamp=datetime.now().isoformat(),
            reasons=reasons if reasons else ["No issues detected"],
            explanation={"signals": signals, "thresholds": config.thresholds} if req.return_explanation else None
        )

        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Verdict: {label} (risk={risk_score:.4f}) for {req.url} in {duration:.3f}s")

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan failed for {req.url}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}"
        )


@app.post("/batch_scan")
async def batch_scan(requests: List[ScanRequest]):
    """Batch scanning endpoint"""
    results = []

    for req in requests:
        try:
            result = await scan(req)
            results.append(result)
        except Exception as e:
            logger.error(f"Batch scan failed for {req.url}: {e}")
            results.append({
                "url": req.url,
                "error": str(e),
                "label": "error",
                "confidence": 0.0,
                "risk_score": 0.0
            })

    return {
        "results": results,
        "total": len(requests),
        "successful": len([r for r in results if not hasattr(r, 'error')])
    }


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Phishing Detection API...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
