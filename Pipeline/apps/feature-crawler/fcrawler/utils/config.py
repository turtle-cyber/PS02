import os, yaml
from dataclasses import dataclass

@dataclass
class _Cfg:
    concurrency: int = 2
    nav_timeout_ms: int = 15000
    user_agent: str = ""
    screenshot_full_page: bool = True
    max_images: int = 64
    image_head_timeout_ms: int = 4000
    block_patterns: list = None
    evidence_serial_backend: str = "hash"
    logo_phash_threshold: int = 8

def _load():
    path = os.getenv("CONFIG_FILE", "/workspace/configs/feature_crawler.yml")
    cfg = _Cfg()
    try:
        with open(path, "r", encoding="utf-8") as f:
            y = yaml.safe_load(f) or {}
        for k, v in y.items():
            if hasattr(cfg, k):
                setattr(cfg, k, v)
    except Exception:
        pass
    return cfg

CFG = _load()
