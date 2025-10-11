from PIL import Image
import imagehash
from pathlib import Path
from ..utils.config import CFG

def _phash(path: str) -> str:
    img = Image.open(path).convert("RGB")
    return str(imagehash.phash(img))

def _hamming(a: str, b: str) -> int:
    return imagehash.hex_to_hash(a) - imagehash.hex_to_hash(b)

def features(screenshot_path: str, cse_id: str):
    screen_phash = _phash(screenshot_path)

    logos_dir = Path(f"/workspace/configs/brand_assets/{cse_id}/logos")
    logo_detected = False
    min_dist = None
    if logos_dir.exists():
        for lp in logos_dir.glob("*.*"):
            try:
                lp_hash = _phash(str(lp))
                d = _hamming(screen_phash, lp_hash)
                if min_dist is None or d < min_dist:
                    min_dist = d
            except Exception:
                continue
        if min_dist is not None and min_dist <= CFG.logo_phash_threshold:
            logo_detected = True

    return {
        "phash": screen_phash,
        "logo_detected": logo_detected,
        "logo_min_phash_distance": min_dist
    }
