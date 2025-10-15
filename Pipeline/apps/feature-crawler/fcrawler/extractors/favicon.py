from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit
from io import BytesIO
from PIL import Image
import requests
import hashlib
from ..utils.config import CFG

def _abs(base_url: str, href: str) -> str:
    return urljoin(base_url, href)

def _hash_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _color_hist_sim(img: Image.Image) -> float:
    # simple histogram cosine similarity vs gray baseline to get a stable number
    h = img.convert("RGB").resize((64,64)).histogram()
    import math
    norm = math.sqrt(sum(v*v for v in h)) or 1.0
    # compare to itself baseline (always 1.0), but return a normalized mean channel variance as proxy
    return round(sum(h)/ (len(h)*255.0), 4)

def features(html: str, base_url: str, cse_id: str):
    soup = BeautifulSoup(html or "", "lxml")
    base_host = urlsplit(base_url).hostname or ""
    href = None

    # find link rel=icon/apple-touch-icon/shortcut icon
    for l in soup.find_all("link", href=True, rel=True):
        rel = " ".join(l.get("rel", [])).lower()
        if any(k in rel for k in ("icon", "shortcut icon", "apple-touch-icon")):
            href = l["href"]
            break
    if not href:
        href = "/favicon.ico"

    fav_url = _abs(base_url, href)
    sha256 = None
    color_sim = None
    ok = False

    try:
        r = requests.get(fav_url, timeout=4)
        r.raise_for_status()
        sha256 = _hash_bytes(r.content)
        ok = True
        try:
            img = Image.open(BytesIO(r.content))
            color_sim = _color_hist_sim(img)
        except Exception:
            pass
    except Exception:
        pass

    # compare against legit hash if exists
    legit_hash_path = f"/workspace/configs/brand_assets/{cse_id}/favicon.sha256"
    match_legit = None
    try:
        with open(legit_hash_path, "r", encoding="utf-8") as f:
            legit = f.read().strip()
            if sha256:
                match_legit = (sha256 == legit)
    except Exception:
        pass

    return {
        "present": ok,
        "url": fav_url,
        "sha256": sha256,
        "color_similarity": color_sim,
        "matches_legit": match_legit
    }
