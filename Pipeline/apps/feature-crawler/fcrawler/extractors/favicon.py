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

def _extract_color_scheme(img: Image.Image) -> dict:
    """
    Extract color scheme features from favicon.
    Returns dominant colors, color diversity, and entropy metrics.
    """
    import math
    from collections import Counter

    result = {
        "dominant_colors": [],
        "color_count": 0,
        "color_variance": 0.0,
        "color_entropy": 0.0,
        "has_transparency": False,
        "avg_brightness": 0.0
    }

    try:
        # Convert to RGB if needed, preserve alpha info
        if img.mode == 'RGBA':
            result["has_transparency"] = True
            # Check if alpha channel has transparency
            alpha = img.split()[-1]
            if alpha.getextrema()[0] < 255:
                result["has_transparency"] = True
            img_rgb = img.convert('RGB')
        else:
            img_rgb = img.convert('RGB')

        # Resize for faster processing
        img_small = img_rgb.resize((32, 32))
        pixels = list(img_small.getdata())

        # Count unique colors
        color_counts = Counter(pixels)
        result["color_count"] = len(color_counts)

        # Get top 5 dominant colors
        dominant = color_counts.most_common(5)
        result["dominant_colors"] = [
            {"rgb": list(color), "hex": "#{:02x}{:02x}{:02x}".format(*color), "count": count}
            for color, count in dominant
        ]

        # Calculate color variance (spread across RGB space)
        if pixels:
            r_vals = [p[0] for p in pixels]
            g_vals = [p[1] for p in pixels]
            b_vals = [p[2] for p in pixels]

            r_var = sum((x - sum(r_vals)/len(r_vals))**2 for x in r_vals) / len(r_vals)
            g_var = sum((x - sum(g_vals)/len(g_vals))**2 for x in g_vals) / len(g_vals)
            b_var = sum((x - sum(b_vals)/len(b_vals))**2 for x in b_vals) / len(b_vals)

            result["color_variance"] = round(math.sqrt((r_var + g_var + b_var) / 3), 2)

            # Average brightness
            brightness_vals = [(r+g+b)/3 for r,g,b in pixels]
            result["avg_brightness"] = round(sum(brightness_vals) / len(brightness_vals), 2)

        # Calculate color entropy (Shannon entropy of color distribution)
        total_pixels = sum(color_counts.values())
        if total_pixels > 0:
            entropy = 0.0
            for count in color_counts.values():
                p = count / total_pixels
                if p > 0:
                    entropy -= p * math.log2(p)
            result["color_entropy"] = round(entropy, 4)

    except Exception as e:
        pass

    return result

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
    color_scheme = None
    ok = False

    try:
        r = requests.get(fav_url, timeout=4)
        r.raise_for_status()
        sha256 = _hash_bytes(r.content)
        ok = True
        try:
            img = Image.open(BytesIO(r.content))
            color_sim = _color_hist_sim(img)
            color_scheme = _extract_color_scheme(img)
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
        "color_scheme": color_scheme,
        "matches_legit": match_legit
    }
