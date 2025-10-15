import re
from bs4 import BeautifulSoup
from pathlib import Path

BRANDS = Path("/workspace/configs/dictionaries/brands.txt")
SUS = Path("/workspace/configs/dictionaries/suspicious_keywords.txt")

def _load_lines(p: Path):
    try:
        return [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    except Exception:
        return []

BRAND_TERMS = _load_lines(BRANDS)
SUSPICIOUS = _load_lines(SUS)

def _visible_text(html: str) -> str:
    soup = BeautifulSoup(html or "", "lxml")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    txt = soup.get_text(separator=" ", strip=True)
    return re.sub(r"\s+", " ", txt)

def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return round(inter / union, 4)

def features(html: str, base_url: str, cse_id: str):
    text = _visible_text(html)
    tokens = {t.lower() for t in re.findall(r"[a-zA-Z0-9]+", text)}
    brand_hits = sum(1 for term in BRAND_TERMS if term.lower() in text.lower())
    sus_hits = [kw for kw in SUSPICIOUS if kw.lower() in text.lower()]

    # Optional: similarity to legit text if exists
    legit_path = Path(f"/workspace/configs/brand_assets/{cse_id}/legit_text.txt")
    sim = 0.0
    if legit_path.exists():
        ltokens = {t.lower() for t in re.findall(r"[a-zA-Z0-9]+", legit_path.read_text(encoding="utf-8"))}
        sim = _jaccard(tokens, ltokens)

    return {
        "visible_len": len(text),
        "brand_mentions": brand_hits,
        "keywords": sus_hits[:10],
        "similarity_to_legit": sim
    }
