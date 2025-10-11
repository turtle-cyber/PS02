import os
from pathlib import Path
from .hashing import sha256_hex

OUT_DIR = Path(os.getenv("OUT_DIR", "/workspace/out"))
HTML_DIR = OUT_DIR / "html"
SHOT_DIR = OUT_DIR / "screenshots"
PDF_DIR  = OUT_DIR / "pdfs"

for d in (HTML_DIR, SHOT_DIR, PDF_DIR):
    d.mkdir(parents=True, exist_ok=True)

def url_to_base(url: str) -> str:
    return sha256_hex(url)

def save_html(url: str, html: str) -> str:
    base = url_to_base(url)
    p = HTML_DIR / f"{base}.html"
    p.write_text(html or "", encoding="utf-8", errors="ignore")
    return str(p)

def screenshot_path(url: str) -> str:
    base = url_to_base(url)
    return str(SHOT_DIR / f"{base}_full.png")

def read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
