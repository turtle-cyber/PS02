from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit
import requests
import math
from ..utils.config import CFG

def _is_internal(href: str, base_host: str) -> bool:
    host = urlsplit(href).hostname
    return (host is None) or (host == base_host)

def features(html: str, base_url: str):
    soup = BeautifulSoup(html or "", "lxml")
    base_host = urlsplit(base_url).hostname or ""
    imgs = [urljoin(base_url, i["src"]) for i in soup.find_all("img", src=True)]

    internal = [u for u in imgs if _is_internal(u, base_host)]
    external = [u for u in imgs if not _is_internal(u, base_host)]

    # Try HEAD a subset to estimate total bytes
    total_bytes = 0
    checked = 0
    for u in imgs[: int(CFG.max_images)]:
        try:
            r = requests.head(u, timeout=CFG.image_head_timeout_ms/1000.0, allow_redirects=True)
            cl = r.headers.get("Content-Length")
            if cl:
                total_bytes += int(cl)
            checked += 1
        except Exception:
            continue

    return {
        "count": len(imgs),
        "internal_count": len(internal),
        "external_count": len(external),
        "total_bytes_est": total_bytes,
        "sampled_count": checked
    }
