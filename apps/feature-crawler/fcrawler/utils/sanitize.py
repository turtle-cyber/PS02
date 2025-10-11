import re

def safe_filename(s: str) -> str:
    s = s or "UNKNOWN"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)
