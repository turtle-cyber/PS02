import idna
from urllib.parse import urlsplit

def idn_info(url: str):
    host = urlsplit(url).hostname or ""
    if not host:
        return {"is_idn": False, "punycode": None, "mixed_script": False, "confusable_count": 0}

    is_idn = any(ord(c) > 127 for c in host)
    try:
        punycode = idna.encode(host).decode("ascii")
    except Exception:
        try:
            punycode = host.encode("ascii").decode("ascii")
        except Exception:
            punycode = None

    ascii_present = any(ord(c) < 128 for c in host)
    non_ascii_present = any(ord(c) > 127 for c in host)
    mixed_script = ascii_present and non_ascii_present
    confusable_count = sum(1 for c in host if ord(c) > 127)

    return {
        "is_idn": is_idn or (punycode and punycode.startswith("xn--")),
        "punycode": punycode,
        "mixed_script": mixed_script,
        "confusable_count": confusable_count
    }

def features(url: str):
    return idn_info(url)
