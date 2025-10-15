from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit

def features(html: str, base_url: str):
    soup = BeautifulSoup(html or "", "lxml")
    base_host = urlsplit(base_url).hostname or ""

    forms = soup.find_all("form")
    count = len(forms)
    password_fields = email_fields = 0
    submit_texts = []
    actions = []

    for f in forms:
        # count inputs
        for inp in f.find_all("input"):
            t = (inp.get("type") or "").lower()
            if t == "password":
                password_fields += 1
            if t in ("email", "text", "username"):
                # treat as potential username
                if t in ("email", "text"):
                    email_fields += 1
        # submit labels
        for btn in f.find_all(["button", "input"]):
            t = (btn.get("type") or "").lower()
            if t in ("submit", ""):
                label = btn.get_text(strip=True) if btn.name == "button" else (btn.get("value") or "").strip()
                if not label or label.lower() == "null":
                    continue
                submit_texts.append(label[:64])

        # actions
        action_url = urljoin(base_url, f.get("action") or "")
        ahost = urlsplit(action_url).hostname or base_host
        actions.append({"url": action_url, "cross_domain": (ahost != base_host)})
    seen = set()
    submit_texts = [x for x in submit_texts if not (x in seen or seen.add(x))]

    return {
        "count": count,
        "password_fields": password_fields,
        "email_fields": email_fields,
        "submit_texts": submit_texts[:5],
        "actions": actions[:5]
    }
