from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit

def _is_internal(href: str, base_host: str) -> bool:
    host = urlsplit(href).hostname
    return (host is None) or (host == base_host)

def features(html: str, base_url: str):
    soup = BeautifulSoup(html or "", "lxml")
    base_host = urlsplit(base_url).hostname or ""

    # Links
    internal = external = 0
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a["href"])
        if _is_internal(href, base_host):
            internal += 1
        else:
            external += 1

    # Scripts & stylesheets
    scripts_external = sum(1 for s in soup.find_all("script", src=True) if not _is_internal(urljoin(base_url, s["src"]), base_host))
    styles_external = sum(1 for l in soup.find_all("link", rel=True, href=True) if "stylesheet" in " ".join(l.get("rel", [])).lower() and not _is_internal(urljoin(base_url, l["href"]), base_host))

    iframes = len(soup.find_all("iframe"))
    html_bytes = len((html or "").encode("utf-8", "ignore"))

    return {
        "bytes": html_bytes,
        "links_internal": internal,
        "links_external": external,
        "iframes": iframes,
        "scripts_external": scripts_external,
        "stylesheets_external": styles_external,
    }
