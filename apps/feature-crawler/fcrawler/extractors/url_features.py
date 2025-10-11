import math
import re
from urllib.parse import urlsplit
import tldextract

SPECIALS_RE = re.compile(r'[@&%_\-\?=\$\!#%]')
REPEATED_DIGITS_RE = re.compile(r'(\d)\1{1,}')

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    ln = len(s)
    return round(sum(-(c/ln)*math.log2(c/ln) for c in Counter(s).values()), 4)

def features(url: str):
    parts = urlsplit(url)
    host = parts.hostname or ""
    url_len = len(url)

    dots = url.count(".")
    specials = len(SPECIALS_RE.findall(url))
    hyphens = url.count("-")
    slashes = url.count("/")
    underscores = url.count("_")
    qmarks = url.count("?")
    equals = url.count("=")
    dollars = url.count("$")
    exclaims = url.count("!")
    hashtags = url.count("#")
    percents = url.count("%")

    tld = tldextract.extract(url)
    domain = f"{tld.domain}.{tld.suffix}" if tld.suffix else tld.domain
    domain_len = len(domain)
    domain_hyphens = domain.count("-")
    domain_specials = len(SPECIALS_RE.findall(domain))
    domain_has_specials = domain_specials > 0

    subs = [s for s in tld.subdomain.split(".") if s] if tld.subdomain else []
    num_subdomains = len(subs)
    avg_sub_len = round(sum(map(len, subs)) / num_subdomains, 2) if num_subdomains else 0.0
    sub_concat = "".join(subs)
    sub_entropy = shannon_entropy(sub_concat) if sub_concat else 0.0
    sub_specials = len(SPECIALS_RE.findall(sub_concat)) if sub_concat else 0
    sub_has_hyphen = "-" in sub_concat
    sub_has_repeated_digits = bool(REPEATED_DIGITS_RE.search(sub_concat))

    path_qf = parts.path + (("?" + parts.query) if parts.query else "") + (("#" + parts.fragment) if parts.fragment else "")
    path_len = len(path_qf)
    has_query = bool(parts.query)
    has_fragment = bool(parts.fragment)

    has_repeated_digits = bool(REPEATED_DIGITS_RE.search(url))
    url_entropy = shannon_entropy(url)
    domain_entropy = shannon_entropy(domain)

    return {
        "url_length": url_len,
        "num_dots": dots,
        "has_repeated_digits": has_repeated_digits,
        "num_special_chars": specials,
        "num_hyphens": hyphens,
        "num_slashes": slashes,
        "num_underscores": underscores,
        "num_question_marks": qmarks,
        "num_equal_signs": equals,
        "num_dollar_signs": dollars,
        "num_exclamation_marks": exclaims,
        "num_hashtags": hashtags,
        "num_percent_signs": percents,
        "domain_length": domain_len,
        "domain_hyphens": domain_hyphens,
        "domain_has_special_chars": domain_has_specials,
        "domain_num_special_chars": domain_specials,
        "url_entropy": url_entropy,
        "domain_entropy": domain_entropy,
        "num_subdomains": num_subdomains,
        "avg_subdomain_length": avg_sub_len,
        "subdomain_entropy": sub_entropy,
        "subdomain_num_special_chars": sub_specials,
        "subdomain_has_hyphen": sub_has_hyphen,
        "subdomain_has_repeated_digits": sub_has_repeated_digits,
        "path_length": path_len,
        "path_has_query": has_query,
        "path_has_fragment": has_fragment,
        "url_has_anchor": has_fragment,
    }
