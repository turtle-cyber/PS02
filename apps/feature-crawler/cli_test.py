#!/usr/bin/env python3
import argparse
import json
import os
import time
from urllib.parse import urlsplit, urljoin
from datetime import datetime
from io import BytesIO

import requests
from PIL import Image, ImageFile
ImageFile.LOAD_TRUNCATED_IMAGES = True

from fcrawler.runner import navigate_and_capture
from fcrawler.utils.pdf import png_to_pdf
from fcrawler.utils.hashing import sha256_hex
from fcrawler.utils.io import read_text
from fcrawler.utils.config import CFG

import fcrawler.extractors.url_features as urlf
import fcrawler.extractors.idn_features as idnf
import fcrawler.extractors.html_features as htmlf
import fcrawler.extractors.form_features as formf
import fcrawler.extractors.text_features as textf
import fcrawler.extractors.favicon as favf
import fcrawler.extractors.image_features as imgf
import fcrawler.extractors.visual as visf
import fcrawler.extractors.ocr as ocrf

# your new extractors
import fcrawler.extractors.image_metadata as imgmetaf
import fcrawler.extractors.image_ocr as imgocrf

# we’ll use Playwright directly to get rendered image URLs for debugging
from playwright.sync_api import sync_playwright


def cse_and_subdomain(url: str, registrable: str | None) -> tuple[str, str]:
    cse_id = (registrable or "").split(".")[0].upper() if registrable else (os.getenv("DEFAULT_CSE", "CSE"))
    host = urlsplit(url).hostname or ""
    subdomain = host.replace(registrable, "").rstrip(".") if (registrable and host.endswith(registrable)) else host
    subdomain = subdomain or "root"
    return cse_id, subdomain


def deterministic_serial(url: str) -> str:
    h = int(sha256_hex(url), 16) % 100000
    return f"{h:05d}"


IMAGE_METADATA_DEFAULT = {
    "total_images": 0, "accessible_images": 0, "images_with_exif": 0,
    "has_camera_info": False, "has_gps_info": False,
    "total_bytes": 0, "avg_image_size_bytes": 0, "avg_width": 0, "avg_height": 0,
    "timestamps_found": 0, "earliest_timestamp": None, "latest_timestamp": None,
    "detailed_metadata": []
}
IMAGE_OCR_DEFAULT = {
    "total_images_processed": 0, "images_accessible": 0, "images_with_text": 0,
    "total_text_length": 0, "combined_text_excerpt": "",
    "images_with_brand_keywords": 0, "images_with_suspicious_keywords": 0,
    "extracted_keywords": [], "detailed_ocr_results": []
}


def safe_call(fn, *args, default=None, **kwargs):
    try:
        out = fn(*args, **kwargs)
        return out if out is not None else default
    except Exception as e:
        print(f"[warn] extractor {getattr(fn, '__name__', fn)} failed: {e}")
        return default


def call_imgmeta(html: str, base_url: str):
    for name in ("features", "extract", "run"):
        fn = getattr(imgmetaf, name, None)
        if callable(fn):
            print(f"[debug] image_metadata entrypoint: {imgmetaf.__file__} :: {name}()")
            return safe_call(fn, html, base_url, default=IMAGE_METADATA_DEFAULT)
    print(f"[warn] image_metadata has no features()/extract()/run(); module at {imgmetaf.__file__}")
    return IMAGE_METADATA_DEFAULT


def call_imgocr(html: str, base_url: str):
    for name in ("features", "extract", "run"):
        fn = getattr(imgocrf, name, None)
        if callable(fn):
            print(f"[debug] image_ocr entrypoint: {imgocrf.__file__} :: {name}()")
            return safe_call(fn, html, base_url, default=IMAGE_OCR_DEFAULT)
    print(f"[warn] image_ocr has no features()/extract()/run(); module at {imgocrf.__file__}")
    return IMAGE_OCR_DEFAULT


def soup_img_urls(html_text: str, base_url: str):
    # fall back to HTML src values (may be placeholders for lazy-loaded images)
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html_text or "", "lxml")
    raw = [t.get("src") for t in soup.find_all("img") if t.get("src")]
    abs_urls = [urljoin(base_url, u) for u in raw]
    return abs_urls


def rendered_img_urls(url: str, user_agent: str | None = None, timeout_ms: int = 15000):
    # collects currentSrc or src after the page finishes loading
    headers = {"User-Agent": user_agent} if user_agent else None
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=(os.getenv("PLAYWRIGHT_HEADLESS","1")=="1"))
        ctx = browser.new_context(user_agent=user_agent) if user_agent else browser.new_context()
        page = ctx.new_page()
        page.set_default_timeout(timeout_ms)
        page.goto(url, wait_until="networkidle")
        urls = page.evaluate("""
            () => Array.from(document.images).map(i => i.currentSrc || i.src).filter(Boolean)
        """)
        browser.close()
        return urls or []


def fetch_probe(urls, base_url, max_n=3):
    # Fetch a few images with proper headers; return per-image debug info
    out = []
    headers = {
        "User-Agent": (CFG.user_agent or "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
        "Referer": base_url
    }
    for u in urls[:max_n]:
        item = {"url": u, "ok": False}
        try:
            r = requests.get(u, headers=headers, timeout=6, stream=True)
            item["status"] = r.status_code
            item["content_type"] = r.headers.get("Content-Type")
            content = r.content
            item["bytes"] = len(content)
            try:
                img = Image.open(BytesIO(content))
                item["format"] = img.format
                item["width"], item["height"] = img.size
                # tiny EXIF peek (don’t dump everything)
                exif = {}
                try:
                    if hasattr(img, "getexif"):
                        e = img.getexif()
                        exif = {str(k): str(v)[:64] for k, v in list(e.items())[:10]} if e else {}
                except Exception:
                    pass
                item["exif_keys"] = list(exif.keys())
                # quick OCR smoke (only for reasonably sized images)
                ocr_text = ""
                if item["width"] and item["height"] and item["width"]*item["height"] >= 40_000:  # ~200x200
                    try:
                        import pytesseract
                        ocr_text = (pytesseract.image_to_string(img) or "").strip()
                    except Exception as ocr_e:
                        ocr_text = f"[ocr_error:{ocr_e}]"
                item["ocr_len"] = len(ocr_text)
                item["ocr_excerpt"] = (ocr_text[:120] + "...") if len(ocr_text) > 120 else ocr_text
                item["ok"] = True
            except Exception as pil_e:
                item["pil_error"] = str(pil_e)
        except Exception as req_e:
            item["req_error"] = str(req_e)
        out.append(item)
    return out


def main():
    p = argparse.ArgumentParser(description="Feature Crawler: single-URL test runner (no Kafka).")
    p.add_argument("--url", required=True)
    p.add_argument("--registrable", default=None)
    p.add_argument("--cse", default=None)
    p.add_argument("--out_jsonl", default=None)
    p.add_argument("--raw_jsonl", default=None)
    args = p.parse_args()

    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    out_jsonl = args.out_jsonl or f"/workspace/out/features_page_{ts}.jsonl"
    raw_jsonl = args.raw_jsonl or f"/workspace/out/http_crawled_{ts}.jsonl"

    url = args.url
    registrable = args.registrable
    cse_id = args.cse or (registrable.split(".")[0].upper() if registrable else "CSE")

    print(f"[debug] image_metadata module: {imgmetaf.__file__}")
    print(f"[debug] image_ocr module:      {imgocrf.__file__}")
    print(f"[debug] writing -> features: {out_jsonl}")
    print(f"[debug] writing -> crawled:  {raw_jsonl}")

    t0 = time.time()
    art = navigate_and_capture(url)
    serial = deterministic_serial(art["final_url"])
    _, subdomain = cse_and_subdomain(art["final_url"], registrable)
    pdf_path = png_to_pdf(art["screenshot_path"], cse_id, subdomain, serial)

    crawl_evt = {
        "schema_version": "v1",
        "event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "url": url,
        "final_url": art["final_url"],
        "status": art["status"],
        "title": art.get("title"),
        "html_path": art["html_path"],
        "screenshot_paths": [art["screenshot_path"]],
        "pdf_path": pdf_path,
        "latency_ms": int((time.time() - t0) * 1000),
    }

    html_text = read_text(art["html_path"]) or ""
    base_url = art["final_url"]

    # Core feature extractors (unchanged)
    url_feats    = safe_call(urlf.features, base_url, default={})
    idn_feats    = safe_call(idnf.features, base_url, default={})
    html_feats   = safe_call(htmlf.features, html_text, base_url, default={})
    form_feats   = safe_call(formf.features, html_text, base_url, default={})
    text_feats   = safe_call(textf.features, html_text, base_url, cse_id, default={})
    favicon_feats= safe_call(favf.features, html_text, base_url, cse_id, default={})
    image_feats  = safe_call(imgf.features, html_text, base_url, default={})
    visual_feats = safe_call(visf.features, art["screenshot_path"], cse_id, default={})
    ocr_feats    = safe_call(ocrf.features, art["screenshot_path"], default={"text_excerpt":"", "length":0})

    # NEW: call your modules (never null)
    image_metadata_feats = call_imgmeta(html_text, base_url)
    image_ocr_feats      = call_imgocr(html_text, base_url)

    # --- IMAGE DEBUGGING START ---
    # 1) raw HTML <img src>
    html_img_urls = soup_img_urls(html_text, base_url)
    # 2) rendered image URLs (handles lazy-loading)
    try:
        rend_img_urls = rendered_img_urls(base_url, user_agent=(CFG.user_agent or None), timeout_ms=int(os.getenv("NAV_TIMEOUT_MS","15000")))
    except Exception as e:
        print(f"[warn] rendered_img_urls failed: {e}")
        rend_img_urls = []

    # 3) fetch & probe a few
    # prefer rendered urls, fall back to html srcs
    probe_src = rend_img_urls or html_img_urls
    img_probes = fetch_probe(probe_src, base_url, max_n=3)

    print("\n[debug] image URL counts:",
          json.dumps({
              "html_img_count": len(html_img_urls),
              "rendered_img_count": len(rend_img_urls),
              "probe_src_used": "rendered" if rend_img_urls else "html",
          }, indent=2))
    print("[debug] image probes:", json.dumps(img_probes, indent=2)[:1600])

    # Pack a compact debug block into the features record
    debug_block = {
        "image_probe": {
            "html_img_count": len(html_img_urls),
            "rendered_img_count": len(rend_img_urls),
            "used": "rendered" if rend_img_urls else "html",
            "samples": img_probes
        }
    }
    # --- IMAGE DEBUGGING END ---

    feat_evt = {
        "schema_version": "v1",
        "event_time": crawl_evt["event_time"],
        "url": base_url,
        "registrable": registrable,
        "cse_id": cse_id,
        "pdf_path": pdf_path,
        "url_features": url_feats,
        "idn": idn_feats,
        "favicon": favicon_feats,
        "images": image_feats,
        "html": html_feats,
        "forms": form_feats,
        "text": text_feats,
        "visual": visual_feats,
        "ocr": ocr_feats,
        "image_metadata": image_metadata_feats or IMAGE_METADATA_DEFAULT,
        "image_ocr": image_ocr_feats or IMAGE_OCR_DEFAULT,
        "debug": debug_block,
    }

    with open(raw_jsonl, "a", encoding="utf-8") as f:
        f.write(json.dumps(crawl_evt, ensure_ascii=False) + "\n")
    with open(out_jsonl, "a", encoding="utf-8") as f:
        f.write(json.dumps(feat_evt, ensure_ascii=False) + "\n")

    # Human-friendly summary
    print("\n=== CRAWL ARTIFACTS ===")
    print(json.dumps(crawl_evt, indent=2, ensure_ascii=False))

    print("\n=== FEATURES KEYS PRESENT ===")
    print(sorted(list(feat_evt.keys())))
    print(f"\n[ok] wrote features to: {out_jsonl}")


if __name__ == "__main__":
    main()
