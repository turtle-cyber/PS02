"""
Image OCR Extractor - OCR for individual page images
Extracts text from images embedded in the page (brand logos, banners, etc.)
This is different from screenshot OCR which captures the rendered page.
"""
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit
from PIL import Image
import pytesseract
import requests
from io import BytesIO
import re
from ..utils.config import CFG

def _is_internal(href: str, base_host: str) -> bool:
    host = urlsplit(href).hostname
    return (host is None) or (host == base_host)

def _ocr_image_url(img_url: str, timeout: float = 4.0) -> dict:
    """Download and OCR a single image"""
    result = {
        "url": img_url,
        "accessible": False,
        "text": "",
        "text_length": 0,
        "has_brand_keywords": False,
        "has_suspicious_keywords": False,
    }
    
    try:
        resp = requests.get(img_url, timeout=timeout)
        resp.raise_for_status()
        
        img = Image.open(BytesIO(resp.content))
        
        # Perform OCR
        text = pytesseract.image_to_string(img, lang='eng')
        text = (text or "").strip()
        
        result["accessible"] = True
        result["text"] = text[:500]  # First 500 chars
        result["text_length"] = len(text)
        
        # Check for common phishing keywords
        text_lower = text.lower()
        
        # Brand/login keywords
        brand_keywords = [
            "login", "sign in", "password", "username", 
            "verify", "account", "security", "suspended",
            "bank", "paypal", "amazon", "google", "microsoft"
        ]
        result["has_brand_keywords"] = any(kw in text_lower for kw in brand_keywords)
        
        # Suspicious urgency keywords
        suspicious = [
            "urgent", "immediately", "expire", "suspended",
            "verify now", "click here", "limited time", "act now"
        ]
        result["has_suspicious_keywords"] = any(kw in text_lower for kw in suspicious)
        
        img.close()
        
    except Exception as e:
        # Image not accessible or OCR failed
        pass
    
    return result

def _extract_keywords(text: str) -> list:
    """Extract important keywords from OCR text"""
    # Remove common noise words
    noise = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for'}
    
    words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
    keywords = [w for w in words if w not in noise]
    
    # Return most common keywords
    from collections import Counter
    return [w for w, _ in Counter(keywords).most_common(20)]

def features(html: str, base_url: str, max_images: int = None):
    """
    Extract text from images on the page using OCR.
    Useful for detecting brand impersonation in image-heavy phishing pages.
    
    Args:
        html: HTML content
        base_url: Base URL for resolving relative paths
        max_images: Maximum number of images to OCR (default from CFG)
    
    Returns:
        dict with OCR results from page images
    """
    soup = BeautifulSoup(html or "", "lxml")
    base_host = urlsplit(base_url).hostname or ""
    
    # Find all images
    img_tags = soup.find_all("img", src=True)
    img_urls = [urljoin(base_url, i["src"]) for i in img_tags]
    
    # Limit processing (OCR is expensive)
    max_proc = max_images or min(int(CFG.max_images), 10)  # Default to 10 for OCR
    img_urls = img_urls[:max_proc]
    
    # OCR each image
    ocr_results = []
    all_text = []
    brand_keyword_count = 0
    suspicious_keyword_count = 0
    
    for img_url in img_urls:
        ocr = _ocr_image_url(img_url, timeout=CFG.image_head_timeout_ms / 1000.0)
        ocr_results.append(ocr)
        
        if ocr["accessible"] and ocr["text"]:
            all_text.append(ocr["text"])
            
            if ocr["has_brand_keywords"]:
                brand_keyword_count += 1
            
            if ocr["has_suspicious_keywords"]:
                suspicious_keyword_count += 1
    
    # Combine all OCR text
    combined_text = " ".join(all_text)
    keywords = _extract_keywords(combined_text)
    
    # Statistics
    accessible_count = sum(1 for r in ocr_results if r["accessible"])
    images_with_text = sum(1 for r in ocr_results if r["text_length"] > 0)
    total_text_length = sum(r["text_length"] for r in ocr_results)
    
    return {
        "total_images_processed": len(img_urls),
        "images_accessible": accessible_count,
        "images_with_text": images_with_text,
        "total_text_length": total_text_length,
        "combined_text_excerpt": combined_text[:1000],  # First 1000 chars
        "images_with_brand_keywords": brand_keyword_count,
        "images_with_suspicious_keywords": suspicious_keyword_count,
        "extracted_keywords": keywords[:20],  # Top 20 keywords
        "detailed_ocr_results": ocr_results  # Full results for each image
    }