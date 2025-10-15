import pytesseract
from PIL import Image

def features(screenshot_path: str):
    try:
        txt = pytesseract.image_to_string(Image.open(screenshot_path))
        txt = (txt or "").strip()
        excerpt = txt[:300]
        return {
            "text_excerpt": excerpt,
            "length": len(txt)
        }
    except Exception:
        return {"text_excerpt": "", "length": 0}
