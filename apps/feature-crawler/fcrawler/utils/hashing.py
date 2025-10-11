import hashlib
from PIL import Image
import imagehash

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()

def phash_image(path: str) -> str:
    img = Image.open(path).convert("RGB")
    return str(imagehash.phash(img))
