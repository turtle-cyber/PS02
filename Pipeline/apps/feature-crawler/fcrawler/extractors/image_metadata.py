"""
Image Metadata Extractor - Category 5: EXIF Data
"""
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit
from PIL import Image
from PIL.ExifTags import TAGS
import requests
from io import BytesIO
from datetime import datetime
from ..utils.config import CFG

def _extract_exif(img: Image.Image) -> dict:
    exif_data = {}
    try:
        exif_raw = img._getexif()
        if exif_raw:
            for tag_id, value in exif_raw.items():
                tag = TAGS.get(tag_id, tag_id)
                if isinstance(value, bytes):
                    try:
                        value = value.decode('utf-8', errors='ignore')
                    except:
                        value = str(value)
                exif_data[tag] = value
    except Exception:
        pass
    return exif_data

def _parse_exif_datetime(dt_str: str):
    if not dt_str:
        return None
    try:
        dt = datetime.strptime(dt_str, '%Y:%m:%d %H:%M:%S')
        return dt.isoformat() + 'Z'
    except:
        return None

def _get_image_metadata(img_url: str, timeout: float = 4.0) -> dict:
    result = {
        "url": img_url,
        "accessible": False,
        "size_bytes": None,
        "width": None,
        "height": None,
        "format": None,
        "mode": None,
        "has_exif": False,
        "camera_make": None,
        "camera_model": None,
        "datetime_original": None,
        "datetime_digitized": None,
        "gps_info": None,
        "software": None,
        "orientation": None,
    }
    
    try:
        resp = requests.get(img_url, timeout=timeout, stream=True)
        resp.raise_for_status()
        
        content_length = resp.headers.get('Content-Length')
        if content_length:
            result["size_bytes"] = int(content_length)
        
        img_bytes = resp.content
        if not result["size_bytes"]:
            result["size_bytes"] = len(img_bytes)
            
        img = Image.open(BytesIO(img_bytes))
        result["accessible"] = True
        result["width"] = img.width
        result["height"] = img.height
        result["format"] = img.format
        result["mode"] = img.mode
        
        exif = _extract_exif(img)
        if exif:
            result["has_exif"] = True
            result["camera_make"] = exif.get("Make")
            result["camera_model"] = exif.get("Model")
            result["software"] = exif.get("Software")
            result["orientation"] = exif.get("Orientation")
            
            dt_orig = exif.get("DateTimeOriginal")
            if dt_orig:
                result["datetime_original"] = _parse_exif_datetime(dt_orig)
            
            dt_dig = exif.get("DateTimeDigitized")
            if dt_dig:
                result["datetime_digitized"] = _parse_exif_datetime(dt_dig)
            
            gps = exif.get("GPSInfo")
            if gps:
                result["gps_info"] = True
        
        img.close()
    except Exception:
        pass
    
    return result

def features(html: str, base_url: str, max_images: int = None):
    soup = BeautifulSoup(html or "", "lxml")
    base_host = urlsplit(base_url).hostname or ""
    
    img_tags = soup.find_all("img", src=True)
    img_urls = [urljoin(base_url, i["src"]) for i in img_tags]
    
    max_proc = max_images or int(CFG.max_images)
    img_urls = img_urls[:max_proc]
    
    metadata_list = []
    exif_count = 0
    total_bytes = 0
    has_camera_info = False
    has_gps_info = False
    timestamps = []
    
    for img_url in img_urls:
        meta = _get_image_metadata(img_url, timeout=CFG.image_head_timeout_ms / 1000.0)
        metadata_list.append(meta)
        
        if meta["accessible"]:
            if meta["size_bytes"]:
                total_bytes += meta["size_bytes"]
            
            if meta["has_exif"]:
                exif_count += 1
            
            if meta["camera_make"] or meta["camera_model"]:
                has_camera_info = True
            
            if meta["gps_info"]:
                has_gps_info = True
            
            if meta["datetime_original"]:
                timestamps.append(meta["datetime_original"])
    
    accessible_count = sum(1 for m in metadata_list if m["accessible"])
    avg_size = round(total_bytes / accessible_count, 2) if accessible_count > 0 else 0
    
    widths = [m["width"] for m in metadata_list if m["width"]]
    heights = [m["height"] for m in metadata_list if m["height"]]
    avg_width = round(sum(widths) / len(widths), 2) if widths else 0
    avg_height = round(sum(heights) / len(heights), 2) if heights else 0
    
    return {
        "total_images": len(img_urls),
        "accessible_images": accessible_count,
        "images_with_exif": exif_count,
        "has_camera_info": has_camera_info,
        "has_gps_info": has_gps_info,
        "total_bytes": total_bytes,
        "avg_image_size_bytes": avg_size,
        "avg_width": avg_width,
        "avg_height": avg_height,
        "timestamps_found": len(timestamps),
        "earliest_timestamp": min(timestamps) if timestamps else None,
        "latest_timestamp": max(timestamps) if timestamps else None,
        "detailed_metadata": metadata_list[:10]
    }