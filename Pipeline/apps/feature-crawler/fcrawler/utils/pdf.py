from PIL import Image
from .io import PDF_DIR
from .sanitize import safe_filename

def png_to_pdf(png_path: str, cse: str, subdomain: str, serial: str) -> str:
    pdf_name = f"{safe_filename(cse)}_{safe_filename(subdomain or 'root')}_{serial}.pdf"
    pdf_path = str(PDF_DIR / pdf_name)
    img = Image.open(png_path).convert("RGB")
    img.save(pdf_path, "PDF", resolution=150.0)
    return pdf_path
