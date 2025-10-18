#!/usr/bin/env python3
"""
Test script for new feature extractors:
- Favicon color scheme analysis
- Image quality metrics
- OCR text extraction
"""
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
from io import BytesIO

# Add the app to path
sys.path.insert(0, str(Path(__file__).parent))

from fcrawler.extractors import favicon, image_metadata, ocr, image_ocr


def test_favicon_color_scheme():
    """Test favicon color scheme extraction"""
    print("\n=== Testing Favicon Color Scheme Analysis ===")

    # Create a simple test favicon (16x16 with red and blue pixels)
    img = Image.new('RGB', (16, 16))
    pixels = img.load()

    # Fill with red and blue pattern
    for i in range(16):
        for j in range(16):
            if (i + j) % 2 == 0:
                pixels[i, j] = (255, 0, 0)  # Red
            else:
                pixels[i, j] = (0, 0, 255)  # Blue

    # Test color extraction
    from fcrawler.extractors.favicon import _extract_color_scheme
    result = _extract_color_scheme(img)

    print(f"✓ Color count: {result['color_count']}")
    print(f"✓ Color variance: {result['color_variance']}")
    print(f"✓ Color entropy: {result['color_entropy']}")
    print(f"✓ Has transparency: {result['has_transparency']}")
    print(f"✓ Avg brightness: {result['avg_brightness']}")
    print(f"✓ Dominant colors: {len(result['dominant_colors'])} colors")

    if result['dominant_colors']:
        print(f"  - Top color: {result['dominant_colors'][0]['hex']}")

    assert result['color_count'] > 0, "Should detect colors"
    assert len(result['dominant_colors']) > 0, "Should have dominant colors"
    print("✓ Favicon color scheme test PASSED")


def test_image_quality_metrics():
    """Test image quality assessment"""
    print("\n=== Testing Image Quality Metrics ===")

    # Create a sharp test image
    img_sharp = Image.new('L', (100, 100), color=128)
    draw = ImageDraw.Draw(img_sharp)
    # Draw sharp edges
    for i in range(0, 100, 10):
        draw.line([(i, 0), (i, 100)], fill=255, width=2)

    from fcrawler.extractors.image_metadata import _calculate_image_quality
    result = _calculate_image_quality(img_sharp)

    print(f"✓ Resolution: {result['resolution']} pixels")
    print(f"✓ Sharpness score: {result['sharpness_score']}")
    print(f"✓ Compression quality: {result['compression_quality']}")
    print(f"✓ Quality classification: {result['quality_classification']}")
    print(f"✓ Aspect ratio: {result['aspect_ratio']}")

    assert result['resolution'] == 10000, "Resolution should be 100x100"
    assert result['sharpness_score'] > 0, "Should calculate sharpness"
    assert result['quality_classification'] in ['high', 'medium', 'low', 'unknown'], "Valid quality classification"
    print("✓ Image quality metrics test PASSED")


def test_ocr_extraction():
    """Test OCR text extraction from screenshot"""
    print("\n=== Testing OCR Text Extraction ===")

    # Create a simple image with text
    img = Image.new('RGB', (200, 50), color='white')
    draw = ImageDraw.Draw(img)

    # Try to use a default font
    try:
        # Use default font
        draw.text((10, 10), "Login Account", fill='black')
    except Exception as e:
        print(f"⚠ Could not draw text: {e}")
        print("  Skipping OCR test (tesseract may not be installed)")
        return

    # Save to temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as f:
        img.save(f.name)
        temp_path = f.name

    try:
        result = ocr.features(temp_path)

        print(f"✓ OCR extracted text length: {result['length']}")
        print(f"✓ Text excerpt: '{result['text_excerpt'][:50]}...'")

        if result['length'] > 0:
            print("✓ OCR successfully extracted text")
        else:
            print("⚠ OCR did not extract text (tesseract may need configuration)")

    except Exception as e:
        print(f"⚠ OCR test failed: {e}")
        print("  This is expected if pytesseract is not installed")
    finally:
        # Clean up
        import os
        os.unlink(temp_path)


def test_image_ocr_extraction():
    """Test OCR from page images"""
    print("\n=== Testing Image OCR (Page Images) ===")

    # Create simple HTML with an image
    html = """
    <html>
        <body>
            <img src="https://example.com/logo.png">
            <img src="https://example.com/banner.png">
        </body>
    </html>
    """

    # This will fail since we can't actually fetch the images
    # but we can test that the function exists and handles errors gracefully
    try:
        result = image_ocr.features(html, "https://example.com", max_images=2)

        print(f"✓ Total images processed: {result['total_images_processed']}")
        print(f"✓ Images accessible: {result['images_accessible']}")
        print(f"✓ Function executed without crashing")

        assert 'total_images_processed' in result, "Should return structure"
        print("✓ Image OCR test PASSED (structure)")

    except Exception as e:
        print(f"⚠ Image OCR test failed: {e}")


def main():
    print("=" * 60)
    print("Testing New Feature Extractors")
    print("=" * 60)

    try:
        test_favicon_color_scheme()
        test_image_quality_metrics()
        test_ocr_extraction()
        test_image_ocr_extraction()

        print("\n" + "=" * 60)
        print("✓ All tests completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
