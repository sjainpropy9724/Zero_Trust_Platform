from PIL import Image, ImageDraw, ImageFont
import os
from io import BytesIO
from pdf2image import convert_from_path
import docx

def add_watermark(image: Image.Image, text: str) -> Image.Image:
    # Ensure image is in a mode that supports transparency for proper compositing
    img_rgba = image.convert("RGBA")
    
    txt_layer = Image.new("RGBA", img_rgba.size, (255, 255, 255, 0))
    draw = ImageDraw.Draw(txt_layer)

    # Dynamic font size based on image width
    font_size = int(img_rgba.size[0] / 20)
    try:
        font = ImageFont.truetype("arial.ttf", font_size)
    except IOError:
        font = ImageFont.load_default()

    # Draw watermark diagonally across the grid
    w, h = img_rgba.size
    # Measure text size using getbbox (left, top, right, bottom)
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    # Spacing between watermarks
    step_x = int(text_width * 1.5)
    step_y = int(text_height * 4)

    for x in range(0, w, step_x):
        for y in range(0, h, step_y):
            # Semi-transparent red
            draw.text((x, y), text, fill=(255, 0, 0, 80), font=font)

    watermarked = Image.alpha_composite(img_rgba, txt_layer)
    return watermarked.convert("RGB")

def text_to_image(text: str) -> Image.Image:
    """Helper to render raw text onto a blank white image."""
    # Create a basic white canvas. 
    # In a real app, you'd calculate needed height based on text length.
    img = Image.new('RGB', (850, 1100), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        # Use a standard readable font if available
        font = ImageFont.truetype("arial.ttf", 16)
    except IOError:
        font = ImageFont.load_default()
        
    # Simple text wrapping could be added here for long lines
    draw.text((50, 50), text[:3000], fill=(0, 0, 0), font=font) # Limit to first ~3000 chars for MVP preview
    return img

def create_watermarked_file(filepath: str, watermark_text: str) -> BytesIO:
    file_ext = os.path.splitext(filepath)[1].lower()
    img = None

    try:
        if file_ext in ['.png', '.jpg', '.jpeg']:
            img = Image.open(filepath)

        elif file_ext == '.pdf':
            # Render ONLY the first page for the secure view MVP
            images = convert_from_path(filepath, first_page=1, last_page=1)
            if images:
                img = images[0]

        elif file_ext == '.docx':
            # Extract text and render as image (loses complex formatting, but secure)
            doc = docx.Document(filepath)
            full_text = []
            for para in doc.paragraphs:
                full_text.append(para.text)
            img = text_to_image("\n".join(full_text))

        elif file_ext == '.txt':
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            img = text_to_image(content)

        if img:
            watermarked = add_watermark(img, watermark_text)
            output = BytesIO()
            watermarked.save(output, format='JPEG', quality=85)
            output.seek(0)
            return output

    except Exception as e:
        print(f"Watermarking error: {e}")
        return None

    return None