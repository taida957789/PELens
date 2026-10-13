"""Generate the PELens icon (assets/pelens.png + assets/pelens.ico).

Design: a dark rounded tile holding rows of "hex byte" bars (a PE file seen as data),
under a rust-orange magnifying glass whose lens magnifies the "MZ" signature.
Rendered at 1024 px and down-sampled for crisp small sizes.
"""
from PIL import Image, ImageDraw, ImageFilter, ImageFont
import os

S = 1024
OUT = os.path.join(os.path.dirname(__file__), '..', 'assets')
os.makedirs(OUT, exist_ok=True)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def tile():
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    # background: vertical gradient inside a rounded square
    grad = Image.new('RGBA', (S, S))
    gd = ImageDraw.Draw(grad)
    for y in range(S):
        gd.line([(0, y), (S, y)], fill=lerp((44, 47, 56, 255), (22, 23, 27, 255), y / S))
    mask = Image.new('L', (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40], radius=190, fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([40, 40, S - 40, S - 40], radius=190, outline=(70, 74, 86, 255), width=10)
    # hex rows: small rounded bars, a few highlighted
    x0, y0, bw, bh, gap = 150, 170, 92, 46, 26
    rng = [3, 7, 1, 5, 2, 6, 4, 0, 5, 3]
    for row in range(8):
        for col in range(6):
            x = x0 + col * (bw + gap)
            y = y0 + row * (bh + 46)
            if x + bw > S - 120:
                continue
            hot = (row * 6 + col) % 7 == rng[row % len(rng)] % 7
            colr = (96, 180, 170, 255) if hot else (78, 84, 98, 255)
            d.rounded_rectangle([x, y, x + bw, y + bh], radius=16, fill=colr)
    return img


def magnifier(img):
    d = ImageDraw.Draw(img)
    cx, cy, r = 430, 430, 255
    # shadow
    sh = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    sd = ImageDraw.Draw(sh)
    sd.ellipse([cx - r + 18, cy - r + 30, cx + r + 18, cy + r + 30], fill=(0, 0, 0, 150))
    sd.line([(cx + 190 + 18, cy + 190 + 30), (S - 150 + 18, S - 150 + 30)], fill=(0, 0, 0, 150), width=120)
    sh = sh.filter(ImageFilter.GaussianBlur(28))
    img.alpha_composite(sh)
    d = ImageDraw.Draw(img)
    # handle (rust gradient approximated by two strokes)
    d.line([(cx + 175, cy + 175), (S - 160, S - 160)], fill=(150, 62, 28, 255), width=118)
    d.line([(cx + 175, cy + 175), (S - 165, S - 165)], fill=(222, 104, 50, 255), width=84)
    d.ellipse([S - 230, S - 230, S - 100, S - 100], fill=(222, 104, 50, 255))
    # lens glass
    lens = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    ld = ImageDraw.Draw(lens)
    ld.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(236, 240, 243, 255))
    img.alpha_composite(lens)
    d = ImageDraw.Draw(img)
    # magnified "MZ"
    font = None
    for f in ['C:/Windows/Fonts/consolab.ttf', 'C:/Windows/Fonts/consola.ttf', 'C:/Windows/Fonts/arialbd.ttf']:
        if os.path.exists(f):
            font = ImageFont.truetype(f, 250)
            break
    font = font or ImageFont.load_default()
    d.text((cx, cy + 10), 'MZ', font=font, fill=(36, 39, 46, 255), anchor='mm')
    # little scan line under the letters
    d.rounded_rectangle([cx - 150, cy + 130, cx + 150, cy + 156], radius=13, fill=(96, 180, 170, 255))
    # glass highlight
    hl = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    hd = ImageDraw.Draw(hl)
    hd.arc([cx - r + 40, cy - r + 40, cx + r - 40, cy + r - 40], start=200, end=260, fill=(255, 255, 255, 170), width=26)
    img.alpha_composite(hl)
    d = ImageDraw.Draw(img)
    # rust ring
    d.ellipse([cx - r - 34, cy - r - 34, cx + r + 34, cy + r + 34], outline=(150, 62, 28, 255), width=78)
    d.ellipse([cx - r - 26, cy - r - 26, cx + r + 26, cy + r + 26], outline=(232, 116, 58, 255), width=56)
    d.arc([cx - r - 22, cy - r - 22, cx + r + 22, cy + r + 22], start=190, end=280, fill=(250, 170, 110, 255), width=18)
    return img


def simple(size):
    """Simplified glyph for very small sizes (16/24 px): ring + handle on the tile."""
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([20, 20, S - 20, S - 20], radius=200, fill=(34, 36, 42, 255))
    cx = cy = 420
    r = 260
    d.line([(cx + 170, cy + 170), (S - 140, S - 140)], fill=(232, 116, 58, 255), width=170)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(236, 240, 243, 255), outline=(232, 116, 58, 255), width=130)
    return img.resize((size, size), Image.LANCZOS)


full = magnifier(tile())
full.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, 'pelens.png'))
full.resize((512, 512), Image.LANCZOS).save(os.path.join(OUT, 'pelens-512.png'))
sizes = [256, 128, 64, 48, 32, 24, 16]
frames = [full.resize((s, s), Image.LANCZOS) if s >= 32 else simple(s) for s in sizes]
frames[0].save(os.path.join(OUT, 'pelens.ico'), format='ICO', sizes=[(s, s) for s in sizes], append_images=frames[1:])
print('written', os.path.abspath(OUT))
