"""
Pure Python PNG Icon Generator for DualShield Extension.
Uses only standard library (zlib, struct).
"""

import zlib
import struct
import os

def create_png(width, height, filename):
    # PNG signature
    signature = b'\x89PNG\r\n\x1a\n'

    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    ihdr_crc = zlib.crc32(b'IHDR' + ihdr_data)
    ihdr_chunk = struct.pack('>I', len(ihdr_data)) + b'IHDR' + ihdr_data + struct.pack('>I', ihdr_crc)

    # Pixel data (RGBA)
    # Draw a stylish rounded emerald/cyan shield
    raw_lines = []
    center_x = width / 2.0
    center_y = height / 2.0
    radius = width * 0.45

    for y in range(height):
        line = [0] # Filter byte 0 (None)
        for x in range(width):
            dx = (x - center_x) / radius
            dy = (y - center_y) / radius
            dist_sq = dx*dx + dy*dy

            if dist_sq <= 1.0:
                # Inside shield circle / shield shape
                # Gradient from emerald (16, 185, 129) to cyan (6, 182, 212)
                t = (x + y) / (width + height * 1.0)
                r = int(16 + t * (6 - 16))
                g = int(185 + t * (182 - 185))
                b = int(129 + t * (212 - 129))
                a = 255
                # Simple shield border highlight
                if dist_sq > 0.85:
                    r, g, b = 255, 255, 255
            else:
                r, g, b, a = 0, 0, 0, 0 # Transparent

            line.extend([r, g, b, a])
        raw_lines.append(bytes(line))

    compressed_data = zlib.compress(b''.join(raw_lines))
    idat_crc = zlib.crc32(b'IDAT' + compressed_data)
    idat_chunk = struct.pack('>I', len(compressed_data)) + b'IDAT' + compressed_data + struct.pack('>I', idat_crc)

    # IEND chunk
    iend_crc = zlib.crc32(b'IEND')
    iend_chunk = struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)

    with open(filename, 'wb') as f:
        f.write(signature + ihdr_chunk + idat_chunk + iend_chunk)

    print(f"Created icon: {filename}")

def main():
    icons_dir = os.path.join(os.path.dirname(__file__), "extension", "icons")
    os.makedirs(icons_dir, exist_ok=True)
    create_png(16, 16, os.path.join(icons_dir, "icon16.png"))
    create_png(48, 48, os.path.join(icons_dir, "icon48.png"))
    create_png(128, 128, os.path.join(icons_dir, "icon128.png"))

if __name__ == "__main__":
    main()
