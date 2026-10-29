"""LSB steganography over the RGB channels of a PNG.

The payload is length-prefixed (4 bytes, big-endian) and written one bit per
channel byte, row by row. PNG is lossless, so the bits survive storage.
"""

import io
import math

from PIL import Image

_HEADER_BYTES = 4


class StegoError(ValueError):
    pass


def capacity(image: Image.Image) -> int:
    return image.width * image.height * 3 // 8 - _HEADER_BYTES


def generate_cover(width: int = 256, height: int = 256) -> bytes:
    gradient = Image.linear_gradient('L').resize((width, height))  # pyright: ignore[reportUnknownMemberType]
    noise = Image.effect_noise((width, height), 48)
    blend = Image.blend(gradient, noise, 0.35)
    image = Image.merge('RGB', (blend, gradient.rotate(90), noise))
    return _to_png(image)


def embed(cover_png: bytes, payload: bytes) -> bytes:
    image = Image.open(io.BytesIO(cover_png)).convert('RGB')
    if len(payload) > capacity(image):
        raise StegoError(f'Payload is {len(payload)} bytes. Cover holds {capacity(image)}. Use a larger cover image.')
    data = len(payload).to_bytes(_HEADER_BYTES, 'big') + payload
    channels = bytearray(image.tobytes())
    for i, byte in enumerate(data):
        for bit in range(8):
            pos = i * 8 + bit
            channels[pos] = (channels[pos] & 0xFE) | ((byte >> (7 - bit)) & 1)
    return _to_png(Image.frombytes('RGB', image.size, bytes(channels)))


def extract(stego_png: bytes) -> bytes:
    image = Image.open(io.BytesIO(stego_png)).convert('RGB')
    channels = image.tobytes()

    def read(start: int, count: int) -> bytes:
        out = bytearray()
        for i in range(start, start + count):
            byte = 0
            for bit in range(8):
                byte = (byte << 1) | (channels[i * 8 + bit] & 1)
            out.append(byte)
        return bytes(out)

    length = int.from_bytes(read(0, _HEADER_BYTES), 'big')
    if length > capacity(image):
        raise StegoError('Image carries no embedded key. The header length exceeds the image capacity.')
    return read(_HEADER_BYTES, length)


def psnr(original_png: bytes, stego_png: bytes) -> float:
    """Peak signal-to-noise ratio in dB, for the image-quality check in report section 3.16.4."""
    a = Image.open(io.BytesIO(original_png)).convert('RGB').tobytes()
    b = Image.open(io.BytesIO(stego_png)).convert('RGB').tobytes()
    mse = sum((x - y) ** 2 for x, y in zip(a, b)) / len(a)
    return math.inf if mse == 0 else 10 * math.log10(255**2 / mse)


def _to_png(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    return buffer.getvalue()
