"""DES in CBC mode with PKCS7 padding. Output is IV || ciphertext.

DES is weak on its own (56-bit key). It only carries the smallest segment plus
metadata, per the report's design (section 3.10.3).
"""

import secrets

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = DES.block_size
KEY_SIZE = 8


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_SIZE)


def encrypt(data: bytes, key: bytes) -> bytes:
    iv = secrets.token_bytes(BLOCK_SIZE)
    return iv + DES.new(key, DES.MODE_CBC, iv).encrypt(pad(data, BLOCK_SIZE))


def decrypt(blob: bytes, key: bytes) -> bytes:
    iv, ciphertext = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
    return unpad(DES.new(key, DES.MODE_CBC, iv).decrypt(ciphertext), BLOCK_SIZE)
