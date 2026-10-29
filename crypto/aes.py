"""AES-256 in CBC mode with PKCS7 padding. Output is IV || ciphertext."""

import secrets

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = AES.block_size
KEY_SIZE = 32


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_SIZE)


def encrypt(data: bytes, key: bytes) -> bytes:
    iv = secrets.token_bytes(BLOCK_SIZE)
    return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, BLOCK_SIZE))


def decrypt(blob: bytes, key: bytes) -> bytes:
    iv, ciphertext = blob[:BLOCK_SIZE], blob[BLOCK_SIZE:]
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext), BLOCK_SIZE)
