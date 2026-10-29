"""Key hierarchy from report section 3.10.5.

server key (env)  --AES-GCM-->  user master key  --LSB-->  stego image
user master key   --AES-GCM-->  per-file session keys (AES, DES, RC6)
"""

import secrets
from dataclasses import dataclass

from Crypto.Cipher import AES

from . import aes, des, rc6, stego

MASTER_KEY_SIZE = 32
_NONCE_SIZE = 12
_TAG_SIZE = 16


class KeyMaterialError(ValueError):
    pass


@dataclass(frozen=True)
class SessionKeys:
    aes: bytes
    des: bytes
    rc6: bytes

    @classmethod
    def generate(cls) -> 'SessionKeys':
        return cls(aes=aes.generate_key(), des=des.generate_key(), rc6=rc6.generate_key())

    def to_bytes(self) -> bytes:
        return self.aes + self.des + self.rc6

    @classmethod
    def from_bytes(cls, raw: bytes) -> 'SessionKeys':
        a, d = aes.KEY_SIZE, aes.KEY_SIZE + des.KEY_SIZE
        return cls(aes=raw[:a], des=raw[a:d], rc6=raw[d:])


def generate_master_key() -> bytes:
    return secrets.token_bytes(MASTER_KEY_SIZE)


def _seal(plaintext: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(_NONCE_SIZE)
    ciphertext, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag


def _open(blob: bytes, key: bytes) -> bytes:
    nonce, ciphertext, tag = blob[:_NONCE_SIZE], blob[_NONCE_SIZE:-_TAG_SIZE], blob[-_TAG_SIZE:]
    try:
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise KeyMaterialError(
            'Key material failed authentication. The key or carrier image was altered or is wrong.'
        ) from exc


def hide_master_key(master_key: bytes, server_key: bytes, cover_png: bytes) -> bytes:
    return stego.embed(cover_png, _seal(master_key, server_key))


def recover_master_key(stego_png: bytes, server_key: bytes) -> bytes:
    return _open(stego.extract(stego_png), server_key)


def wrap_session_keys(keys: SessionKeys, master_key: bytes) -> bytes:
    return _seal(keys.to_bytes(), master_key)


def unwrap_session_keys(blob: bytes, master_key: bytes) -> SessionKeys:
    return SessionKeys.from_bytes(_open(blob, master_key))
