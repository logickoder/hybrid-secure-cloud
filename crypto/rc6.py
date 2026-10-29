"""RC6-32/20/b block cipher (128-bit blocks, 20 rounds) in CBC mode with PKCS7 padding.

No maintained Python library ships RC6, so the primitive lives here and is
checked against the reference test vectors from the RC6 submission in tests.
"""

import secrets

from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16
KEY_SIZE = 16
ROUNDS = 20
_MASK = 0xFFFFFFFF
_P32 = 0xB7E15163
_Q32 = 0x9E3779B9


def _rol(x: int, n: int) -> int:
    n &= 31
    return ((x << n) | (x >> (32 - n))) & _MASK


def _ror(x: int, n: int) -> int:
    n &= 31
    return ((x >> n) | (x << (32 - n))) & _MASK


def key_schedule(key: bytes) -> list[int]:
    c = max(1, (len(key) + 3) // 4)
    l = [int.from_bytes(key[i : i + 4].ljust(4, b'\0'), 'little') for i in range(0, c * 4, 4)]
    t = 2 * ROUNDS + 4
    s = [(_P32 + i * _Q32) & _MASK for i in range(t)]
    a = b = i = j = 0
    for _ in range(3 * max(t, c)):
        a = s[i] = _rol((s[i] + a + b) & _MASK, 3)
        b = l[j] = _rol((l[j] + a + b) & _MASK, a + b)
        i = (i + 1) % t
        j = (j + 1) % c
    return s


def encrypt_block(s: list[int], block: bytes) -> bytes:
    a, b, c, d = (int.from_bytes(block[i : i + 4], 'little') for i in range(0, 16, 4))
    b = (b + s[0]) & _MASK
    d = (d + s[1]) & _MASK
    for r in range(1, ROUNDS + 1):
        t = _rol((b * (2 * b + 1)) & _MASK, 5)
        u = _rol((d * (2 * d + 1)) & _MASK, 5)
        a = (_rol(a ^ t, u) + s[2 * r]) & _MASK
        c = (_rol(c ^ u, t) + s[2 * r + 1]) & _MASK
        a, b, c, d = b, c, d, a
    a = (a + s[2 * ROUNDS + 2]) & _MASK
    c = (c + s[2 * ROUNDS + 3]) & _MASK
    return b''.join(x.to_bytes(4, 'little') for x in (a, b, c, d))


def decrypt_block(s: list[int], block: bytes) -> bytes:
    a, b, c, d = (int.from_bytes(block[i : i + 4], 'little') for i in range(0, 16, 4))
    c = (c - s[2 * ROUNDS + 3]) & _MASK
    a = (a - s[2 * ROUNDS + 2]) & _MASK
    for r in range(ROUNDS, 0, -1):
        a, b, c, d = d, a, b, c
        u = _rol((d * (2 * d + 1)) & _MASK, 5)
        t = _rol((b * (2 * b + 1)) & _MASK, 5)
        c = _ror((c - s[2 * r + 1]) & _MASK, t) ^ u
        a = _ror((a - s[2 * r]) & _MASK, u) ^ t
    d = (d - s[1]) & _MASK
    b = (b - s[0]) & _MASK
    return b''.join(x.to_bytes(4, 'little') for x in (a, b, c, d))


def generate_key() -> bytes:
    return secrets.token_bytes(KEY_SIZE)


def encrypt(data: bytes, key: bytes) -> bytes:
    s = key_schedule(key)
    iv = secrets.token_bytes(BLOCK_SIZE)
    prev, out = iv, [iv]
    padded = pad(data, BLOCK_SIZE)
    for i in range(0, len(padded), BLOCK_SIZE):
        prev = encrypt_block(s, bytes(a ^ b for a, b in zip(padded[i : i + BLOCK_SIZE], prev)))
        out.append(prev)
    return b''.join(out)


def decrypt(blob: bytes, key: bytes) -> bytes:
    s = key_schedule(key)
    prev, out = blob[:BLOCK_SIZE], list[bytes]()
    for i in range(BLOCK_SIZE, len(blob), BLOCK_SIZE):
        block = blob[i : i + BLOCK_SIZE]
        out.append(bytes(a ^ b for a, b in zip(decrypt_block(s, block), prev)))
        prev = block
    return unpad(b''.join(out), BLOCK_SIZE)
