"""Hybrid scheme from report sections 3.7 to 3.10.

The file is split by fixed rule: the first 60% goes to AES, the next 25% to
RC6, the last 15% to DES. The DES payload also carries the metadata needed to
reassemble the file (segment sizes, algorithm order, SHA-256 checksum).
"""

import hashlib
import json
from dataclasses import dataclass

from . import aes, des, rc6
from .keys import SessionKeys

AES_SHARE = 0.60
RC6_SHARE = 0.25
_META_LEN_BYTES = 4


class IntegrityError(ValueError):
    pass


@dataclass(frozen=True)
class EncryptedFile:
    aes_segment: bytes
    rc6_segment: bytes
    des_segment: bytes
    checksum: str


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def split(data: bytes) -> tuple[bytes, bytes, bytes]:
    a = int(len(data) * AES_SHARE)
    r = a + int(len(data) * RC6_SHARE)
    return data[:a], data[a:r], data[r:]


def encrypt_file(data: bytes, keys: SessionKeys) -> EncryptedFile:
    aes_part, rc6_part, des_part = split(data)
    digest = checksum(data)
    metadata = json.dumps(
        {
            'version': 1,
            'order': ['aes', 'rc6', 'des'],
            'sizes': {'aes': len(aes_part), 'rc6': len(rc6_part), 'des': len(des_part)},
            'block_sizes': {'aes': aes.BLOCK_SIZE, 'rc6': rc6.BLOCK_SIZE, 'des': des.BLOCK_SIZE},
            'padding': 'PKCS7',
            'sha256': digest,
        }
    ).encode()
    des_payload = len(metadata).to_bytes(_META_LEN_BYTES, 'big') + metadata + des_part
    return EncryptedFile(
        aes_segment=aes.encrypt(aes_part, keys.aes),
        rc6_segment=rc6.encrypt(rc6_part, keys.rc6),
        des_segment=des.encrypt(des_payload, keys.des),
        checksum=digest,
    )


def decrypt_file(encrypted: EncryptedFile, keys: SessionKeys) -> bytes:
    des_payload = des.decrypt(encrypted.des_segment, keys.des)
    meta_len = int.from_bytes(des_payload[:_META_LEN_BYTES], 'big')
    metadata = json.loads(des_payload[_META_LEN_BYTES : _META_LEN_BYTES + meta_len])
    des_part = des_payload[_META_LEN_BYTES + meta_len :]

    aes_part = aes.decrypt(encrypted.aes_segment, keys.aes)
    rc6_part = rc6.decrypt(encrypted.rc6_segment, keys.rc6)
    sizes = metadata['sizes']
    if (len(aes_part), len(rc6_part), len(des_part)) != (sizes['aes'], sizes['rc6'], sizes['des']):
        raise IntegrityError('Segment sizes do not match the stored metadata. A segment is missing or corrupted.')

    data = aes_part + rc6_part + des_part
    actual = checksum(data)
    if actual != metadata['sha256'] or actual != encrypted.checksum:
        raise IntegrityError('Checksum mismatch after decryption. The file was altered in storage.')
    return data
