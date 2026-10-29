import secrets
from types import ModuleType

import pytest

from crypto import aes, des, hybrid, keys, rc6, stego


@pytest.mark.parametrize(
    ('key', 'plaintext', 'ciphertext'),
    [
        ('00' * 16, '00' * 16, '8fc3a53656b1f778c129df4e9848a41e'),
        ('0123456789abcdef0112233445566778', '02132435465768798a9bacbdcedfe0f1', '524e192f4715c6231f51f6367ea43f18'),
    ],
)
def test_rc6_reference_vectors(key: str, plaintext: str, ciphertext: str) -> None:
    schedule = rc6.key_schedule(bytes.fromhex(key))
    assert rc6.encrypt_block(schedule, bytes.fromhex(plaintext)).hex() == ciphertext
    assert rc6.decrypt_block(schedule, bytes.fromhex(ciphertext)).hex() == plaintext


@pytest.mark.parametrize('cipher', [aes, des, rc6])
@pytest.mark.parametrize('size', [0, 1, 15, 16, 17, 1000])
def test_cipher_round_trip(cipher: ModuleType, size: int) -> None:
    key = cipher.generate_key()
    data = secrets.token_bytes(size)
    blob = cipher.encrypt(data, key)
    assert blob[cipher.BLOCK_SIZE :] != data
    assert cipher.decrypt(blob, key) == data


@pytest.mark.parametrize('size', [0, 1, 7, 100, 4096, 100_003])
def test_hybrid_round_trip(size: int) -> None:
    data = secrets.token_bytes(size)
    session = keys.SessionKeys.generate()
    encrypted = hybrid.encrypt_file(data, session)
    assert hybrid.decrypt_file(encrypted, session) == data


def test_hybrid_split_shares() -> None:
    a, r, d = hybrid.split(bytes(1000))
    assert (len(a), len(r), len(d)) == (600, 250, 150)


def test_hybrid_detects_tampering() -> None:
    session = keys.SessionKeys.generate()
    encrypted = hybrid.encrypt_file(secrets.token_bytes(5000), session)
    flipped = bytearray(encrypted.aes_segment)
    flipped[-20] ^= 0x01
    tampered = hybrid.EncryptedFile(bytes(flipped), encrypted.rc6_segment, encrypted.des_segment, encrypted.checksum)
    with pytest.raises(ValueError):
        hybrid.decrypt_file(tampered, session)


def test_master_key_survives_stego_round_trip() -> None:
    server_key, master = secrets.token_bytes(32), keys.generate_master_key()
    cover = stego.generate_cover()
    carrier = keys.hide_master_key(master, server_key, cover)
    assert keys.recover_master_key(carrier, server_key) == master
    assert stego.psnr(cover, carrier) > 50


def test_wrong_server_key_is_rejected() -> None:
    carrier = keys.hide_master_key(keys.generate_master_key(), secrets.token_bytes(32), stego.generate_cover())
    with pytest.raises(keys.KeyMaterialError):
        keys.recover_master_key(carrier, secrets.token_bytes(32))


def test_session_keys_wrap_round_trip() -> None:
    master, session = keys.generate_master_key(), keys.SessionKeys.generate()
    assert keys.unwrap_session_keys(keys.wrap_session_keys(session, master), master) == session


def test_stego_rejects_oversized_payload() -> None:
    with pytest.raises(stego.StegoError):
        stego.embed(stego.generate_cover(8, 8), bytes(100))
