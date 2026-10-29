"""Generates the evaluation data for report section 3.16 as CSV files.

Avalanche is measured per block (fixed key, one plaintext bit flipped), since
CBC with a random IV changes every ciphertext bit by design and would hide the
cipher's own diffusion.
"""

import csv
import io
import json
import random
import secrets
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from Crypto.Cipher import AES, DES
from django.core.management.base import BaseCommand
from PIL import Image

from crypto import aes, des, hybrid, keys, rc6, stego

SIZES_MB = (0.5, 1, 2, 5, 10)
CIPHERS: dict[str, Any] = {'AES-256': aes, 'DES': des, 'RC6': rc6}


def _ms(fn: Callable[..., Any], *args: Any) -> tuple[float, Any]:
    started = time.perf_counter()
    result = fn(*args)
    return (time.perf_counter() - started) * 1000, result


def _bits_changed(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def _flip_bit(data: bytes, bit: int) -> bytes:
    out = bytearray(data)
    out[bit // 8] ^= 1 << (bit % 8)
    return bytes(out)


def _block_encryptors() -> dict[str, tuple[int, int, Callable[[bytes, bytes], bytes]]]:
    return {
        'AES-256': (32, 16, lambda k, b: AES.new(k, AES.MODE_ECB).encrypt(b)),
        'DES': (8, 8, lambda k, b: DES.new(k, DES.MODE_ECB).encrypt(b)),
        'RC6': (16, 16, lambda k, b: rc6.encrypt_block(rc6.key_schedule(k), b)),
    }


def _sample_files() -> dict[str, bytes]:
    image = Image.effect_noise((400, 300), 64).convert('RGB')
    png, jpg = io.BytesIO(), io.BytesIO()
    image.save(png, format='PNG')
    image.save(jpg, format='JPEG')
    text = ('Hybrid secure cloud storage test document. ' * 2000).encode()
    rows = '\n'.join(f'{i},ACME-{i:04d},{i * 7 % 1000}' for i in range(20000)).encode()
    return {
        'document.txt': text,
        'records.csv': rows,
        'config.json': json.dumps({'items': list(range(5000))}).encode(),
        'photo.png': png.getvalue(),
        'photo.jpg': jpg.getvalue(),
        'archive.bin': secrets.token_bytes(3 * 1024 * 1024),
        'tiny.txt': b'a',
    }


class Command(BaseCommand):
    help = 'Measure integrity, timing, avalanche effect and key recovery. Writes CSVs for Chapter 4.'

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument('--out', default='benchmark', help='Output directory.')
        parser.add_argument('--trials', type=int, default=100, help='Trials for avalanche and key recovery.')

    def handle(self, *args: Any, **options: Any) -> None:
        out = Path(options['out'])
        out.mkdir(parents=True, exist_ok=True)
        trials: int = options['trials']
        self._integrity(out)
        self._timing(out)
        self._avalanche(out, trials)
        self._key_recovery(out, trials)
        self.stdout.write(self.style.SUCCESS(f'Wrote CSVs to {out.resolve()}'))

    def _write(self, path: Path, header: list[str], rows: list[list[object]]) -> None:
        with path.open('w', newline='') as handle:
            writer = csv.writer(handle)
            writer.writerow(header)
            writer.writerows(rows)
        self.stdout.write(f'\n{path.name}')
        for row in [header, *rows]:
            self.stdout.write('  ' + ' | '.join(str(c) for c in row))

    def _integrity(self, out: Path) -> None:
        rows: list[list[object]] = []
        for name, data in _sample_files().items():
            session = keys.SessionKeys.generate()
            before = hybrid.checksum(data)
            after = hybrid.checksum(hybrid.decrypt_file(hybrid.encrypt_file(data, session), session))
            rows.append([name, len(data), before[:16], after[:16], 'PASS' if before == after else 'FAIL'])
        self._write(out / 'integrity.csv', ['file', 'bytes', 'sha256_before', 'sha256_after', 'result'], rows)

    def _timing(self, out: Path) -> None:
        rows: list[list[object]] = []
        for size_mb in SIZES_MB:
            data = secrets.token_bytes(int(size_mb * 1024 * 1024))
            for name, cipher in CIPHERS.items():
                key = cipher.generate_key()
                enc_ms, blob = _ms(cipher.encrypt, data, key)
                dec_ms, _ = _ms(cipher.decrypt, blob, key)
                rows.append([size_mb, name, round(enc_ms, 2), round(dec_ms, 2), round(size_mb / (enc_ms / 1000), 2)])
            session = keys.SessionKeys.generate()
            enc_ms, encrypted = _ms(hybrid.encrypt_file, data, session)
            dec_ms, _ = _ms(hybrid.decrypt_file, encrypted, session)
            rows.append([size_mb, 'Hybrid', round(enc_ms, 2), round(dec_ms, 2), round(size_mb / (enc_ms / 1000), 2)])
        self._write(out / 'timing.csv', ['size_mb', 'algorithm', 'encrypt_ms', 'decrypt_ms', 'encrypt_mb_per_s'], rows)

        server_key, cover = secrets.token_bytes(32), stego.generate_cover()
        embed_times, extract_times = list[float](), list[float]()
        for _ in range(20):
            embed_ms, carrier = _ms(keys.hide_master_key, keys.generate_master_key(), server_key, cover)
            extract_ms, _ = _ms(keys.recover_master_key, carrier, server_key)
            embed_times.append(embed_ms)
            extract_times.append(extract_ms)
        self._write(
            out / 'stego_timing.csv',
            ['step', 'mean_ms', 'min_ms', 'max_ms'],
            [
                [
                    'embed',
                    round(statistics.mean(embed_times), 2),
                    round(min(embed_times), 2),
                    round(max(embed_times), 2),
                ],
                [
                    'extract',
                    round(statistics.mean(extract_times), 2),
                    round(min(extract_times), 2),
                    round(max(extract_times), 2),
                ],
            ],
        )

    def _avalanche(self, out: Path, trials: int) -> None:
        rows: list[list[object]] = []
        for name, (key_size, block_size, encrypt) in _block_encryptors().items():
            ratios: list[float] = []
            for _ in range(trials):
                key, block = secrets.token_bytes(key_size), secrets.token_bytes(block_size)
                flipped = _flip_bit(block, random.randrange(block_size * 8))
                ratios.append(_bits_changed(encrypt(key, block), encrypt(key, flipped)) / (block_size * 8) * 100)
            rows.append(
                [
                    name,
                    block_size * 8,
                    trials,
                    round(statistics.mean(ratios), 2),
                    round(min(ratios), 2),
                    round(max(ratios), 2),
                ]
            )
        header = ['algorithm', 'block_bits', 'trials', 'mean_changed_pct', 'min_changed_pct', 'max_changed_pct']
        self._write(out / 'avalanche.csv', header, rows)

    def _key_recovery(self, out: Path, trials: int) -> None:
        server_key, successes, psnrs = secrets.token_bytes(32), 0, list[float]()
        for _ in range(trials):
            master, session, cover = keys.generate_master_key(), keys.SessionKeys.generate(), stego.generate_cover()
            carrier = keys.hide_master_key(master, server_key, cover)
            recovered = keys.recover_master_key(carrier, server_key)
            unwrapped = keys.unwrap_session_keys(keys.wrap_session_keys(session, master), recovered)
            successes += recovered == master and unwrapped == session
            psnrs.append(stego.psnr(cover, carrier))
        self._write(
            out / 'key_recovery.csv',
            ['trials', 'successful', 'success_rate_pct', 'mean_psnr_db', 'min_psnr_db'],
            [
                [
                    trials,
                    successes,
                    round(successes / trials * 100, 2),
                    round(statistics.mean(psnrs), 2),
                    round(min(psnrs), 2),
                ]
            ],
        )
