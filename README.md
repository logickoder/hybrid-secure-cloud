# Hybrid Secure Cloud Storage

Hybrid Secure Cloud Storage using Multi-Algorithm Encryption and Embedded AES Key Protection.

A Django web app that encrypts each uploaded file before it reaches cloud storage:

- The file is split by fixed rule: 60% AES-256, 25% RC6, 15% DES. The DES segment also carries the reassembly metadata.
- Each segment gets its own random session key. The three keys are wrapped with the user's master key (AES-256-GCM).
- The user's master key is sealed with the server key (AES-256-GCM) and hidden in a carrier PNG by LSB steganography. The carrier lives in the database, apart from the segments in cloud storage.
- Login takes a password plus a TOTP code from an authenticator app. Every decryption needs a TOTP code from the last 5 minutes.
- Five failed attempts on either factor lock the account for 15 minutes. Every attempt is logged.
- Downloads are checked against the SHA-256 checksum taken before encryption.

## Layout

| Path | Purpose |
|---|---|
| `crypto/aes.py`, `des.py`, `rc6.py` | Ciphers, CBC mode, PKCS7 padding. RC6 is implemented here and checked against the reference test vectors. |
| `crypto/hybrid.py` | File splitting, metadata, checksum verification. |
| `crypto/keys.py` | Session keys, master key, key wrapping. |
| `crypto/stego.py` | LSB embed and extract, carrier generation, PSNR. |
| `accounts/` | Registration, login, TOTP setup and verification, lockout. |
| `vault/` | Upload, list, download, delete. `benchmark` management command. |

## Run locally

```sh
uv sync
cp .env.example .env   # fill SECRET_KEY and MASTER_KEY
uv run python manage.py migrate
uv run python manage.py runserver
```

Without `DATABASE_URL` it uses SQLite. Without `R2_BUCKET` it stores segments in `./media`.

## Checks

```sh
uv run ruff check . && uv run ruff format --check . && uv run pyright && uv run pytest
```

## Evaluation data (report section 3.16)

```sh
uv run python manage.py benchmark --trials 100
```

Writes `benchmark/integrity.csv`, `timing.csv`, `stego_timing.csv`, `avalanche.csv` and `key_recovery.csv`.

## Deploy (Render + Neon + Cloudflare R2)

1. Neon: create a project, copy the pooled connection string into `DATABASE_URL`.
2. Cloudflare R2: create a bucket and an API token with object read and write. Set `R2_BUCKET`, `R2_ENDPOINT_URL` (`https://<account-id>.r2.cloudflarestorage.com`), `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`.
3. Render: new Web Service from this repo.
   - Build command: `./build.sh`
   - Start command: `uv run gunicorn config.wsgi --timeout 120`
   - Env: everything in `.env.example`, with `DEBUG=False` and `ALLOWED_HOSTS=<service>.onrender.com`.

Never change `MASTER_KEY` after users exist. Every stored file becomes unrecoverable.
