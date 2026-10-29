#!/usr/bin/env bash
set -o errexit
pip install uv
uv sync --frozen --no-dev
uv run --no-sync python manage.py collectstatic --no-input
uv run --no-sync python manage.py migrate
