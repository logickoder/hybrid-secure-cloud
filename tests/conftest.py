from pathlib import Path
from typing import Any

import pytest


@pytest.fixture(autouse=True)
def isolated_storage(settings: Any, tmp_path: Path) -> None:
    settings.STORAGES = {
        **settings.STORAGES,
        'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage', 'OPTIONS': {'location': tmp_path}},
        'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
    }
