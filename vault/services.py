import mimetypes
import time
import uuid
from pathlib import PurePath

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import UploadedFile
from django.db import transaction

from accounts.services import master_key_for
from crypto import hybrid, keys

from .models import StoredFile

BLOCKED_EXTENSIONS = {'.exe', '.bat', '.cmd', '.com', '.msi', '.scr', '.ps1', '.vbs', '.jar', '.sh', '.dll'}


def validate_upload(upload: UploadedFile) -> None:
    name = PurePath(upload.name or '').name
    if not name:
        raise ValidationError('File has no name. Rename it and upload again.')
    if upload.size == 0:
        raise ValidationError('File is empty. Choose a file with content.')
    if upload.size > settings.MAX_UPLOAD_SIZE:
        limit = settings.MAX_UPLOAD_SIZE // (1024 * 1024)
        raise ValidationError(f'File is over {limit} MB. Upload a smaller file.')
    if PurePath(name).suffix.lower() in BLOCKED_EXTENSIONS:
        raise ValidationError('Executable files are not accepted. Upload a document, image or archive.')


def _read_segment(path: str) -> bytes:
    with default_storage.open(path, 'rb') as handle:
        return handle.read()


@transaction.atomic
def store_file(owner: User, upload: UploadedFile) -> StoredFile:
    validate_upload(upload)
    data = upload.read()
    name = PurePath(upload.name or 'file').name

    started = time.perf_counter()
    session = keys.SessionKeys.generate()
    encrypted = hybrid.encrypt_file(data, session)
    wrapped = keys.wrap_session_keys(session, master_key_for(owner))
    encrypt_ms = (time.perf_counter() - started) * 1000

    prefix = f'segments/{owner.pk}/{uuid.uuid4()}'
    paths = {
        part: default_storage.save(f'{prefix}/{part}.bin', ContentFile(getattr(encrypted, f'{part}_segment')))
        for part in ('aes', 'rc6', 'des')
    }
    return StoredFile.objects.create(
        owner=owner,
        name=name,
        content_type=upload.content_type or mimetypes.guess_type(name)[0] or 'application/octet-stream',
        size=len(data),
        checksum=encrypted.checksum,
        wrapped_keys=wrapped,
        aes_path=paths['aes'],
        rc6_path=paths['rc6'],
        des_path=paths['des'],
        encrypt_ms=encrypt_ms,
    )


def load_file(record: StoredFile) -> bytes:
    """Reverse of store_file. Raises hybrid.IntegrityError if the checksum no longer matches."""
    session = keys.unwrap_session_keys(bytes(record.wrapped_keys), master_key_for(record.owner))
    encrypted = hybrid.EncryptedFile(
        aes_segment=_read_segment(record.aes_path),
        rc6_segment=_read_segment(record.rc6_path),
        des_segment=_read_segment(record.des_path),
        checksum=record.checksum,
    )
    return hybrid.decrypt_file(encrypted, session)


def delete_file(record: StoredFile) -> None:
    for path in (record.aes_path, record.rc6_path, record.des_path):
        default_storage.delete(path)
    record.delete()
