from typing import Any

import pyotp
import pytest
from django.contrib.auth.models import User
from django.core.files.storage import default_storage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client
from django.urls import reverse

from accounts.services import profile_of
from accounts.views import VERIFIED_AT
from vault.models import StoredFile

pytestmark = pytest.mark.django_db
PASSWORD = 'ACME-test-pass-1111'


def _code(username: str) -> str:
    return pyotp.TOTP(profile_of(User.objects.get(username=username)).totp_secret).now()


def _signed_in(client: Client, username: str = 'alice') -> Client:
    client.post(
        reverse('accounts:register'),
        {'username': username, 'email': f'{username}@example.com', 'password1': PASSWORD, 'password2': PASSWORD},
    )
    client.post(reverse('accounts:totp_setup'), {'code': _code(username)})
    return client


def _upload(client: Client, name: str = 'notes.txt', content: bytes = b'hello cloud ' * 500) -> StoredFile:
    client.post(reverse('vault:upload'), {'file': SimpleUploadedFile(name, content)})
    return StoredFile.objects.latest('created_at')


def test_register_requires_totp_before_dashboard(client: Client) -> None:
    client.post(
        reverse('accounts:register'),
        {'username': 'bob', 'email': 'bob@example.com', 'password1': PASSWORD, 'password2': PASSWORD},
    )
    assert client.get(reverse('vault:dashboard')).status_code == 302
    client.post(reverse('accounts:totp_setup'), {'code': _code('bob')})
    assert client.get(reverse('vault:dashboard')).status_code == 200


def test_login_needs_both_factors(client: Client) -> None:
    _signed_in(client)
    client.post(reverse('accounts:logout'))
    response = client.post(reverse('accounts:login'), {'username': 'alice', 'password': PASSWORD})
    assert response['Location'] == reverse('accounts:totp_verify')
    assert client.get(reverse('vault:dashboard')).status_code == 302
    client.post(reverse('accounts:totp_verify'), {'code': '000000'})
    assert client.get(reverse('vault:dashboard')).status_code == 302
    client.post(reverse('accounts:totp_verify'), {'code': _code('alice')})
    assert client.get(reverse('vault:dashboard')).status_code == 200


def test_upload_and_download_round_trip(client: Client) -> None:
    _signed_in(client)
    content = bytes(range(256)) * 400
    record = _upload(client, 'data.bin', content)
    assert all(default_storage.exists(p) for p in (record.aes_path, record.rc6_path, record.des_path))
    assert content not in default_storage.open(record.aes_path).read()
    response = client.get(reverse('vault:download', args=[record.pk]))
    assert response.status_code == 200
    assert response.content == content


def test_download_requires_fresh_totp(client: Client) -> None:
    _signed_in(client)
    record = _upload(client)
    session = client.session
    session[VERIFIED_AT] = 0
    session.save()
    response = client.get(reverse('vault:download', args=[record.pk]))
    assert response.status_code == 302
    assert response['Location'].startswith(reverse('accounts:totp_verify'))
    response = client.post(
        reverse('accounts:totp_verify'),
        {'code': _code('alice'), 'next': reverse('vault:download', args=[record.pk])},
    )
    assert response['Location'] == reverse('vault:download', args=[record.pk])


def test_tampered_segment_fails_integrity(client: Client) -> None:
    _signed_in(client)
    record = _upload(client)
    original = default_storage.open(record.rc6_path).read()
    default_storage.delete(record.rc6_path)
    default_storage.save(record.rc6_path, SimpleUploadedFile('x', original[:16] + bytes(len(original) - 16)))
    response = client.get(reverse('vault:download', args=[record.pk]), follow=True)
    assert b'failed its integrity check' in response.content


def test_other_users_cannot_download(client: Client) -> None:
    _signed_in(client)
    record = _upload(client)
    other = _signed_in(Client(), 'mallory')
    assert other.get(reverse('vault:download', args=[record.pk])).status_code == 404


def test_lockout_after_repeated_failures(client: Client, settings: Any) -> None:
    _signed_in(client)
    client.post(reverse('accounts:logout'))
    for _ in range(settings.MAX_FAILED_ATTEMPTS):
        client.post(reverse('accounts:login'), {'username': 'alice', 'password': 'wrong'})
    response = client.post(reverse('accounts:login'), {'username': 'alice', 'password': PASSWORD})
    assert b'Account locked' in response.content


def test_totp_setup_respects_lockout(client: Client, settings: Any) -> None:
    client.post(
        reverse('accounts:register'),
        {'username': 'carol', 'email': 'carol@example.com', 'password1': PASSWORD, 'password2': PASSWORD},
    )
    for _ in range(settings.MAX_FAILED_ATTEMPTS):
        client.post(reverse('accounts:totp_setup'), {'code': '000000'})
    response = client.post(reverse('accounts:totp_setup'), {'code': _code('carol')})
    assert b'Account locked' in response.content
    assert client.get(reverse('vault:dashboard')).status_code == 302


@pytest.mark.parametrize('name', ['setup.exe', 'empty.txt'])
def test_rejected_uploads(client: Client, name: str) -> None:
    _signed_in(client)
    content = b'' if name == 'empty.txt' else b'MZ binary'
    client.post(reverse('vault:upload'), {'file': SimpleUploadedFile(name, content)})
    assert not StoredFile.objects.exists()


def test_delete_removes_segments(client: Client) -> None:
    _signed_in(client)
    record = _upload(client)
    paths = (record.aes_path, record.rc6_path, record.des_path)
    client.post(reverse('vault:delete', args=[record.pk]))
    assert not StoredFile.objects.exists()
    assert not any(default_storage.exists(p) for p in paths)
