from datetime import timedelta

import pyotp
import qrcode
import qrcode.image.svg
from django.conf import settings
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import User
from django.db import transaction
from django.http import HttpRequest
from django.utils import timezone

from crypto import keys, stego

from .models import AuthAttempt, Profile

ISSUER = 'Hybrid Secure Cloud Storage'


@transaction.atomic
def create_account(username: str, email: str, password: str) -> User:
    user = User.objects.create_user(username=username, email=email, password=password)
    cover = stego.generate_cover()
    Profile.objects.create(
        user=user,
        totp_secret=pyotp.random_base32(),
        key_image=keys.hide_master_key(keys.generate_master_key(), settings.SERVER_KEY, cover),
    )
    return user


def profile_of(user: AbstractBaseUser) -> Profile:
    return Profile.objects.get(user=user)


def master_key_for(user: User) -> bytes:
    return keys.recover_master_key(bytes(profile_of(user).key_image), settings.SERVER_KEY)


def client_ip(request: HttpRequest) -> str | None:
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    return forwarded.split(',')[0].strip() if forwarded else request.META.get('REMOTE_ADDR')


def record_attempt(request: HttpRequest, username: str, factor: str, success: bool) -> None:
    AuthAttempt.objects.create(username=username, factor=factor, success=success, ip_address=client_ip(request))


def is_locked(username: str) -> bool:
    """Locked after MAX_FAILED_ATTEMPTS failures, on either factor, inside the lockout window."""
    since = timezone.now() - timedelta(seconds=settings.LOCKOUT_SECONDS)
    recent = AuthAttempt.objects.filter(username=username, created_at__gte=since)
    last_success = recent.filter(success=True).first()
    failures = recent.filter(success=False)
    if last_success:
        failures = failures.filter(created_at__gt=last_success.created_at)
    return failures.count() >= settings.MAX_FAILED_ATTEMPTS


def verify_totp(profile: Profile, code: str) -> bool:
    return pyotp.TOTP(profile.totp_secret).verify(code.strip().replace(' ', ''), valid_window=1)


def totp_qr_svg(profile: Profile) -> str:
    uri: str = pyotp.TOTP(profile.totp_secret).provisioning_uri(  # pyright: ignore[reportUnknownMemberType]
        name=profile.user.username, issuer_name=ISSUER
    )
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8)
    return image.to_string(encoding='unicode')
