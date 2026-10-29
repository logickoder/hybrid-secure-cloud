from django.conf import settings
from django.db import models


class Profile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='profile')
    totp_secret = models.CharField(max_length=32)
    totp_confirmed = models.BooleanField(default=False)
    # Carrier PNG holding the user's sealed master key. Kept in the database, apart from
    # the encrypted segments in cloud storage (report section 3.14).
    key_image = models.BinaryField()

    def __str__(self) -> str:
        return f'Profile({self.user})'


class AuthAttempt(models.Model):
    class Factor(models.TextChoices):
        PASSWORD = 'password'
        TOTP = 'totp'

    username = models.CharField(max_length=150, db_index=True)
    factor = models.CharField(max_length=10, choices=Factor.choices)
    success = models.BooleanField()
    ip_address = models.GenericIPAddressField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self) -> str:
        return f'{self.username} {self.factor} {"ok" if self.success else "fail"}'
