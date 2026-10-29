import uuid

from django.conf import settings
from django.db import models


class StoredFile(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='files')
    name = models.CharField(max_length=255)
    content_type = models.CharField(max_length=100, default='application/octet-stream')
    size = models.PositiveBigIntegerField()
    checksum = models.CharField(max_length=64)
    wrapped_keys = models.BinaryField()
    aes_path = models.CharField(max_length=255)
    rc6_path = models.CharField(max_length=255)
    des_path = models.CharField(max_length=255)
    encrypt_ms = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-created_at',)

    def __str__(self) -> str:
        return self.name
