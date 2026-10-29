from typing import TYPE_CHECKING

from django.contrib import admin

from .models import StoredFile

# ModelAdmin is generic only in the type stubs. Subscripting it at runtime raises.
if TYPE_CHECKING:
    StoredFileAdminBase = admin.ModelAdmin[StoredFile]
else:
    StoredFileAdminBase = admin.ModelAdmin


@admin.register(StoredFile)
class StoredFileAdmin(StoredFileAdminBase):
    list_display = ('name', 'owner', 'size', 'encrypt_ms', 'created_at')
    exclude = ('wrapped_keys',)
