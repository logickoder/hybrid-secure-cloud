from typing import TYPE_CHECKING

from django.contrib import admin

from .models import AuthAttempt, Profile

# ModelAdmin is generic only in the type stubs. Subscripting it at runtime raises.
if TYPE_CHECKING:
    ProfileAdminBase = admin.ModelAdmin[Profile]
    AuthAttemptAdminBase = admin.ModelAdmin[AuthAttempt]
else:
    ProfileAdminBase = AuthAttemptAdminBase = admin.ModelAdmin


@admin.register(Profile)
class ProfileAdmin(ProfileAdminBase):
    list_display = ('user', 'totp_confirmed')
    exclude = ('totp_secret', 'key_image')


@admin.register(AuthAttempt)
class AuthAttemptAdmin(AuthAttemptAdminBase):
    list_display = ('created_at', 'username', 'factor', 'success', 'ip_address')
    list_filter = ('factor', 'success')
    search_fields = ('username',)
