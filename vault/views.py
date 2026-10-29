import time
from urllib.parse import quote

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from accounts.views import VERIFIED_AT
from crypto.hybrid import IntegrityError
from crypto.keys import KeyMaterialError

from . import services
from .models import StoredFile


@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    files = StoredFile.objects.filter(owner=request.user)
    limit_mb = settings.MAX_UPLOAD_SIZE // (1024 * 1024)
    return render(request, 'vault/dashboard.html', {'files': files, 'limit_mb': limit_mb})


@login_required
@require_POST
def upload(request: HttpRequest) -> HttpResponse:
    file = request.FILES.get('file')
    if file is None:
        messages.error(request, 'No file selected. Choose a file, then upload.')
        return redirect('vault:dashboard')
    try:
        record = services.store_file(request.user, file)  # type: ignore[arg-type]
    except ValidationError as exc:
        messages.error(request, exc.messages[0])
    else:
        messages.success(request, f'{record.name} encrypted with AES, RC6 and DES in {record.encrypt_ms:.0f} ms.')
    return redirect('vault:dashboard')


@login_required
def download(request: HttpRequest, file_id: str) -> HttpResponse:
    record = get_object_or_404(StoredFile, pk=file_id, owner=request.user)
    verified_at = request.session.get(VERIFIED_AT, 0)
    if time.time() - verified_at > settings.STEP_UP_SECONDS:
        here = reverse('vault:download', args=[record.pk])
        return redirect(f'{reverse("accounts:totp_verify")}?next={quote(here)}')
    try:
        data = services.load_file(record)
    except (IntegrityError, KeyMaterialError, ValueError):
        messages.error(
            request, f'{record.name} failed its integrity check. Stored data was altered. Delete it and upload again.'
        )
        return redirect('vault:dashboard')
    response = HttpResponse(data, content_type=record.content_type)
    response['Content-Disposition'] = f"attachment; filename*=UTF-8''{quote(record.name)}"
    return response


@login_required
@require_POST
def delete(request: HttpRequest, file_id: str) -> HttpResponse:
    record = get_object_or_404(StoredFile, pk=file_id, owner=request.user)
    services.delete_file(record)
    messages.info(request, f'{record.name} deleted.')
    return redirect('vault:dashboard')
