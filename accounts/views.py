import time

from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from . import services
from .forms import LoginForm, RegisterForm, TotpForm
from .models import AuthAttempt

PENDING_USER = 'pending_user_id'
VERIFIED_AT = 'totp_verified_at'


def _pending_user(request: HttpRequest) -> User | None:
    user_id = request.session.get(PENDING_USER)
    return User.objects.filter(pk=user_id).first() if user_id else None


def _safe_next(request: HttpRequest) -> str | None:
    target = request.POST.get('next') or request.GET.get('next')
    if target and url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        return target
    return None


def register(request: HttpRequest) -> HttpResponse:
    form = RegisterForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = services.create_account(
            form.cleaned_data['username'], form.cleaned_data['email'], form.cleaned_data['password1']
        )
        request.session[PENDING_USER] = user.pk
        return redirect('accounts:totp_setup')
    return render(request, 'accounts/register.html', {'form': form})


def login_view(request: HttpRequest) -> HttpResponse:
    form = LoginForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        username = form.cleaned_data['username']
        if services.is_locked(username):
            form.add_error(None, 'Account locked. Too many failed attempts. Try again in 15 minutes.')
        else:
            user = authenticate(request, username=username, password=form.cleaned_data['password'])
            services.record_attempt(request, username, AuthAttempt.Factor.PASSWORD, user is not None)
            if user is None:
                form.add_error(None, 'Wrong username or password. Check both and try again.')
            else:
                request.session[PENDING_USER] = user.pk
                confirmed = services.profile_of(user).totp_confirmed
                return redirect('accounts:totp_verify' if confirmed else 'accounts:totp_setup')
    return render(request, 'accounts/login.html', {'form': form})


def totp_setup(request: HttpRequest) -> HttpResponse:
    user = _pending_user(request)
    if user is None:
        return redirect('accounts:login')
    profile = services.profile_of(user)
    if profile.totp_confirmed:
        return redirect('accounts:totp_verify')
    form = TotpForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        if services.is_locked(user.username):
            form.add_error(None, 'Account locked. Too many failed attempts. Try again in 15 minutes.')
        else:
            ok = services.verify_totp(profile, form.cleaned_data['code'])
            services.record_attempt(request, user.username, AuthAttempt.Factor.TOTP, ok)
            if ok:
                profile.totp_confirmed = True
                profile.save(update_fields=['totp_confirmed'])
                return _complete_login(request, user)
            form.add_error('code', 'Code did not match. Use the current 6-digit code from your authenticator app.')
    context = {'form': form, 'qr_svg': services.totp_qr_svg(profile), 'secret': profile.totp_secret}
    return render(request, 'accounts/totp_setup.html', context)


def totp_verify(request: HttpRequest) -> HttpResponse:
    """Second factor at login, and step-up check before any decryption (report section 3.13)."""
    user = request.user if request.user.is_authenticated else _pending_user(request)
    if user is None:
        return redirect('accounts:login')
    assert isinstance(user, User)
    form = TotpForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        if services.is_locked(user.username):
            form.add_error(None, 'Account locked. Too many failed attempts. Try again in 15 minutes.')
        else:
            ok = services.verify_totp(services.profile_of(user), form.cleaned_data['code'])
            services.record_attempt(request, user.username, AuthAttempt.Factor.TOTP, ok)
            if ok:
                return _complete_login(request, user)
            form.add_error('code', 'Code did not match. Use the current 6-digit code from your authenticator app.')
    step_up = request.user.is_authenticated
    return render(request, 'accounts/totp_verify.html', {'form': form, 'step_up': step_up, 'next': _safe_next(request)})


def _complete_login(request: HttpRequest, user: User) -> HttpResponse:
    if not request.user.is_authenticated:
        login(request, user)
    request.session.pop(PENDING_USER, None)
    request.session[VERIFIED_AT] = time.time()
    return redirect(_safe_next(request) or 'vault:dashboard')


@require_POST
def logout_view(request: HttpRequest) -> HttpResponse:
    logout(request)
    messages.info(request, 'Signed out.')
    return redirect('accounts:login')
