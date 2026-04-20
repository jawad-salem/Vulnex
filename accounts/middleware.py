"""MFA enforcement middleware.

Users whose role is listed in settings.MFA_REQUIRED_ROLES must have a
confirmed TOTP device before accessing any app view. Without one, every
request is redirected to the MFA setup page — the only reachable endpoints
are the setup flow itself, logout, login, and static assets.

Clients (and any other non-required role) are untouched.
"""
from django.conf import settings
from django.shortcuts import redirect
from django_otp import user_has_device


ALLOWED_PATH_PREFIXES = (
    '/static/',
    '/media/',
    '/accounts/logout/',
    '/accounts/login/',
    '/accounts/mfa/',
)


class MFARequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, 'user', None)
        required = getattr(settings, 'MFA_REQUIRED_ROLES', [])
        if (
            user is not None
            and user.is_authenticated
            and getattr(user, 'role', None) in required
            and not user_has_device(user, confirmed=True)
        ):
            path = request.path
            if not any(path.startswith(p) for p in ALLOWED_PATH_PREFIXES):
                return redirect('accounts:mfa_setup')
        return self.get_response(request)
