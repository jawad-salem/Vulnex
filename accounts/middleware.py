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
    # JWT-bootstrap and schema only. The schema endpoint is needed because the
    # docs UI fetches it during render. Every other /api/v1/ path is gated:
    # session-authed users land here as request.user, get redirected to MFA
    # setup; JWT/API-key clients hit Django middleware as AnonymousUser (DRF
    # authenticates per-request, after middleware) and pass through.
    '/api/v1/auth/token/',
    '/api/v1/auth/token/refresh/',
    '/api/schema/',
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


class PermissionsPolicyMiddleware:
    """Emit `Permissions-Policy` from settings.PERMISSIONS_POLICY.

    Django's SecurityMiddleware doesn't support this header natively. The
    setting is a dict of feature -> allowlist (empty list = disabled), e.g.
    `{'camera': [], 'microphone': [], 'geolocation': []}`.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        policy = getattr(settings, 'PERMISSIONS_POLICY', {}) or {}
        parts = []
        for feature, allowlist in policy.items():
            if not allowlist:
                parts.append(f'{feature}=()')
            else:
                rendered = ' '.join(
                    'self' if v == 'self' else f'"{v}"' for v in allowlist
                )
                parts.append(f'{feature}=({rendered})')
        self._header = ', '.join(parts)

    def __call__(self, request):
        response = self.get_response(request)
        if self._header:
            response.headers['Permissions-Policy'] = self._header
        return response
