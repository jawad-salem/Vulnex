"""API key authentication for the REST API.

Clients authenticate by sending ``Authorization: ApiKey vlnx_<prefix>_<secret>``.
The raw key is never stored — only the SHA-256 hash and a non-secret prefix
used to pick the right row. See ``accounts.models.APIKey`` for key issuance.
"""
from django.utils import timezone
from rest_framework import authentication, exceptions

from accounts.models import APIKey


class APIKeyAuthentication(authentication.BaseAuthentication):
    keyword = 'ApiKey'

    def authenticate(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth:
            return None
        try:
            scheme, raw = auth.split(' ', 1)
        except ValueError:
            return None
        if scheme != self.keyword:
            return None
        raw = raw.strip()
        if not raw.startswith('vlnx_'):
            raise exceptions.AuthenticationFailed('Malformed API key.')
        parts = raw.split('_', 2)
        if len(parts) != 3 or not parts[1] or not parts[2]:
            raise exceptions.AuthenticationFailed('Malformed API key.')
        prefix = parts[1]
        try:
            key = APIKey.objects.select_related('user').get(key_prefix=prefix)
        except APIKey.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid API key.')
        if not key.is_active:
            raise exceptions.AuthenticationFailed('API key revoked or expired.')
        if not key.matches(raw):
            raise exceptions.AuthenticationFailed('Invalid API key.')
        if not key.user.is_active:
            raise exceptions.AuthenticationFailed('User is disabled.')
        key.last_used_at = timezone.now()
        key.save(update_fields=['last_used_at'])
        return (key.user, key)

    def authenticate_header(self, request):
        return self.keyword
