"""API key authentication for the REST API.

Clients authenticate by sending ``Authorization: ApiKey vlnx_<prefix>_<secret>``.
The raw key is never stored — only the SHA-256 hash and a non-secret prefix
used to pick the right row. See ``accounts.models.APIKey`` for key issuance.
"""
from django.conf import settings
from django_otp import user_has_device
from django_otp.models import Device
from rest_framework_simplejwt.authentication import JWTAuthentication
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
        # Issued prefixes are exactly eight URL-safe characters. Underscores
        # are valid inside both prefix and secret, so splitting on '_' can
        # reject otherwise valid randomly generated keys.
        if len(raw) < 15 or raw[13] != '_':
            raise exceptions.AuthenticationFailed('Malformed API key.')
        prefix = raw[5:13]
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


class SecureJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user = super().get_user(validated_token)
        if validated_token.get('auth_version') != 2:
            raise exceptions.AuthenticationFailed('Please sign in again.')
        enrolled = user_has_device(user, confirmed=True)
        if user.role in settings.MFA_REQUIRED_ROLES and not enrolled:
            raise exceptions.AuthenticationFailed('MFA setup is required.')
        device_id = validated_token.get('otp_device')
        if enrolled or device_id:
            device = Device.from_persistent_id(device_id) if device_id else None
            if device is None or device.user_id != user.pk or not device.confirmed:
                raise exceptions.AuthenticationFailed('MFA verification is required. Please sign in again.')
        return user
