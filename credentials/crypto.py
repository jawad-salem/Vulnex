"""Symmetric encryption for sensitive credential secrets.

The Fernet key is read from ``settings.VAULT_MASTER_KEY`` (sourced from the
``VAULT_MASTER_KEY`` environment variable). It must be a 32-byte key
base64url-encoded — the exact format produced by ``Fernet.generate_key()``::

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Behaviour when the key is missing:

* ``DEBUG=True``  — falls back to a key deterministically derived from
  ``SECRET_KEY`` (the pre-1.2 behaviour) so existing development databases
  keep decrypting. A one-shot warning is logged.
* ``DEBUG=False`` — raises :class:`ImproperlyConfigured` on first use.
  ``python manage.py check --deploy`` also surfaces this in ops checks.

Rotate the key with::

    python manage.py rotate_vault_key --old-key <old> --new-key <new>
"""
import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)
_dev_warning_emitted = False


def _derive_dev_key():
    """DEBUG-only fallback: deterministic key derived from SECRET_KEY."""
    return base64.urlsafe_b64encode(
        hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    )


def _fernet():
    global _dev_warning_emitted
    key = (getattr(settings, 'VAULT_MASTER_KEY', '') or '').strip()
    if key:
        return Fernet(key.encode() if isinstance(key, str) else key)
    if not settings.DEBUG:
        raise ImproperlyConfigured(
            'VAULT_MASTER_KEY must be set when DJANGO_DEBUG=False. Generate one '
            'with: python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )
    if not _dev_warning_emitted:
        logger.warning(
            'VAULT_MASTER_KEY is not set — using a SECRET_KEY-derived fallback '
            'for development. Set VAULT_MASTER_KEY before deploying.'
        )
        _dev_warning_emitted = True
    return Fernet(_derive_dev_key())


def encrypt_secret(plaintext):
    if not plaintext:
        return ''
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext):
    if not ciphertext:
        return ''
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return ''
