"""Symmetric encryption for sensitive credential secrets.

The Fernet key is derived deterministically from Django's SECRET_KEY, so
credentials stay decryptable across restarts without adding another secret to
manage. This is a pragmatic tradeoff — rotating SECRET_KEY invalidates every
stored credential, so document that in ops runbooks if this project is ever
deployed seriously.
"""
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


def _fernet():
    key = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))


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
