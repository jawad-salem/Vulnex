import uuid
from django.conf import settings
from django.db import models
from django.urls import reverse
from engagements.models import Engagement
from recon.models import DiscoveredHost
from .crypto import encrypt_secret, decrypt_secret


class Credential(models.Model):
    """Discovered credential captured during an engagement.

    The `secret` value (password / hash / token / key material) is encrypted at
    rest via Fernet — the DB column holds ciphertext only. Use `.secret` to
    read the plaintext and `.set_secret(value)` to write it.

    Clients NEVER see this table — enforced at the view layer.
    """

    class Type(models.TextChoices):
        PASSWORD = 'password', 'Username / Password'
        HASH = 'hash', 'Password Hash'
        API_TOKEN = 'api_token', 'API Token / Key'
        SSH_KEY = 'ssh_key', 'SSH Key'
        SESSION = 'session', 'Session Cookie'
        OTHER = 'other', 'Other'

    class Status(models.TextChoices):
        UNTESTED = 'untested', 'Untested'
        VALID = 'valid', 'Valid'
        INVALID = 'invalid', 'Invalid'
        EXPIRED = 'expired', 'Expired'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(
        Engagement, on_delete=models.CASCADE, related_name='credentials',
    )
    credential_type = models.CharField(
        max_length=20, choices=Type.choices, default=Type.PASSWORD,
    )
    username = models.CharField(max_length=300, blank=True)
    # Ciphertext — do not read/write directly; use the `secret` property.
    secret_encrypted = models.TextField(blank=True)
    hash_type = models.CharField(
        max_length=50, blank=True,
        help_text='e.g. NTLM, bcrypt, MD5, SHA1',
    )
    host = models.ForeignKey(
        DiscoveredHost, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='credentials',
    )
    service = models.CharField(
        max_length=100, blank=True,
        help_text='e.g. SSH, RDP, HTTP /admin, MySQL',
    )
    source = models.CharField(
        max_length=200, blank=True,
        help_text='How it was obtained — e.g. "mimikatz", "DB dump", "phishing"',
    )
    status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.UNTESTED,
    )
    notes = models.TextField(blank=True)

    found_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
        related_name='found_credentials',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['engagement', '-created_at']),
        ]

    def __str__(self):
        return f'{self.get_credential_type_display()} — {self.username or "(no user)"}'

    def get_absolute_url(self):
        return reverse('credentials:list', kwargs={'engagement_pk': self.engagement_id})

    @property
    def secret(self):
        return decrypt_secret(self.secret_encrypted)

    def set_secret(self, plaintext):
        self.secret_encrypted = encrypt_secret(plaintext or '')

    @property
    def masked_secret(self):
        """Return a masked preview — `••••` for passwords, first 4 chars for hashes/tokens."""
        value = self.secret
        if not value:
            return ''
        if self.credential_type in (self.Type.HASH, self.Type.API_TOKEN, self.Type.SSH_KEY):
            return value[:4] + '…' + ('·' * 6)
        return '•' * min(len(value), 8)
