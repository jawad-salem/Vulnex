"""Re-encrypt every Credential secret from an old vault key to a new one.

Runs in a single transaction — any decryption failure aborts the whole
rotation. Use this when rotating VAULT_MASTER_KEY or migrating from the
pre-1.2 SECRET_KEY-derived key.

Examples
--------
Rotate to a new key (new key read from settings.VAULT_MASTER_KEY)::

    VAULT_MASTER_KEY=<new> python manage.py rotate_vault_key --old-key <old>

Explicit both::

    python manage.py rotate_vault_key --old-key <old> --new-key <new>
"""
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from credentials.models import Credential


def _build_fernet(label, key):
    if not key:
        raise CommandError(f'{label} is empty.')
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except Exception as exc:
        raise CommandError(f'{label} is not a valid Fernet key: {exc}')


class Command(BaseCommand):
    help = 'Re-encrypt all Credential secrets from --old-key to --new-key.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--old-key', required=True,
            help='Current Fernet key used to decrypt existing ciphertexts.',
        )
        parser.add_argument(
            '--new-key', required=False,
            help='Target Fernet key. Defaults to settings.VAULT_MASTER_KEY.',
        )

    @transaction.atomic
    def handle(self, *args, **opts):
        old_key = opts['old_key']
        new_key = opts.get('new_key') or (getattr(settings, 'VAULT_MASTER_KEY', '') or '').strip()
        if not new_key:
            raise CommandError(
                'No new key — pass --new-key or set VAULT_MASTER_KEY in the environment.'
            )
        if old_key == new_key:
            raise CommandError('Old and new keys are identical — nothing to do.')

        old_fernet = _build_fernet('--old-key', old_key)
        new_fernet = _build_fernet('--new-key', new_key)

        rotated = 0
        skipped = 0
        queryset = Credential.objects.exclude(secret_encrypted='')
        total = queryset.count()

        for cred in queryset.iterator():
            try:
                plaintext = old_fernet.decrypt(cred.secret_encrypted.encode()).decode()
            except InvalidToken:
                # Don't silently accept — rotation should be all-or-nothing.
                raise CommandError(
                    f'Credential {cred.pk} could not be decrypted with --old-key. '
                    f'Rotation aborted; no changes committed.'
                )
            cred.secret_encrypted = new_fernet.encrypt(plaintext.encode()).decode()
            cred.save(update_fields=['secret_encrypted'])
            rotated += 1

        self.stdout.write(self.style.SUCCESS(
            f'Rotated {rotated}/{total} credentials. Skipped {skipped}.'
        ))
