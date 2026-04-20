"""Django system checks for the credentials vault.

Run ``python manage.py check --deploy`` to surface these in ops pipelines.
"""
from django.conf import settings
from django.core.checks import Error, Tags, register


@register(Tags.security, deploy=True)
def vault_master_key_configured(app_configs, **kwargs):
    errors = []
    key = (getattr(settings, 'VAULT_MASTER_KEY', '') or '').strip()
    if not settings.DEBUG and not key:
        errors.append(
            Error(
                'VAULT_MASTER_KEY is not set. The credentials vault will refuse to '
                'encrypt or decrypt until a Fernet key is provided.',
                hint=(
                    'Generate one with: python -c "from cryptography.fernet import '
                    'Fernet; print(Fernet.generate_key().decode())", then export '
                    'it as VAULT_MASTER_KEY.'
                ),
                id='credentials.E001',
            )
        )
    return errors
