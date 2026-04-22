import uuid

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0009_expand_auditlog_actions'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditlog',
            name='action',
            field=models.CharField(
                max_length=40,
                choices=[
                    ('user_create', 'User created'),
                    ('user_update', 'User updated'),
                    ('user_delete', 'User deleted'),
                    ('user_role_change', 'User role changed'),
                    ('engagement_create', 'Engagement created'),
                    ('engagement_delete', 'Engagement deleted'),
                    ('report_downloaded', 'Report downloaded'),
                    ('report_generated', 'Report generated'),
                    ('login_failed', 'Login failed'),
                    ('login_success', 'Login succeeded'),
                    ('login_locked', 'Login locked out'),
                    ('logout', 'Logout'),
                    ('mfa_enabled', 'MFA enabled'),
                    ('mfa_disabled', 'MFA disabled'),
                    ('mfa_challenge_failed', 'MFA challenge failed'),
                    ('password_change', 'Password changed'),
                    ('credential_create', 'Credential created'),
                    ('credential_delete', 'Credential deleted'),
                    ('credential_reveal', 'Credential revealed'),
                    ('evidence_download', 'Evidence downloaded'),
                    ('invitation_sent', 'Invitation sent'),
                    ('invitation_accepted', 'Invitation accepted'),
                    ('api_key_issued', 'API key issued'),
                    ('api_key_revoked', 'API key revoked'),
                ],
            ),
        ),
        migrations.CreateModel(
            name='APIKey',
            fields=[
                ('id', models.UUIDField(
                    default=uuid.uuid4, editable=False,
                    primary_key=True, serialize=False,
                )),
                ('name', models.CharField(
                    help_text='Human label, e.g. "CI pipeline"',
                    max_length=100,
                )),
                ('key_prefix', models.CharField(db_index=True, max_length=16, unique=True)),
                ('hashed_key', models.CharField(max_length=128)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_used_at', models.DateTimeField(blank=True, null=True)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('revoked_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='api_keys',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'ordering': ['-created_at']},
        ),
    ]
