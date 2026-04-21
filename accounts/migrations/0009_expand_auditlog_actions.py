from django.db import migrations, models


def rename_report_actions_forward(apps, schema_editor):
    AuditLog = apps.get_model('accounts', 'AuditLog')
    AuditLog.objects.filter(action='report_download').update(action='report_downloaded')
    AuditLog.objects.filter(action='report_generate').update(action='report_generated')


def rename_report_actions_backward(apps, schema_editor):
    AuditLog = apps.get_model('accounts', 'AuditLog')
    AuditLog.objects.filter(action='report_downloaded').update(action='report_download')
    AuditLog.objects.filter(action='report_generated').update(action='report_generate')


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_alter_auditlog_action'),
    ]

    operations = [
        migrations.RunPython(rename_report_actions_forward, rename_report_actions_backward),
        migrations.AlterField(
            model_name='auditlog',
            name='action',
            field=models.CharField(
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
                ],
                max_length=40,
            ),
        ),
    ]
