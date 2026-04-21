from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_alter_auditlog_action'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditlog',
            name='action',
            field=models.CharField(choices=[('user_create', 'User created'), ('user_update', 'User updated'), ('user_delete', 'User deleted'), ('user_role_change', 'User role changed'), ('engagement_create', 'Engagement created'), ('engagement_delete', 'Engagement deleted'), ('report_download', 'Report downloaded'), ('report_generate', 'Report generated'), ('login_failed', 'Login failed'), ('login_success', 'Login succeeded'), ('login_locked', 'Login locked out'), ('logout', 'Logout'), ('mfa_enabled', 'MFA enabled'), ('mfa_disabled', 'MFA disabled'), ('mfa_challenge_failed', 'MFA challenge failed'), ('password_change', 'Password changed')], max_length=40),
        ),
    ]
