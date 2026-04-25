from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_alter_auditlog_action'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditlog',
            name='action',
            field=models.CharField(choices=[('user_create', 'User created'), ('user_update', 'User updated'), ('user_delete', 'User deleted'), ('user_role_change', 'User role changed'), ('engagement_create', 'Engagement created'), ('engagement_delete', 'Engagement deleted'), ('report_downloaded', 'Report downloaded'), ('report_generated', 'Report generated'), ('login_failed', 'Login failed'), ('login_success', 'Login succeeded'), ('login_locked', 'Login locked out'), ('logout', 'Logout'), ('mfa_enabled', 'MFA enabled'), ('mfa_disabled', 'MFA disabled'), ('mfa_challenge_failed', 'MFA challenge failed'), ('password_change', 'Password changed'), ('credential_create', 'Credential created'), ('credential_delete', 'Credential deleted'), ('credential_reveal', 'Credential revealed'), ('evidence_download', 'Evidence downloaded'), ('invitation_sent', 'Invitation sent'), ('invitation_accepted', 'Invitation accepted'), ('api_key_issued', 'API key issued'), ('api_key_revoked', 'API key revoked'), ('comment_post', 'Comment posted'), ('comment_edit', 'Comment edited'), ('comment_delete', 'Comment deleted'), ('finding_merge', 'Finding merged')], max_length=40),
        ),
    ]
