from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0002_update_user_roles'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='AuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('action', models.CharField(
                    choices=[
                        ('user_create', 'User created'),
                        ('user_update', 'User updated'),
                        ('user_delete', 'User deleted'),
                        ('user_role_change', 'User role changed'),
                        ('engagement_create', 'Engagement created'),
                        ('engagement_delete', 'Engagement deleted'),
                        ('report_download', 'Report downloaded'),
                        ('report_generate', 'Report generated'),
                        ('login_failed', 'Login failed'),
                    ],
                    max_length=40,
                )),
                ('target', models.CharField(blank=True, max_length=300)),
                ('details', models.JSONField(blank=True, default=dict)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('actor', models.ForeignKey(
                    blank=True, null=True,
                    on_delete=models.deletion.SET_NULL,
                    related_name='audit_actions',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                'ordering': ['-timestamp'],
                'indexes': [
                    models.Index(fields=['-timestamp'], name='accounts_au_timesta_idx'),
                    models.Index(fields=['action', '-timestamp'], name='accounts_au_action_idx'),
                ],
            },
        ),
    ]
