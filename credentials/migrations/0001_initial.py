import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('engagements', '0002_remove_engagement_lead_and_more'),
        ('recon', '0002_scheduledscan_scanpipeline'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Credential',
            fields=[
                ('id', models.UUIDField(
                    default=uuid.uuid4, editable=False, primary_key=True, serialize=False,
                )),
                ('credential_type', models.CharField(
                    choices=[
                        ('password', 'Username / Password'),
                        ('hash', 'Password Hash'),
                        ('api_token', 'API Token / Key'),
                        ('ssh_key', 'SSH Key'),
                        ('session', 'Session Cookie'),
                        ('other', 'Other'),
                    ],
                    default='password', max_length=20,
                )),
                ('username', models.CharField(blank=True, max_length=300)),
                ('secret_encrypted', models.TextField(blank=True)),
                ('hash_type', models.CharField(
                    blank=True, help_text='e.g. NTLM, bcrypt, MD5, SHA1', max_length=50,
                )),
                ('service', models.CharField(
                    blank=True,
                    help_text='e.g. SSH, RDP, HTTP /admin, MySQL',
                    max_length=100,
                )),
                ('source', models.CharField(
                    blank=True,
                    help_text='How it was obtained — e.g. "mimikatz", "DB dump", "phishing"',
                    max_length=200,
                )),
                ('status', models.CharField(
                    choices=[
                        ('untested', 'Untested'),
                        ('valid', 'Valid'),
                        ('invalid', 'Invalid'),
                        ('expired', 'Expired'),
                    ],
                    default='untested', max_length=20,
                )),
                ('notes', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('engagement', models.ForeignKey(
                    on_delete=models.deletion.CASCADE,
                    related_name='credentials', to='engagements.engagement',
                )),
                ('found_by', models.ForeignKey(
                    null=True, on_delete=models.deletion.SET_NULL,
                    related_name='found_credentials', to=settings.AUTH_USER_MODEL,
                )),
                ('host', models.ForeignKey(
                    blank=True, null=True, on_delete=models.deletion.SET_NULL,
                    related_name='credentials', to='recon.discoveredhost',
                )),
            ],
            options={
                'ordering': ['-created_at'],
                'indexes': [
                    models.Index(fields=['engagement', '-created_at'], name='credentials_engage_created_idx'),
                ],
            },
        ),
    ]
