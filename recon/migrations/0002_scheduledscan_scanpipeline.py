# Generated manually

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('recon', '0001_initial'),
        ('engagements', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScheduledScan',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('scan_type', models.CharField(choices=[
                    ('port_scan', 'Port Scan'),
                    ('subdomain', 'Subdomain Enumeration'),
                    ('tech_detect', 'Technology Detection'),
                    ('dir_brute', 'Directory Bruteforce'),
                    ('dns_enum', 'DNS Enumeration'),
                    ('whois', 'WHOIS Lookup'),
                ], max_length=20)),
                ('target', models.CharField(max_length=500)),
                ('frequency', models.CharField(choices=[
                    ('hourly', 'Every hour'),
                    ('daily', 'Daily'),
                    ('weekly', 'Weekly'),
                    ('monthly', 'Monthly'),
                ], default='daily', max_length=20)),
                ('is_active', models.BooleanField(default=True)),
                ('periodic_task_name', models.CharField(blank=True, max_length=200)),
                ('last_run', models.DateTimeField(blank=True, null=True)),
                ('run_count', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('engagement', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scheduled_scans', to='engagements.engagement')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='ScanPipeline',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('target', models.CharField(max_length=500)),
                ('steps', models.JSONField(default=list, help_text='Ordered list of scan_type strings')),
                ('current_step', models.IntegerField(default=0)),
                ('status', models.CharField(choices=[
                    ('pending', 'Pending'),
                    ('running', 'Running'),
                    ('completed', 'Completed'),
                    ('failed', 'Failed'),
                ], default='pending', max_length=20)),
                ('results_summary', models.JSONField(blank=True, default=dict)),
                ('error_message', models.TextField(blank=True)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('started_by', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('engagement', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scan_pipelines', to='engagements.engagement')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
