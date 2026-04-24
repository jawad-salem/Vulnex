import django.db.models.deletion
import uuid
from django.db import migrations, models

from engagements.models import client_logo_path


def backfill_clients(apps, schema_editor):
    Engagement = apps.get_model('engagements', 'Engagement')
    Client = apps.get_model('engagements', 'Client')

    seen = {}
    for eng in Engagement.objects.all():
        raw = (eng.client_name or '').strip() or 'Unspecified Client'
        key = raw.lower()
        client = seen.get(key)
        if client is None:
            client, _ = Client.objects.get_or_create(name=raw)
            seen[key] = client
        eng.client = client
        eng.save(update_fields=['client'])


def reverse_backfill(apps, schema_editor):
    Engagement = apps.get_model('engagements', 'Engagement')
    for eng in Engagement.objects.select_related('client').all():
        if eng.client:
            eng.client_name = eng.client.name
            eng.save(update_fields=['client_name'])


class Migration(migrations.Migration):

    dependencies = [
        ('engagements', '0002_remove_engagement_lead_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Client',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200, unique=True)),
                ('logo', models.ImageField(blank=True, null=True, upload_to=client_logo_path)),
                ('primary_contact_email', models.EmailField(blank=True, max_length=254)),
                ('notes', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={'ordering': ['name']},
        ),
        migrations.AddField(
            model_name='engagement',
            name='client',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name='engagements', to='engagements.client',
            ),
        ),
        migrations.RunPython(backfill_clients, reverse_backfill),
        migrations.RemoveField(
            model_name='engagement',
            name='client_name',
        ),
    ]
