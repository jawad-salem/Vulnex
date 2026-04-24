import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vulns', '0009_protect_evidence_storage'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='FindingComment',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('body', models.TextField()),
                ('internal_only', models.BooleanField(
                    default=False,
                    help_text='Hide from Client role. Internal team discussion.',
                )),
                ('is_review_feedback', models.BooleanField(
                    default=False,
                    help_text='Mark as review feedback — surfaces alongside the reviewer decision.',
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('edited_at', models.DateTimeField(blank=True, null=True)),
                ('author', models.ForeignKey(
                    null=True, on_delete=django.db.models.deletion.SET_NULL,
                    related_name='finding_comments', to=settings.AUTH_USER_MODEL,
                )),
                ('finding', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='comments', to='vulns.finding',
                )),
                ('parent', models.ForeignKey(
                    blank=True, null=True, on_delete=django.db.models.deletion.CASCADE,
                    related_name='replies', to='vulns.findingcomment',
                )),
            ],
            options={
                'ordering': ['created_at'],
                'indexes': [models.Index(fields=['finding', 'created_at'], name='vulns_findi_finding_90bbdf_idx')],
            },
        ),
    ]
