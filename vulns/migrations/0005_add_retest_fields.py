from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vulns', '0004_add_cvss_scope'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='retest_status',
            field=models.CharField(
                choices=[
                    ('not_retested', 'Not retested'),
                    ('fixed', 'Fixed'),
                    ('partial', 'Partially fixed'),
                    ('still_present', 'Still present'),
                ],
                default='not_retested',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='finding',
            name='retest_date',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='finding',
            name='retest_notes',
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name='finding',
            name='retested_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.deletion.SET_NULL,
                related_name='retested_findings',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
