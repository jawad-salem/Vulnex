from datetime import timedelta
from django.db import migrations, models


SLA_DAYS = {
    'critical': 7,
    'high': 14,
    'medium': 30,
    'low': 60,
    'info': 90,
}


def backfill_due_dates(apps, schema_editor):
    Finding = apps.get_model('vulns', 'Finding')
    for f in Finding.objects.filter(due_date__isnull=True):
        days = SLA_DAYS.get(f.severity, 90)
        f.due_date = f.created_at.date() + timedelta(days=days)
        f.save(update_fields=['due_date'])


class Migration(migrations.Migration):

    dependencies = [
        ('vulns', '0005_add_retest_fields'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='due_date',
            field=models.DateField(blank=True, null=True),
        ),
        migrations.RunPython(backfill_due_dates, migrations.RunPython.noop),
    ]
