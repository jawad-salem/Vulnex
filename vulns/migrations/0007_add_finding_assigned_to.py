from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vulns', '0006_add_sla_due_date'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='assigned_to',
            field=models.ForeignKey(
                blank=True,
                help_text='Team member responsible for this finding',
                null=True,
                on_delete=models.deletion.SET_NULL,
                related_name='assigned_findings',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
