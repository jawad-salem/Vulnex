import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('engagements', '0003_client_model'),
        ('reports', '0002_report_template'),
    ]

    operations = [
        migrations.AddField(
            model_name='client',
            name='default_report_template',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='clients', to='reports.reporttemplate',
                help_text='Report template used when generating reports for this client.',
            ),
        ),
    ]
