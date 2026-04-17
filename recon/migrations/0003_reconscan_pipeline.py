from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('recon', '0002_scheduledscan_scanpipeline'),
    ]

    operations = [
        migrations.AddField(
            model_name='reconscan',
            name='pipeline',
            field=models.ForeignKey(
                blank=True,
                help_text='Pipeline this scan was created by (null for ad-hoc scans).',
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='scans',
                to='recon.scanpipeline',
            ),
        ),
    ]
