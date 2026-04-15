from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vulns', '0003_add_discovered_host_fk_and_finding_template'),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='scope',
            field=models.CharField(
                choices=[('U', 'Unchanged'), ('C', 'Changed')],
                default='U',
                max_length=1,
            ),
        ),
        migrations.AddField(
            model_name='findingtemplate',
            name='scope',
            field=models.CharField(default='U', max_length=1),
        ),
    ]
