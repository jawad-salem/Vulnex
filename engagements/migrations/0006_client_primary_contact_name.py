from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('engagements', '0005_attack_path'),
    ]

    operations = [
        migrations.AddField(
            model_name='client',
            name='primary_contact_name',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
