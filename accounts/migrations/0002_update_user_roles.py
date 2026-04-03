from django.db import migrations, models


def migrate_viewer_to_reviewer(apps, schema_editor):
    """Convert existing 'viewer' users to 'reviewer'."""
    User = apps.get_model('accounts', 'User')
    User.objects.filter(role='viewer').update(role='reviewer')


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0001_initial'),
    ]

    operations = [
        # First migrate data, then change field choices
        migrations.RunPython(migrate_viewer_to_reviewer, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(
                choices=[
                    ('admin', 'Admin'),
                    ('pentester', 'Pentester'),
                    ('reviewer', 'Reviewer'),
                    ('client', 'Client'),
                ],
                default='pentester',
                max_length=20,
            ),
        ),
    ]
