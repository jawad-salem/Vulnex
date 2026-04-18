from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_rename_accounts_au_timesta_idx_accounts_au_timesta_40aa9a_idx_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='auditlog',
            name='ip_address',
        ),
    ]
