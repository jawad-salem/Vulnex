from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('vulns', '0007_add_finding_assigned_to'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='finding',
            name='review_state',
            field=models.CharField(
                choices=[
                    ('draft', 'Draft'),
                    ('in_review', 'In review'),
                    ('approved', 'Approved'),
                    ('changes_requested', 'Changes requested'),
                ],
                default='draft',
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name='finding',
            name='reviewed_by',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=models.deletion.SET_NULL,
                related_name='reviewed_findings',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name='finding',
            name='reviewed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='finding',
            name='review_notes',
            field=models.TextField(
                blank=True,
                help_text='Reviewer feedback — visible on "Changes requested".',
            ),
        ),
    ]
