import django.core.validators
import uuid
from django.db import migrations, models

from reports.models import report_template_logo_path


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='ReportTemplate',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=120, unique=True)),
                ('cover_logo', models.FileField(
                    blank=True, null=True, upload_to=report_template_logo_path,
                    help_text='Logo rendered on the cover page. PNG or JPG, up to 1 MB.',
                )),
                ('primary_color', models.CharField(
                    default='#534AB7', max_length=7,
                    help_text='Main brand color — cover divider, table headers.',
                    validators=[django.core.validators.RegexValidator(
                        regex=r'^#[0-9A-Fa-f]{6}$',
                        message='Colors must be hex in the form #RRGGBB.',
                    )],
                )),
                ('accent_color', models.CharField(
                    default='#378ADD', max_length=7,
                    help_text='Secondary accent — section rules, callouts.',
                    validators=[django.core.validators.RegexValidator(
                        regex=r'^#[0-9A-Fa-f]{6}$',
                        message='Colors must be hex in the form #RRGGBB.',
                    )],
                )),
                ('preamble_markdown', models.TextField(
                    blank=True,
                    help_text='Optional text rendered at the top of the executive summary.',
                )),
                ('disclaimer_markdown', models.TextField(
                    blank=True,
                    help_text='Optional disclaimer rendered at the end of the report.',
                )),
                ('footer_text', models.CharField(
                    blank=True, max_length=200,
                    help_text='Text rendered in the footer of each page.',
                )),
                ('is_default', models.BooleanField(
                    default=False,
                    help_text='Fallback template used when an engagement has no other preference.',
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={'ordering': ['name']},
        ),
    ]
