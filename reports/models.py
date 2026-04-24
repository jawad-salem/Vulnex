from django.core.validators import RegexValidator
from django.db import models
from django.conf import settings
from engagements.models import Engagement
import uuid


HEX_COLOR_VALIDATOR = RegexValidator(
    regex=r'^#[0-9A-Fa-f]{6}$',
    message='Colors must be hex in the form #RRGGBB.',
)


def report_template_logo_path(instance, filename):
    return f'report_template_logos/{instance.pk}/{filename}'


class ReportTemplate(models.Model):
    """Brand kit for generated reports — logo, colors, boilerplate.

    Admins maintain a small library of templates; Clients can pin a default
    template so reports generated for their engagements look consistent.
    One template in the library carries `is_default=True` as the global
    fallback when no engagement/client preference exists.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=120, unique=True)
    cover_logo = models.FileField(
        upload_to=report_template_logo_path, blank=True, null=True,
        help_text='Logo rendered on the cover page. PNG or JPG, up to 1 MB.',
    )
    primary_color = models.CharField(
        max_length=7, default='#534AB7', validators=[HEX_COLOR_VALIDATOR],
        help_text='Main brand color — cover divider, table headers.',
    )
    accent_color = models.CharField(
        max_length=7, default='#378ADD', validators=[HEX_COLOR_VALIDATOR],
        help_text='Secondary accent — section rules, callouts.',
    )
    preamble_markdown = models.TextField(
        blank=True,
        help_text='Optional text rendered at the top of the executive summary.',
    )
    disclaimer_markdown = models.TextField(
        blank=True,
        help_text='Optional disclaimer rendered at the end of the report.',
    )
    footer_text = models.CharField(
        max_length=200, blank=True,
        help_text='Text rendered in the footer of each page.',
    )
    is_default = models.BooleanField(
        default=False,
        help_text='Fallback template used when an engagement has no other preference.',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # Only one default — flipping is_default on this row clears others.
        if self.is_default:
            ReportTemplate.objects.exclude(pk=self.pk).filter(
                is_default=True
            ).update(is_default=False)
        super().save(*args, **kwargs)


class Report(models.Model):
    class ReportType(models.TextChoices):
        FULL = 'full', 'Full Report'
        EXECUTIVE = 'executive', 'Executive Summary'
        TECHNICAL = 'technical', 'Technical Detail'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='reports')
    title = models.CharField(max_length=300)
    report_type = models.CharField(max_length=20, choices=ReportType.choices, default=ReportType.FULL)
    file = models.FileField(upload_to='reports/%Y/%m/', blank=True)
    generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title

