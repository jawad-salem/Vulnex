from django.db import models
from django.conf import settings
from engagements.models import Engagement
import uuid


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

