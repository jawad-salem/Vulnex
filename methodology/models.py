from django.db import models
from django.conf import settings
from engagements.models import Engagement
import uuid


class Methodology(models.Model):
    """A testing methodology template (OWASP, PTES, custom)."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    is_default = models.BooleanField(default=False)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = 'methodologies'
        ordering = ['name']

    def __str__(self):
        return self.name


class ChecklistCategory(models.Model):
    """Category within a methodology (e.g. 'Authentication', 'Input Validation')."""
    methodology = models.ForeignKey(Methodology, on_delete=models.CASCADE, related_name='categories')
    name = models.CharField(max_length=200)
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order', 'name']
        verbose_name_plural = 'checklist categories'

    def __str__(self):
        return f"{self.methodology.name} — {self.name}"


class ChecklistItem(models.Model):
    """Individual test case within a category."""
    category = models.ForeignKey(ChecklistCategory, on_delete=models.CASCADE, related_name='items')
    title = models.CharField(max_length=300)
    description = models.TextField(blank=True)
    reference_id = models.CharField(max_length=50, blank=True, help_text='e.g. WSTG-ATHN-01')
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['order', 'title']

    def __str__(self):
        return self.title


class EngagementChecklist(models.Model):
    """Tracks checklist progress for an engagement."""
    class ItemStatus(models.TextChoices):
        NOT_STARTED = 'not_started', 'Not Started'
        IN_PROGRESS = 'in_progress', 'In Progress'
        COMPLETED = 'completed', 'Completed'
        NOT_APPLICABLE = 'not_applicable', 'N/A'

    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='checklist_items')
    checklist_item = models.ForeignKey(ChecklistItem, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, choices=ItemStatus.choices, default=ItemStatus.NOT_STARTED)
    notes = models.TextField(blank=True)
    completed_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ['engagement', 'checklist_item']

    def __str__(self):
        return f"{self.checklist_item.title} — {self.get_status_display()}"

