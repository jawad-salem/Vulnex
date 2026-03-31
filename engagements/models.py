from django.db import models
from django.conf import settings
from django.urls import reverse
import uuid


class Engagement(models.Model):
    class Status(models.TextChoices):
        PLANNING = 'planning', 'Planning'
        RECON = 'recon', 'Reconnaissance'
        SCANNING = 'scanning', 'Scanning'
        EXPLOITATION = 'exploitation', 'Exploitation'
        POST_EXPLOIT = 'post_exploitation', 'Post-Exploitation'
        REPORTING = 'reporting', 'Reporting'
        COMPLETED = 'completed', 'Completed'
        CANCELLED = 'cancelled', 'Cancelled'

    class EngagementType(models.TextChoices):
        EXTERNAL = 'external', 'External Pentest'
        INTERNAL = 'internal', 'Internal Pentest'
        WEBAPP = 'webapp', 'Web Application'
        API = 'api', 'API Assessment'
        MOBILE = 'mobile', 'Mobile Application'
        WIRELESS = 'wireless', 'Wireless Assessment'
        SOCIAL = 'social_engineering', 'Social Engineering'
        RED_TEAM = 'red_team', 'Red Team'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    client_name = models.CharField(max_length=200)
    engagement_type = models.CharField(max_length=30, choices=EngagementType.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PLANNING)
    description = models.TextField(blank=True)

    # Scope
    in_scope = models.TextField(help_text='One target per line (IPs, domains, URLs)', blank=True)
    out_of_scope = models.TextField(help_text='Excluded targets, one per line', blank=True)
    rules_of_engagement = models.TextField(blank=True)

    # Dates
    start_date = models.DateField(null=True, blank=True)
    end_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Team
    lead = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, related_name='led_engagements'
    )
    team_members = models.ManyToManyField(
        settings.AUTH_USER_MODEL, blank=True, related_name='engagements'
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, related_name='created_engagements'
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} — {self.client_name}"

    def get_absolute_url(self):
        return reverse('engagements:detail', kwargs={'pk': self.pk})

    @property
    def scope_targets(self):
        """Return in-scope targets as a list."""
        return [t.strip() for t in self.in_scope.splitlines() if t.strip()]

    @property
    def finding_count(self):
        return self.findings.count()

    @property
    def critical_count(self):
        return self.findings.filter(severity='critical').count()

    @property
    def high_count(self):
        return self.findings.filter(severity='high').count()

    @property
    def progress_percent(self):
        phases = list(self.Status.values)
        if self.status == self.Status.CANCELLED:
            return 0
        try:
            idx = phases.index(self.status)
            return int((idx / (len(phases) - 2)) * 100)  # exclude cancelled
        except ValueError:
            return 0


class EngagementNote(models.Model):
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Note on {self.engagement.name} by {self.author}"


class ActivityLog(models.Model):
    """Audit trail for engagement actions."""
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='activity_logs')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    action = models.CharField(max_length=200)
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user} — {self.action}"

