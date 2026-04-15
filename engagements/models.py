from django.db import models
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
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

    # Creator
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

    def get_user_role(self, user):
        """Return the user's EngagementMember role, or None if not a member."""
        try:
            return self.members.get(user=user).role
        except self.members.model.DoesNotExist:
            return None

    def user_can_access(self, user):
        """Check if user can access this engagement."""
        if user.role == 'admin':
            return True
        return self.members.filter(user=user).exists()

    def user_can_edit(self, user):
        """Check if user can edit (lead or pentester on this engagement)."""
        if user.role == 'admin':
            return True
        role = self.get_user_role(user)
        return role in ('lead', 'pentester')

    def user_is_lead(self, user):
        """Check if user is lead on this engagement."""
        if user.role == 'admin':
            return True
        return self.get_user_role(user) == 'lead'

    def user_is_client(self, user):
        """Check if user has client role on this engagement."""
        return self.get_user_role(user) == 'client'

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

    @property
    def phase_progress(self):
        """List of {value, label, state} for the phase stepper — excludes Cancelled."""
        phases = [c for c in self.Status.choices if c[0] != self.Status.CANCELLED]
        current_idx = next(
            (i for i, (v, _) in enumerate(phases) if v == self.status), 0
        )
        result = []
        for i, (v, label) in enumerate(phases):
            if i < current_idx:
                state = 'done'
            elif i == current_idx:
                state = 'active'
            else:
                state = 'pending'
            result.append({'value': v, 'label': label, 'state': state})
        return result


class EngagementNote(models.Model):
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Note on {self.engagement.name} by {self.author}"


class EngagementMember(models.Model):
    """Per-engagement role assignment."""
    class Role(models.TextChoices):
        LEAD = 'lead', 'Lead'
        PENTESTER = 'pentester', 'Pentester'
        REVIEWER = 'reviewer', 'Reviewer'
        CLIENT = 'client', 'Client'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='members')
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=20, choices=Role.choices)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('engagement', 'user')
        ordering = ['role', 'joined_at']

    def __str__(self):
        return f"{self.user} — {self.get_role_display()} on {self.engagement.name}"

    @property
    def can_edit(self):
        return self.role in (self.Role.LEAD, self.Role.PENTESTER)

    @property
    def can_manage(self):
        return self.role == self.Role.LEAD

    @property
    def is_client(self):
        return self.role == self.Role.CLIENT


class Invitation(models.Model):
    """Email-based invitation to join an engagement."""
    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        ACCEPTED = 'accepted', 'Accepted'
        EXPIRED = 'expired', 'Expired'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='invitations')
    email = models.EmailField()
    role = models.CharField(max_length=20, choices=EngagementMember.Role.choices)
    invited_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Invite {self.email} → {self.engagement.name} as {self.get_role_display()}"

    @property
    def is_expired(self):
        return (timezone.now() - self.created_at).days > 7


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

