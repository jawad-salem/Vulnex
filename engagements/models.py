from django.db import models
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
import uuid


def client_logo_path(instance, filename):
    return f'client_logos/{instance.pk}/{filename}'


class Client(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200, unique=True)
    industry = models.CharField(max_length=120, blank=True, help_text='e.g. Financial services, E-commerce, Healthcare')
    logo = models.ImageField(upload_to=client_logo_path, blank=True, null=True)
    primary_contact_name = models.CharField(max_length=200, blank=True)
    primary_contact_email = models.EmailField(blank=True)
    notes = models.TextField(blank=True)
    default_report_template = models.ForeignKey(
        'reports.ReportTemplate', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='clients',
        help_text='Report template used when generating reports for this client.',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('engagements:client_detail', kwargs={'pk': self.pk})


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
    client = models.ForeignKey(
        Client, on_delete=models.PROTECT,
        related_name='engagements', null=True, blank=True,
    )
    engagement_type = models.CharField(max_length=30, choices=EngagementType.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PLANNING)
    description = models.TextField(blank=True)

    # Scope
    in_scope = models.TextField(help_text='One target per line (IPs, domains, URLs)', blank=True)
    out_of_scope = models.TextField(help_text='Excluded targets, one per line', blank=True)
    rules_of_engagement = models.TextField(blank=True)

    # Rules-of-engagement sign-off — once signed, scope/RoE edits are locked
    # until a lead revokes the sign-off.
    roe_signed_off = models.BooleanField(default=False)
    roe_signed_off_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='signed_off_engagements',
    )
    roe_signed_off_at = models.DateTimeField(null=True, blank=True)

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
    def client_name(self):
        return self.client.name if self.client_id else ''

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
    def lead(self):
        """The engagement lead (first member with the lead role), or the
        creator as a fallback. Used for the engagement card byline."""
        member = self.members.filter(role='lead').select_related('user').first()
        return member.user if member else self.created_by

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

    def user_can_review(self, user):
        """Check if user can approve / request changes on findings."""
        if user.role == 'admin':
            return True
        return self.get_user_role(user) in ('lead', 'reviewer')

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


class AttackPath(models.Model):
    """A red-team attack path: a DAG of nodes (hosts/identities/assets/objectives)
    connected by edges that carry a technique label and an optional ATT&CK ID
    plus a linked finding. Visible only on red-team engagements.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(
        Engagement, on_delete=models.CASCADE, related_name='attack_paths',
    )
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='created_attack_paths',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} ({self.engagement.name})'


class AttackPathNode(models.Model):
    class Kind(models.TextChoices):
        ENTRYPOINT = 'entrypoint', 'Entry Point'
        HOST = 'host', 'Host'
        IDENTITY = 'identity', 'Identity'
        ASSET = 'asset', 'Asset'
        OBJECTIVE = 'objective', 'Objective'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    path = models.ForeignKey(
        AttackPath, on_delete=models.CASCADE, related_name='nodes',
    )
    label = models.CharField(max_length=200)
    kind = models.CharField(
        max_length=20, choices=Kind.choices, default=Kind.HOST,
    )
    discovered_host = models.ForeignKey(
        'recon.DiscoveredHost', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='attack_path_nodes',
    )
    notes = models.TextField(blank=True)
    position_x = models.IntegerField(default=0)
    position_y = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']

    def __str__(self):
        return f'{self.get_kind_display()}: {self.label}'


class AttackPathEdge(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    path = models.ForeignKey(
        AttackPath, on_delete=models.CASCADE, related_name='edges',
    )
    from_node = models.ForeignKey(
        AttackPathNode, on_delete=models.CASCADE, related_name='outgoing_edges',
    )
    to_node = models.ForeignKey(
        AttackPathNode, on_delete=models.CASCADE, related_name='incoming_edges',
    )
    technique = models.CharField(
        max_length=200,
        help_text='Free-form technique label, e.g. "Pass-the-Hash", "Kerberoast".',
    )
    mitre_attack_id = models.CharField(
        max_length=20, blank=True,
        help_text='Optional MITRE ATT&CK technique ID, e.g. T1078.',
    )
    finding = models.ForeignKey(
        'vulns.Finding', on_delete=models.SET_NULL,
        null=True, blank=True, related_name='attack_path_edges',
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        constraints = [
            models.CheckConstraint(
                check=~models.Q(from_node=models.F('to_node')),
                name='attackpathedge_no_self_loop',
            ),
        ]

    def __str__(self):
        return f'{self.from_node.label} → {self.to_node.label} ({self.technique})'


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

