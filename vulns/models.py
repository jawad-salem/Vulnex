from datetime import timedelta
from django.db import models
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.urls import reverse
from django.utils import timezone
from engagements.models import Engagement
from recon.models import DiscoveredHost
import uuid


def protected_storage():
    """Storage for evidence files. Lives outside MEDIA_ROOT so it can never be
    served by the static/media handler — only via vulns.views.evidence_download
    after an engagement-membership check."""
    return FileSystemStorage(location=settings.PROTECTED_MEDIA_ROOT)


class Finding(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = 'critical', 'Critical'
        HIGH = 'high', 'High'
        MEDIUM = 'medium', 'Medium'
        LOW = 'low', 'Low'
        INFO = 'info', 'Informational'

    class Status(models.TextChoices):
        OPEN = 'open', 'Open'
        CONFIRMED = 'confirmed', 'Confirmed'
        FALSE_POSITIVE = 'false_positive', 'False Positive'
        REMEDIATED = 'remediated', 'Remediated'
        ACCEPTED = 'accepted', 'Risk Accepted'

    # CVSS v3.1 Base Score vectors
    class AttackVector(models.TextChoices):
        NETWORK = 'N', 'Network'
        ADJACENT = 'A', 'Adjacent'
        LOCAL = 'L', 'Local'
        PHYSICAL = 'P', 'Physical'

    class AttackComplexity(models.TextChoices):
        LOW = 'L', 'Low'
        HIGH = 'H', 'High'

    class PrivilegesRequired(models.TextChoices):
        NONE = 'N', 'None'
        LOW = 'L', 'Low'
        HIGH = 'H', 'High'

    class UserInteraction(models.TextChoices):
        NONE = 'N', 'None'
        REQUIRED = 'R', 'Required'

    class Impact(models.TextChoices):
        HIGH = 'H', 'High'
        LOW = 'L', 'Low'
        NONE = 'N', 'None'

    class Scope(models.TextChoices):
        UNCHANGED = 'U', 'Unchanged'
        CHANGED = 'C', 'Changed'

    class RetestStatus(models.TextChoices):
        NOT_RETESTED = 'not_retested', 'Not retested'
        FIXED = 'fixed', 'Fixed'
        PARTIALLY_FIXED = 'partial', 'Partially fixed'
        STILL_PRESENT = 'still_present', 'Still present'

    class ReviewState(models.TextChoices):
        DRAFT = 'draft', 'Draft'
        IN_REVIEW = 'in_review', 'In review'
        APPROVED = 'approved', 'Approved'
        CHANGES_REQUESTED = 'changes_requested', 'Changes requested'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='findings')
    title = models.CharField(max_length=300)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)

    # CVSS v3.1 vectors
    cvss_score = models.FloatField(null=True, blank=True)
    attack_vector = models.CharField(max_length=1, choices=AttackVector.choices, default='N')
    attack_complexity = models.CharField(max_length=1, choices=AttackComplexity.choices, default='L')
    privileges_required = models.CharField(max_length=1, choices=PrivilegesRequired.choices, default='N')
    user_interaction = models.CharField(max_length=1, choices=UserInteraction.choices, default='N')
    scope = models.CharField(max_length=1, choices=Scope.choices, default='U')
    confidentiality_impact = models.CharField(max_length=1, choices=Impact.choices, default='N')
    integrity_impact = models.CharField(max_length=1, choices=Impact.choices, default='N')
    availability_impact = models.CharField(max_length=1, choices=Impact.choices, default='N')

    # Location — where exactly the vulnerability exists
    class HttpMethod(models.TextChoices):
        GET = 'GET', 'GET'
        POST = 'POST', 'POST'
        PUT = 'PUT', 'PUT'
        PATCH = 'PATCH', 'PATCH'
        DELETE = 'DELETE', 'DELETE'
        OPTIONS = 'OPTIONS', 'OPTIONS'
        HEAD = 'HEAD', 'HEAD'

    discovered_host = models.ForeignKey(
        DiscoveredHost, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='findings', help_text='Link to a discovered host from recon'
    )
    host = models.CharField(max_length=300, blank=True, help_text='e.g. api.example.com')
    port = models.PositiveIntegerField(null=True, blank=True, help_text='e.g. 443, 8080')
    url = models.URLField(max_length=2000, blank=True, help_text='Full URL where the issue was found')
    parameter = models.CharField(max_length=300, blank=True, help_text='Vulnerable parameter, e.g. username, id')
    http_method = models.CharField(max_length=10, choices=HttpMethod.choices, blank=True, help_text='HTTP method used')
    endpoint = models.CharField(max_length=500, blank=True, help_text='API endpoint or path, e.g. /api/v1/login')

    # Details
    description = models.TextField()
    affected_hosts = models.TextField(blank=True, help_text='Additional affected hosts — one per line')
    proof_of_concept = models.TextField(blank=True, help_text='Steps to reproduce')
    remediation = models.TextField(blank=True)
    references = models.TextField(blank=True, help_text='CVE IDs, URLs — one per line')
    cwe_id = models.CharField(max_length=20, blank=True, help_text='e.g. CWE-79')

    # Metadata
    found_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='assigned_findings',
        help_text='Team member responsible for this finding',
    )
    tool_source = models.CharField(max_length=100, blank=True, help_text='e.g. Nmap, Burp, Manual')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # Retest / verification
    retest_status = models.CharField(
        max_length=20, choices=RetestStatus.choices,
        default=RetestStatus.NOT_RETESTED,
    )
    retest_date = models.DateField(null=True, blank=True)
    retest_notes = models.TextField(blank=True)
    retested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='retested_findings',
    )

    # Review / approval workflow
    review_state = models.CharField(
        max_length=20, choices=ReviewState.choices, default=ReviewState.DRAFT,
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='reviewed_findings',
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(
        blank=True, help_text='Reviewer feedback — visible on "Changes requested".',
    )

    # SLA — remediation deadline driven by severity
    due_date = models.DateField(null=True, blank=True)

    # Days allowed to remediate, per severity. Clock starts at discovery.
    SLA_DAYS = {
        'critical': 7,
        'high': 14,
        'medium': 30,
        'low': 60,
        'info': 90,
    }

    # Statuses where the SLA clock has stopped — they're closed, not overdue
    SLA_CLOSED_STATUSES = frozenset(('remediated', 'false_positive', 'accepted'))

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.title}"

    def get_absolute_url(self):
        return reverse('vulns:detail', kwargs={'pk': self.pk})

    @property
    def is_overdue(self):
        if not self.due_date or self.status in self.SLA_CLOSED_STATUSES:
            return False
        return self.due_date < timezone.now().date()

    @property
    def days_until_due(self):
        if not self.due_date:
            return None
        return (self.due_date - timezone.now().date()).days

    @property
    def overdue_days(self):
        """Positive number of days overdue, or 0 if on track."""
        if not self.is_overdue:
            return 0
        return (timezone.now().date() - self.due_date).days

    @property
    def sla_status(self):
        """Return 'closed', 'overdue', 'due_soon' (≤3 days), or 'on_track'."""
        if self.status in self.SLA_CLOSED_STATUSES:
            return 'closed'
        if not self.due_date:
            return 'on_track'
        days = self.days_until_due
        if days < 0:
            return 'overdue'
        if days <= 3:
            return 'due_soon'
        return 'on_track'

    @property
    def severity_color(self):
        return {
            'critical': '#E24B4A',
            'high': '#D85A30',
            'medium': '#EF9F27',
            'low': '#378ADD',
            'info': '#888780',
        }.get(self.severity, '#888780')

    # Map from vector abbreviation → (model field name, allowed value set)
    CVSS_VECTOR_MAP = {
        'AV': ('attack_vector', {'N', 'A', 'L', 'P'}),
        'AC': ('attack_complexity', {'L', 'H'}),
        'PR': ('privileges_required', {'N', 'L', 'H'}),
        'UI': ('user_interaction', {'N', 'R'}),
        'S':  ('scope', {'U', 'C'}),
        'C':  ('confidentiality_impact', {'H', 'L', 'N'}),
        'I':  ('integrity_impact', {'H', 'L', 'N'}),
        'A':  ('availability_impact', {'H', 'L', 'N'}),
    }

    @classmethod
    def parse_cvss_vector(cls, vector_string):
        """Parse a CVSS:3.1 vector string into a dict of model field values.

        Raises ValueError on malformed input. Accepts partial vectors — unknown
        or missing metrics are simply not returned. Example input:
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        """
        if not vector_string:
            raise ValueError('Empty vector string.')
        parts = [p.strip() for p in vector_string.strip().split('/') if p.strip()]
        if not parts or not parts[0].upper().startswith('CVSS:3'):
            raise ValueError('Vector must start with CVSS:3.x')
        out = {}
        for part in parts[1:]:
            if ':' not in part:
                raise ValueError(f'Malformed metric: "{part}"')
            key, value = part.split(':', 1)
            mapping = cls.CVSS_VECTOR_MAP.get(key.upper())
            if not mapping:
                continue
            field, allowed = mapping
            if value.upper() not in allowed:
                raise ValueError(f'Invalid value "{value}" for {key}')
            out[field] = value.upper()
        return out

    @property
    def cvss_vector_string(self):
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:{self.scope}/C:{self.confidentiality_impact}"
            f"/I:{self.integrity_impact}/A:{self.availability_impact}"
        )

    def calculate_cvss(self):
        """Calculate CVSS v3.1 base score.

        Follows the official spec at https://www.first.org/cvss/v3.1/specification-document
        Supports both Scope:Unchanged and Scope:Changed.
        """
        import math

        av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
        ac_scores = {'L': 0.77, 'H': 0.44}
        # PR weights depend on Scope: Changed uses higher values
        pr_scores_unchanged = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        pr_scores_changed = {'N': 0.85, 'L': 0.68, 'H': 0.50}
        ui_scores = {'N': 0.85, 'R': 0.62}
        impact_scores = {'H': 0.56, 'L': 0.22, 'N': 0.0}

        scope_changed = self.scope == 'C'
        pr_scores = pr_scores_changed if scope_changed else pr_scores_unchanged

        iss = 1 - (
            (1 - impact_scores[self.confidentiality_impact])
            * (1 - impact_scores[self.integrity_impact])
            * (1 - impact_scores[self.availability_impact])
        )

        if iss <= 0:
            self.cvss_score = 0.0
            return self.cvss_score

        # Impact formula differs by Scope
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        exploitability = (
            8.22
            * av_scores[self.attack_vector]
            * ac_scores[self.attack_complexity]
            * pr_scores[self.privileges_required]
            * ui_scores[self.user_interaction]
        )

        if impact <= 0:
            self.cvss_score = 0.0
            return self.cvss_score

        raw = impact + exploitability
        if scope_changed:
            raw *= 1.08
        score = min(raw, 10.0)

        # Official CVSS Roundup: operates in integer arithmetic at 100000
        # precision to tolerate floating-point error (spec §7.1).
        int_input = round(score * 100000)
        if int_input % 10000 == 0:
            self.cvss_score = int_input / 100000.0
        else:
            self.cvss_score = (math.floor(int_input / 10000) + 1) / 10.0
        return self.cvss_score

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Snapshot severity so save() can tell whether it actually changed
        # before overwriting a manually-adjusted due_date.
        self._loaded_severity = self.severity

    @classmethod
    def from_db(cls, db, field_names, values):
        instance = super().from_db(db, field_names, values)
        instance._loaded_severity = instance.severity
        return instance

    def save(self, *args, **kwargs):
        self.calculate_cvss()
        # Auto-set severity from CVSS
        if self.cvss_score >= 9.0:
            self.severity = 'critical'
        elif self.cvss_score >= 7.0:
            self.severity = 'high'
        elif self.cvss_score >= 4.0:
            self.severity = 'medium'
        elif self.cvss_score >= 0.1:
            self.severity = 'low'
        else:
            self.severity = 'info'
        # SLA due date — (re)compute on create or when severity changes.
        # Don't clobber a manually-set due_date when severity is unchanged.
        severity_changed = self.severity != getattr(self, '_loaded_severity', None)
        if self._state.adding or severity_changed or self.due_date is None:
            base_date = self.created_at.date() if self.created_at else timezone.now().date()
            self.due_date = base_date + timedelta(days=self.SLA_DAYS.get(self.severity, 90))
        super().save(*args, **kwargs)
        self._loaded_severity = self.severity


class FindingTemplate(models.Model):
    """Pre-built vulnerability templates for common finding types."""
    name = models.CharField(max_length=200, unique=True)
    title = models.CharField(max_length=300)
    severity = models.CharField(max_length=20, choices=Finding.Severity.choices)
    description = models.TextField()
    remediation = models.TextField(blank=True)
    references = models.TextField(blank=True)
    cwe_id = models.CharField(max_length=20, blank=True)
    # CVSS defaults
    attack_vector = models.CharField(max_length=1, default='N')
    attack_complexity = models.CharField(max_length=1, default='L')
    privileges_required = models.CharField(max_length=1, default='N')
    user_interaction = models.CharField(max_length=1, default='N')
    scope = models.CharField(max_length=1, default='U')
    confidentiality_impact = models.CharField(max_length=1, default='N')
    integrity_impact = models.CharField(max_length=1, default='N')
    availability_impact = models.CharField(max_length=1, default='N')

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class Evidence(models.Model):
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='evidence')
    file = models.FileField(upload_to='evidence/%Y/%m/', storage=protected_storage)
    caption = models.CharField(max_length=300, blank=True)
    uploaded_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = 'evidence'

    def __str__(self):
        return self.caption or self.file.name

    @property
    def is_image(self):
        return self.file.name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))

