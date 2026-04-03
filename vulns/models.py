from django.db import models
from django.conf import settings
from django.urls import reverse
from engagements.models import Engagement
from recon.models import DiscoveredHost
import uuid


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
    tool_source = models.CharField(max_length=100, blank=True, help_text='e.g. Nmap, Burp, Manual')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.get_severity_display()}] {self.title}"

    def get_absolute_url(self):
        return reverse('vulns:detail', kwargs={'pk': self.pk})

    @property
    def severity_color(self):
        return {
            'critical': '#E24B4A',
            'high': '#D85A30',
            'medium': '#EF9F27',
            'low': '#378ADD',
            'info': '#888780',
        }.get(self.severity, '#888780')

    @property
    def cvss_vector_string(self):
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}"
            f"/PR:{self.privileges_required}/UI:{self.user_interaction}"
            f"/S:U/C:{self.confidentiality_impact}/I:{self.integrity_impact}"
            f"/A:{self.availability_impact}"
        )

    def calculate_cvss(self):
        """Calculate CVSS v3.1 base score."""
        av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
        ac_scores = {'L': 0.77, 'H': 0.44}
        pr_scores = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        ui_scores = {'N': 0.85, 'R': 0.62}
        impact_scores = {'H': 0.56, 'L': 0.22, 'N': 0.0}

        iss = 1 - (
            (1 - impact_scores[self.confidentiality_impact])
            * (1 - impact_scores[self.integrity_impact])
            * (1 - impact_scores[self.availability_impact])
        )

        if iss <= 0:
            self.cvss_score = 0.0
            return self.cvss_score

        impact = 6.42 * iss  # Scope Unchanged

        exploitability = (
            8.22
            * av_scores[self.attack_vector]
            * ac_scores[self.attack_complexity]
            * pr_scores[self.privileges_required]
            * ui_scores[self.user_interaction]
        )

        import math
        score = min(impact + exploitability, 10.0)
        self.cvss_score = math.ceil(score * 10) / 10
        return self.cvss_score

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
        super().save(*args, **kwargs)


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
    confidentiality_impact = models.CharField(max_length=1, default='N')
    integrity_impact = models.CharField(max_length=1, default='N')
    availability_impact = models.CharField(max_length=1, default='N')

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name


class Evidence(models.Model):
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name='evidence')
    file = models.FileField(upload_to='evidence/%Y/%m/')
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

