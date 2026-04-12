from django.db import models
from django.conf import settings
from django.utils import timezone
from engagements.models import Engagement
import uuid


class ReconScan(models.Model):
    class ScanType(models.TextChoices):
        PORT_SCAN = 'port_scan', 'Port Scan'
        SUBDOMAIN = 'subdomain', 'Subdomain Enumeration'
        TECH_DETECT = 'tech_detect', 'Technology Detection'
        DIR_BRUTE = 'dir_brute', 'Directory Bruteforce'
        DNS_ENUM = 'dns_enum', 'DNS Enumeration'
        WHOIS = 'whois', 'WHOIS Lookup'

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='scans')
    scan_type = models.CharField(max_length=20, choices=ScanType.choices)
    target = models.CharField(max_length=500)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    options = models.JSONField(default=dict, blank=True, help_text='Scan options as JSON')

    # Results
    raw_output = models.TextField(blank=True)
    parsed_results = models.JSONField(default=list, blank=True)
    error_message = models.TextField(blank=True)

    # Meta
    started_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self) -> str:
        return f"{self.get_scan_type_display()} — {self.target}"  # type: ignore[attr-defined]

    @property
    def duration(self):
        if self.started_at and self.completed_at:
            delta = self.completed_at - self.started_at
            return str(delta).split('.')[0]
        return None

    @property
    def result_count(self):
        if isinstance(self.parsed_results, list):
            return len(self.parsed_results)
        return 0


class DiscoveredHost(models.Model):
    """Hosts/subdomains discovered during recon."""
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='discovered_hosts')
    scan = models.ForeignKey(ReconScan, on_delete=models.CASCADE, related_name='hosts', null=True)
    hostname = models.CharField(max_length=500)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    ports = models.JSONField(default=list, blank=True)
    technologies = models.JSONField(default=list, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['hostname']
        unique_together = ['engagement', 'hostname']

    def __str__(self):
        return self.hostname


class ScheduledScan(models.Model):
    """Recurring scan that runs on a cron schedule via Celery Beat."""

    class Frequency(models.TextChoices):
        HOURLY = 'hourly', 'Every hour'
        DAILY = 'daily', 'Daily'
        WEEKLY = 'weekly', 'Weekly'
        MONTHLY = 'monthly', 'Monthly'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='scheduled_scans')
    scan_type = models.CharField(max_length=20, choices=ReconScan.ScanType.choices)
    target = models.CharField(max_length=500)
    frequency = models.CharField(max_length=20, choices=Frequency.choices, default=Frequency.DAILY)
    is_active = models.BooleanField(default=True)

    # Link to django-celery-beat PeriodicTask
    periodic_task_name = models.CharField(max_length=200, blank=True)

    # Tracking
    last_run = models.DateTimeField(null=True, blank=True)
    run_count = models.PositiveIntegerField(default=0)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"[{self.get_frequency_display()}] {self.get_scan_type_display()} on {self.target}"


class ScanPipeline(models.Model):
    """Chain multiple scan types to run sequentially on a target.
    e.g. subdomain enum → port scan each subdomain → tech detect each host.
    """

    class Status(models.TextChoices):
        PENDING = 'pending', 'Pending'
        RUNNING = 'running', 'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    PIPELINE_PRESETS = {
        'full_recon': {
            'name': 'Full Recon',
            'steps': ['subdomain', 'port_scan', 'tech_detect', 'dir_brute'],
            'description': 'Subdomain enum → Port scan → Tech detect → Dir bruteforce',
        },
        'web_recon': {
            'name': 'Web Recon',
            'steps': ['tech_detect', 'dir_brute'],
            'description': 'Technology detection → Directory bruteforce',
        },
        'network_recon': {
            'name': 'Network Recon',
            'steps': ['dns_enum', 'port_scan', 'whois'],
            'description': 'DNS enumeration → Port scan → WHOIS lookup',
        },
        'subdomain_deep': {
            'name': 'Subdomain Deep Dive',
            'steps': ['subdomain', 'port_scan', 'tech_detect'],
            'description': 'Subdomain enum → Port scan discovered hosts → Tech detect',
        },
    }

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    engagement = models.ForeignKey(Engagement, on_delete=models.CASCADE, related_name='scan_pipelines')
    name = models.CharField(max_length=200)
    target = models.CharField(max_length=500)
    steps = models.JSONField(default=list, help_text='Ordered list of scan_type strings')
    current_step = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)

    # Results tracking
    results_summary = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)

    # Meta
    started_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} — {self.target}"

    @property
    def progress_percent(self):
        if not self.steps:
            return 0
        if self.status == 'completed':
            return 100
        return int((self.current_step / len(self.steps)) * 100)

    @property
    def total_results(self):
        return sum(self.results_summary.get(step, {}).get('count', 0) for step in self.steps)

