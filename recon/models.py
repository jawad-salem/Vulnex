from django.db import models
from django.conf import settings
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

