"""Seed the database with a demo engagement so reviewers can see a populated UI
immediately after `docker-compose up`.

Idempotent: if the demo engagement already exists, the command does nothing.
Safe to re-run. Use --force to wipe and recreate.
"""

from datetime import timedelta
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from accounts.models import User
from engagements.models import Engagement, EngagementMember


DEMO_ENGAGEMENT_NAME = 'Acme Corp — Q2 External Pentest'
DEMO_CLIENT = 'Acme Corporation'


class Command(BaseCommand):
    help = 'Seed a demo engagement with realistic fake data for showcase purposes.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force', action='store_true',
            help='Delete existing demo engagement and recreate it.',
        )

    @transaction.atomic
    def handle(self, *args, **opts):
        existing = Engagement.objects.filter(name=DEMO_ENGAGEMENT_NAME).first()
        if existing:
            if not opts['force']:
                self.stdout.write(self.style.WARNING(
                    f'Demo engagement "{DEMO_ENGAGEMENT_NAME}" already exists. '
                    f'Re-run with --force to wipe and recreate.'
                ))
                return
            existing.delete()
            self.stdout.write(f'Deleted existing demo engagement.')

        owner = self._get_or_create_owner()
        engagement = self._create_engagement(owner)
        self._add_members(engagement, owner)
        self._create_findings(engagement)
        self._create_hosts(engagement)

        self.stdout.write(self.style.SUCCESS(
            f'Seeded demo engagement: {engagement.name} (id={engagement.pk})'
        ))
        self.stdout.write(
            f'Log in as "{owner.username}" (password: demo-password) to explore.'
        )

    def _get_or_create_owner(self):
        owner, created = User.objects.get_or_create(
            username='demo-lead',
            defaults={
                'email': 'demo-lead@example.com',
                'first_name': 'Alex',
                'last_name': 'Chen',
                'role': 'pentester',
                'is_staff': False,
            },
        )
        if created:
            owner.set_password('demo-password')
            owner.save()
        return owner

    def _create_engagement(self, owner):
        today = timezone.now().date()
        return Engagement.objects.create(
            name=DEMO_ENGAGEMENT_NAME,
            client_name=DEMO_CLIENT,
            engagement_type=Engagement.EngagementType.EXTERNAL,
            status=Engagement.Status.EXPLOITATION,
            description=(
                'External black-box penetration test of Acme\'s public-facing '
                'web application and supporting infrastructure. Objectives: '
                'identify exploitable vulnerabilities, assess data-exposure '
                'risk, and validate the organization\'s external attack surface.'
            ),
            in_scope=(
                'app.acme.example\n'
                'api.acme.example\n'
                'www.acme.example\n'
                '203.0.113.0/28'
            ),
            out_of_scope=(
                'staging.acme.example\n'
                'Denial-of-service testing\n'
                'Social engineering against employees'
            ),
            rules_of_engagement=(
                'Testing window: 09:00 – 18:00 UTC, weekdays only.\n'
                'Primary contact: security@acme.example.\n'
                'Do not exfiltrate production data — proof-of-concept only.'
            ),
            start_date=today - timedelta(days=6),
            end_date=today + timedelta(days=8),
            created_by=owner,
        )

    def _add_members(self, engagement, owner):
        EngagementMember.objects.create(
            engagement=engagement, user=owner,
            role=EngagementMember.Role.LEAD,
        )

        reviewer, created = User.objects.get_or_create(
            username='demo-reviewer',
            defaults={
                'email': 'demo-reviewer@example.com',
                'first_name': 'Priya',
                'last_name': 'Rao',
                'role': 'reviewer',
            },
        )
        if created:
            reviewer.set_password('demo-password')
            reviewer.save()
        EngagementMember.objects.create(
            engagement=engagement, user=reviewer,
            role=EngagementMember.Role.REVIEWER,
        )

    def _create_findings(self, engagement):
        from vulns.models import Finding

        findings = [
            {
                'title': 'SQL Injection in product search endpoint',
                'severity': Finding.Severity.CRITICAL,
                'host': 'api.acme.example', 'port': 443,
                'url': 'https://api.acme.example/v2/products/search',
                'http_method': 'GET', 'parameter': 'q',
                'attack_vector': 'N', 'attack_complexity': 'L',
                'privileges_required': 'N', 'user_interaction': 'N',
                'confidentiality_impact': 'H', 'integrity_impact': 'H', 'availability_impact': 'H',
                'description': (
                    'The `q` query parameter on the product-search endpoint is '
                    'concatenated directly into a SQL query. Union-based '
                    'injection allows extraction of the full users table, '
                    'including bcrypt password hashes.'
                ),
                'remediation': (
                    'Use parameterized queries or a query builder. Audit all '
                    'other endpoints for similar patterns. Rotate any '
                    'credentials that may have been exposed in the database.'
                ),
            },
            {
                'title': 'Stored XSS in customer review widget',
                'severity': Finding.Severity.HIGH,
                'host': 'www.acme.example', 'port': 443,
                'url': 'https://www.acme.example/products/42/reviews',
                'http_method': 'POST', 'parameter': 'body',
                'attack_vector': 'N', 'attack_complexity': 'L',
                'privileges_required': 'L', 'user_interaction': 'R',
                'scope': 'C',
                'confidentiality_impact': 'L', 'integrity_impact': 'L', 'availability_impact': 'N',
                'description': (
                    'Customer review submissions are rendered without '
                    'encoding, allowing stored script injection that '
                    'executes for every user viewing the product page.'
                ),
                'remediation': (
                    'Apply context-aware HTML encoding on render. Enable a '
                    'restrictive Content-Security-Policy for the reviews area.'
                ),
            },
            {
                'title': 'Missing rate limiting on login endpoint',
                'severity': Finding.Severity.MEDIUM,
                'host': 'app.acme.example', 'port': 443,
                'url': 'https://app.acme.example/login',
                'http_method': 'POST',
                'attack_vector': 'N', 'attack_complexity': 'L',
                'privileges_required': 'N', 'user_interaction': 'N',
                'confidentiality_impact': 'L', 'integrity_impact': 'N', 'availability_impact': 'N',
                'description': (
                    'No rate limiting is enforced on the login endpoint. A '
                    'brute-force attack succeeded with a dictionary of 10,000 '
                    'common passwords against a test account.'
                ),
                'remediation': (
                    'Apply per-IP and per-account rate limiting. Lock accounts '
                    'after N failed attempts. Log failures for SOC review.'
                ),
            },
            {
                'title': 'Verbose error responses leak stack traces',
                'severity': Finding.Severity.LOW,
                'host': 'api.acme.example', 'port': 443,
                'attack_vector': 'N', 'attack_complexity': 'L',
                'privileges_required': 'N', 'user_interaction': 'N',
                'confidentiality_impact': 'L', 'integrity_impact': 'N', 'availability_impact': 'N',
                'description': (
                    'Triggering unhandled exceptions returns a full Python '
                    'stack trace including file paths and framework versions.'
                ),
                'remediation': (
                    'Set `DEBUG=False` in production. Return opaque 500 '
                    'responses and log full traces server-side.'
                ),
            },
            {
                'title': 'HSTS header missing on primary domain',
                'severity': Finding.Severity.INFO,
                'host': 'www.acme.example', 'port': 443,
                'attack_vector': 'N', 'attack_complexity': 'H',
                'privileges_required': 'N', 'user_interaction': 'R',
                'confidentiality_impact': 'L', 'integrity_impact': 'L', 'availability_impact': 'N',
                'description': (
                    '`Strict-Transport-Security` is not set. Clients on a '
                    'hostile network could be downgraded to HTTP before the '
                    'first redirect.'
                ),
                'remediation': (
                    'Add `Strict-Transport-Security: max-age=31536000; '
                    'includeSubDomains; preload` and submit to the HSTS '
                    'preload list.'
                ),
            },
        ]

        for data in findings:
            f = Finding(engagement=engagement, **data)
            if hasattr(f, 'calculate_cvss_score'):
                f.calculate_cvss_score()
            f.save()

    def _create_hosts(self, engagement):
        try:
            from recon.models import DiscoveredHost
        except ImportError:
            return

        hosts = [
            {'hostname': 'app.acme.example', 'ip_address': '203.0.113.4',
             'notes': 'Primary customer portal, load-balanced behind Cloudflare.'},
            {'hostname': 'api.acme.example', 'ip_address': '203.0.113.7',
             'notes': 'Public REST API, v2 endpoints in production.'},
            {'hostname': 'www.acme.example', 'ip_address': '203.0.113.10',
             'notes': 'Marketing site, WordPress.'},
        ]
        for h in hosts:
            DiscoveredHost.objects.create(engagement=engagement, **h)
