"""Populate the database with a realistic demo so a fresh `docker compose up`
lands on a populated UI instead of empty tables.

Idempotent: re-running this command after a successful seed is a no-op (the
demo client + named engagements already exist). Use --force to wipe and
recreate the demo data only.
"""

from datetime import timedelta
from io import BytesIO

from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from accounts.models import AuditLog
from engagements.models import (
    ActivityLog, AttackPath, AttackPathEdge, AttackPathNode,
    Client, Engagement, EngagementMember,
)


DEMO_CLIENT_NAME = 'Acme Corporation'
DEMO_ENGAGEMENTS = [
    'Acme Corp — Q2 External Pentest',
    'Acme Corp — Red Team Adversary Simulation',
]

# 1×1 transparent PNG. Used as the placeholder image for demo evidence so the
# evidence list/detail page is populated without bundling a real screenshot.
PLACEHOLDER_PNG = bytes.fromhex(
    '89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4'
    '890000000d49444154789c63000000050001a5f6450c0000000049454e44ae42'
    '6082'
)

USERS = [
    # username, role, first, last, password
    ('demo-admin',     'admin',     'Avery',  'Hart',  'demo-password'),
    ('demo-pentester', 'pentester', 'Alex',   'Chen',  'demo-password'),
    ('demo-reviewer',  'reviewer',  'Priya',  'Rao',   'demo-password'),
    ('demo-client',    'client',    'Jordan', 'Park',  'demo-password'),
]


class Command(BaseCommand):
    help = 'Seed a populated demo (client, engagements, users, findings, evidence, report, logs).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force', action='store_true',
            help='Delete existing demo data and recreate it.',
        )

    @transaction.atomic
    def handle(self, *args, **opts):
        if opts['force']:
            self._wipe()

        if Engagement.objects.filter(name__in=DEMO_ENGAGEMENTS).exists():
            self.stdout.write(self.style.WARNING(
                'Demo engagements already present — nothing to do. '
                'Re-run with --force to wipe and recreate.'
            ))
            return

        users = self._seed_users()
        client = self._seed_client()
        external = self._seed_external_engagement(client, users)
        red_team = self._seed_red_team_engagement(client, users)
        self._seed_findings_and_evidence(external, red_team, users)
        self._seed_recon_hosts(external, red_team)
        self._seed_attack_path(red_team, users)
        self._seed_activity_logs(external, red_team, users)
        self._seed_report(external, users)

        self.stdout.write(self.style.SUCCESS('Demo data seeded.'))
        self.stdout.write(
            'Sign in with any of:\n'
            '  demo-admin / demo-password (platform admin)\n'
            '  demo-pentester / demo-password (engagement lead + pentester)\n'
            '  demo-reviewer / demo-password (engagement reviewer)\n'
            '  demo-client / demo-password (client read-only)'
        )

    # ── lifecycle ────────────────────────────────────────────────────────

    def _wipe(self):
        Engagement.objects.filter(name__in=DEMO_ENGAGEMENTS).delete()
        Client.objects.filter(name=DEMO_CLIENT_NAME).delete()
        get_user_model().objects.filter(
            username__in=[u[0] for u in USERS]
        ).delete()
        self.stdout.write('Wiped existing demo data.')

    # ── users ────────────────────────────────────────────────────────────

    def _seed_users(self):
        User = get_user_model()
        out = {}
        for username, role, first, last, password in USERS:
            user, created = User.objects.get_or_create(
                username=username,
                defaults={
                    'email': f'{username}@example.com',
                    'first_name': first,
                    'last_name': last,
                    'role': role,
                    'is_staff': role == 'admin',
                    'is_superuser': False,
                },
            )
            if created:
                user.set_password(password)
                user.save()
                AuditLog.record(
                    actor=None,
                    action=AuditLog.Action.USER_CREATE,
                    target=user.username,
                    details={'source': 'seed_demo'},
                )
            out[role] = user
        return out

    # ── client + engagements ─────────────────────────────────────────────

    def _seed_client(self):
        client, _ = Client.objects.get_or_create(
            name=DEMO_CLIENT_NAME,
            defaults={
                'primary_contact_email': 'security@acme.example',
                'notes': (
                    'Long-standing demo client. Two open engagements covering '
                    'external surface and a red-team adversary simulation.'
                ),
            },
        )
        return client

    def _seed_external_engagement(self, client, users):
        today = timezone.now().date()
        eng = Engagement.objects.create(
            name=DEMO_ENGAGEMENTS[0],
            client=client,
            engagement_type=Engagement.EngagementType.EXTERNAL,
            status=Engagement.Status.EXPLOITATION,
            description=(
                'External black-box penetration test of Acme\'s public-facing '
                'web application and supporting infrastructure.'
            ),
            in_scope='app.acme.example\napi.acme.example\nwww.acme.example\n203.0.113.0/28',
            out_of_scope='staging.acme.example\nDenial-of-service testing\nSocial engineering',
            rules_of_engagement=(
                'Testing window: 09:00 – 18:00 UTC, weekdays only.\n'
                'Primary contact: security@acme.example.\n'
                'Do not exfiltrate production data — proof-of-concept only.'
            ),
            start_date=today - timedelta(days=6),
            end_date=today + timedelta(days=8),
            created_by=users['pentester'],
        )
        EngagementMember.objects.create(
            engagement=eng, user=users['pentester'],
            role=EngagementMember.Role.LEAD,
        )
        EngagementMember.objects.create(
            engagement=eng, user=users['reviewer'],
            role=EngagementMember.Role.REVIEWER,
        )
        EngagementMember.objects.create(
            engagement=eng, user=users['client'],
            role=EngagementMember.Role.CLIENT,
        )
        return eng

    def _seed_red_team_engagement(self, client, users):
        today = timezone.now().date()
        eng = Engagement.objects.create(
            name=DEMO_ENGAGEMENTS[1],
            client=client,
            engagement_type=Engagement.EngagementType.RED_TEAM,
            status=Engagement.Status.POST_EXPLOIT,
            description=(
                'Red-team adversary simulation against Acme\'s internal estate. '
                'Goals: validate detection coverage and reach Domain Admin from '
                'an assumed-breach starting position.'
            ),
            in_scope='internal.acme.example\nAcme corporate AD forest',
            out_of_scope='Production database servers (exfil only — no destructive ops)',
            rules_of_engagement=(
                'Assumed-breach scenario starting from a workstation foothold.\n'
                'No ransomware, no destructive payloads.\n'
                'Detection-team is unaware of testing window.'
            ),
            start_date=today - timedelta(days=18),
            end_date=today + timedelta(days=4),
            created_by=users['pentester'],
        )
        EngagementMember.objects.create(
            engagement=eng, user=users['pentester'],
            role=EngagementMember.Role.LEAD,
        )
        EngagementMember.objects.create(
            engagement=eng, user=users['reviewer'],
            role=EngagementMember.Role.REVIEWER,
        )
        return eng

    # ── findings + evidence ──────────────────────────────────────────────

    def _seed_findings_and_evidence(self, external, red_team, users):
        from vulns.models import Evidence, Finding

        seeds = [
            # External — 6 findings, all severities + 1 extra
            dict(
                engagement=external,
                title='SQL Injection in product search endpoint',
                severity=Finding.Severity.CRITICAL,
                status=Finding.Status.CONFIRMED,
                review_state=Finding.ReviewState.APPROVED,
                host='api.acme.example', port=443,
                url='https://api.acme.example/v2/products/search',
                http_method='GET', parameter='q',
                attack_vector='N', attack_complexity='L',
                privileges_required='N', user_interaction='N',
                confidentiality_impact='H', integrity_impact='H', availability_impact='H',
                description=(
                    'The `q` query parameter on the product-search endpoint is '
                    'concatenated directly into a SQL query. Union-based '
                    'injection allows extraction of the full users table, '
                    'including bcrypt password hashes.'
                ),
                proof_of_concept=(
                    "GET /v2/products/search?q=foo'%20UNION%20SELECT%20username,password_hash%20FROM%20users--\n"
                    'Server returns a JSON body with rows from the users table.'
                ),
                remediation=(
                    'Use parameterized queries or a query builder. Audit all '
                    'other endpoints for similar patterns. Rotate any '
                    'credentials that may have been exposed.'
                ),
                attach_evidence=True,
            ),
            dict(
                engagement=external,
                title='Stored XSS in customer review widget',
                severity=Finding.Severity.HIGH,
                status=Finding.Status.CONFIRMED,
                review_state=Finding.ReviewState.IN_REVIEW,
                host='www.acme.example', port=443,
                url='https://www.acme.example/products/42/reviews',
                http_method='POST', parameter='body',
                attack_vector='N', attack_complexity='L',
                privileges_required='L', user_interaction='R',
                scope='C',
                confidentiality_impact='L', integrity_impact='L', availability_impact='N',
                description=(
                    'Customer review submissions are rendered without '
                    'encoding, allowing stored script injection that '
                    'executes for every user viewing the product page.'
                ),
                remediation=(
                    'Apply context-aware HTML encoding on render. Enable a '
                    'restrictive Content-Security-Policy for the reviews area.'
                ),
                attach_evidence=True,
            ),
            dict(
                engagement=external,
                title='Missing rate limiting on login endpoint',
                severity=Finding.Severity.MEDIUM,
                status=Finding.Status.OPEN,
                review_state=Finding.ReviewState.DRAFT,
                host='app.acme.example', port=443,
                url='https://app.acme.example/login',
                http_method='POST',
                attack_vector='N', attack_complexity='L',
                privileges_required='N', user_interaction='N',
                confidentiality_impact='L', integrity_impact='N', availability_impact='N',
                description=(
                    'No rate limiting is enforced on the login endpoint. A '
                    'brute-force attack succeeded with a dictionary of 10,000 '
                    'common passwords against a test account.'
                ),
                remediation=(
                    'Apply per-IP and per-account rate limiting. Lock accounts '
                    'after N failed attempts. Log failures for SOC review.'
                ),
            ),
            dict(
                engagement=external,
                title='Verbose error responses leak stack traces',
                severity=Finding.Severity.LOW,
                status=Finding.Status.OPEN,
                review_state=Finding.ReviewState.DRAFT,
                host='api.acme.example', port=443,
                attack_vector='N', attack_complexity='L',
                privileges_required='N', user_interaction='N',
                confidentiality_impact='L', integrity_impact='N', availability_impact='N',
                description=(
                    'Triggering unhandled exceptions returns a full Python '
                    'stack trace including file paths and framework versions.'
                ),
                remediation='Set `DEBUG=False` in production. Return opaque 500 responses.',
            ),
            dict(
                engagement=external,
                title='HSTS header missing on primary domain',
                severity=Finding.Severity.INFO,
                status=Finding.Status.OPEN,
                review_state=Finding.ReviewState.DRAFT,
                host='www.acme.example', port=443,
                attack_vector='N', attack_complexity='H',
                privileges_required='N', user_interaction='R',
                confidentiality_impact='L', integrity_impact='L', availability_impact='N',
                description=(
                    '`Strict-Transport-Security` is not set. Clients on a '
                    'hostile network could be downgraded to HTTP before the '
                    'first redirect.'
                ),
                remediation='Add HSTS with preload and submit to the HSTS preload list.',
            ),
            dict(
                engagement=external,
                title='Authenticated SSRF in image-resize endpoint',
                severity=Finding.Severity.HIGH,
                status=Finding.Status.CONFIRMED,
                review_state=Finding.ReviewState.APPROVED,
                host='api.acme.example', port=443,
                url='https://api.acme.example/v2/images/resize',
                http_method='POST', parameter='source_url',
                attack_vector='N', attack_complexity='L',
                privileges_required='L', user_interaction='N',
                confidentiality_impact='H', integrity_impact='L', availability_impact='N',
                description=(
                    'The `source_url` parameter is fetched server-side without '
                    'allowlisting. An attacker can reach 169.254.169.254 and '
                    'exfiltrate cloud instance metadata credentials.'
                ),
                remediation=(
                    'Allowlist hostnames; resolve DNS once and re-validate the '
                    'IP literal isn\'t in a private/loopback/link-local range.'
                ),
                attach_evidence=True,
            ),
            # Red team — 2 findings to round out 8 total
            dict(
                engagement=red_team,
                title='Kerberoastable service account with weak password',
                severity=Finding.Severity.CRITICAL,
                status=Finding.Status.CONFIRMED,
                review_state=Finding.ReviewState.APPROVED,
                host='dc01.internal.acme.example', port=88,
                attack_vector='N', attack_complexity='L',
                privileges_required='L', user_interaction='N',
                confidentiality_impact='H', integrity_impact='H', availability_impact='H',
                description=(
                    'Service account `svc_sql` has a non-randomised password '
                    'and is registered with an SPN, allowing offline cracking '
                    'of its TGS to recover plaintext credentials.'
                ),
                remediation=(
                    'Randomise the service account password to ≥ 25 characters '
                    'or migrate to a Group Managed Service Account (gMSA).'
                ),
            ),
            dict(
                engagement=red_team,
                title='Unconstrained delegation on file server',
                severity=Finding.Severity.HIGH,
                status=Finding.Status.OPEN,
                review_state=Finding.ReviewState.IN_REVIEW,
                host='fs01.internal.acme.example', port=445,
                attack_vector='N', attack_complexity='H',
                privileges_required='H', user_interaction='N',
                confidentiality_impact='H', integrity_impact='H', availability_impact='L',
                description=(
                    'FS01 is configured for unconstrained Kerberos delegation. '
                    'An attacker who compromises this host can capture TGTs of '
                    'any user that authenticates to it, including domain admins.'
                ),
                remediation=(
                    'Switch to constrained delegation, scoped to the specific '
                    'services FS01 actually needs to impersonate users to.'
                ),
            ),
        ]

        for data in seeds:
            attach_evidence = data.pop('attach_evidence', False)
            f = Finding(**data)
            if hasattr(f, 'calculate_cvss_score'):
                f.calculate_cvss_score()
            f.save()
            if attach_evidence:
                ev = Evidence(
                    finding=f,
                    caption='Request/response capture (placeholder)',
                    uploaded_by=users['pentester'],
                )
                ev.file.save(
                    f'demo_{f.pk}.png',
                    ContentFile(PLACEHOLDER_PNG),
                    save=True,
                )

    # ── recon ────────────────────────────────────────────────────────────

    def _seed_recon_hosts(self, external, red_team):
        from recon.models import DiscoveredHost

        for h in [
            ('app.acme.example', '203.0.113.4',
             'Primary customer portal, load-balanced behind Cloudflare.'),
            ('api.acme.example', '203.0.113.7',
             'Public REST API, v2 endpoints in production.'),
            ('www.acme.example', '203.0.113.10',
             'Marketing site, WordPress.'),
            ('staging.acme.example', '203.0.113.42',
             'Out of scope. Discovered during enumeration.'),
        ]:
            DiscoveredHost.objects.create(
                engagement=external,
                hostname=h[0], ip_address=h[1], notes=h[2],
            )
        for h in [
            ('dc01.internal.acme.example', '10.10.0.10',
             'Primary domain controller. Forest root.'),
            ('fs01.internal.acme.example', '10.10.0.42',
             'File server with unconstrained delegation enabled.'),
            ('ws-pentest.internal.acme.example', '10.10.5.99',
             'Assumed-breach foothold workstation.'),
        ]:
            DiscoveredHost.objects.create(
                engagement=red_team,
                hostname=h[0], ip_address=h[1], notes=h[2],
            )

    # ── attack path (red team only) ──────────────────────────────────────

    def _seed_attack_path(self, red_team, users):
        path = AttackPath.objects.create(
            engagement=red_team,
            name='Workstation → Domain Admin',
            description=(
                'Reference kill-chain mapping initial foothold to Domain Admin '
                'via Kerberoasting and unconstrained-delegation abuse.'
            ),
            created_by=users['pentester'],
        )
        n_entry = AttackPathNode.objects.create(
            path=path, label='Phished employee laptop',
            kind=AttackPathNode.Kind.ENTRYPOINT,
        )
        n_ws = AttackPathNode.objects.create(
            path=path, label='ws-pentest.internal.acme.example',
            kind=AttackPathNode.Kind.HOST,
        )
        n_svc = AttackPathNode.objects.create(
            path=path, label='svc_sql (kerberoastable)',
            kind=AttackPathNode.Kind.IDENTITY,
        )
        n_fs = AttackPathNode.objects.create(
            path=path, label='fs01 (unconstrained delegation)',
            kind=AttackPathNode.Kind.HOST,
        )
        n_da = AttackPathNode.objects.create(
            path=path, label='Domain Admin (CONTOSO\\Administrator)',
            kind=AttackPathNode.Kind.OBJECTIVE,
        )
        AttackPathEdge.objects.create(
            path=path, from_node=n_entry, to_node=n_ws,
            technique='Initial Access via spear-phish', mitre_attack_id='T1566.001',
        )
        AttackPathEdge.objects.create(
            path=path, from_node=n_ws, to_node=n_svc,
            technique='Kerberoasting', mitre_attack_id='T1558.003',
        )
        AttackPathEdge.objects.create(
            path=path, from_node=n_svc, to_node=n_fs,
            technique='Lateral movement via SMB', mitre_attack_id='T1021.002',
        )
        AttackPathEdge.objects.create(
            path=path, from_node=n_fs, to_node=n_da,
            technique='Unconstrained delegation TGT capture', mitre_attack_id='T1558',
        )

    # ── activity log ─────────────────────────────────────────────────────

    def _seed_activity_logs(self, external, red_team, users):
        for eng, user, action, details in [
            (external, users['pentester'], 'Engagement created',
                {'name': external.name}),
            (external, users['pentester'], 'Recon scan completed',
                {'tool': 'nmap', 'targets': 4}),
            (external, users['pentester'], 'Finding submitted for review',
                {'count': 3}),
            (external, users['reviewer'], 'Finding approved',
                {'finding_title': 'SQL Injection in product search endpoint'}),
            (red_team, users['pentester'], 'Engagement created',
                {'name': red_team.name}),
            (red_team, users['pentester'], 'Attack path created',
                {'name': 'Workstation → Domain Admin'}),
        ]:
            ActivityLog.objects.create(
                engagement=eng, user=user, action=action, details=details,
            )

    # ── report ───────────────────────────────────────────────────────────

    def _seed_report(self, engagement, users):
        from reports.models import Report
        from reports.generator import generate_report_pdf

        try:
            pdf_bytes = generate_report_pdf(engagement, report_type='full')
        except Exception as exc:
            self.stdout.write(self.style.WARNING(
                f'Skipped PDF generation in seed_demo: {exc}'
            ))
            return

        report = Report.objects.create(
            engagement=engagement,
            title=f'{engagement.name} — Full Report',
            report_type=Report.ReportType.FULL,
            generated_by=users['pentester'],
        )
        report.file.save(
            f'demo_{engagement.pk}.pdf',
            ContentFile(pdf_bytes),
            save=True,
        )
        AuditLog.record(
            actor=users['pentester'],
            action=AuditLog.Action.REPORT_GENERATED,
            target=str(engagement.pk),
            details={'report_id': str(report.pk), 'source': 'seed_demo'},
        )
