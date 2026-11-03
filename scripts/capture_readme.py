"""Refresh README screenshots from synthetic, disposable data.
Run: python scripts/capture_readme.py (requires requirements-dev.txt and a browser).
"""
import os
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.ui_checks import WorkspaceBrowserChecks
from django.conf import settings
from django.test.runner import DiscoverRunner
from django.urls import reverse
from playwright.sync_api import sync_playwright, expect
from accounts.models import AuditLog
from credentials.models import Credential
from recon.models import DiscoveredHost, ReconScan
from vulns.models import FindingComment


class ReadmeScreenshots(WorkspaceBrowserChecks):
    def test_capture(self):
        # Keep the regression fixture's normal findings, omit pagination stress data.
        self.eng.findings.filter(title__startswith='Cross-account authorization bypass').delete()
        self.empty_engagement.delete()
        self.user.role = 'admin'
        self.user.save(update_fields=['role'])
        self.eng.authorization_reference = 'Client authorization / staging assessment / v1'
        self.eng.out_of_scope = 'production.example.test'
        self.eng.save(update_fields=['authorization_reference', 'out_of_scope'])
        for hostname, address, service in [('api.example.test', '192.0.2.10', 'API gateway'), ('app.example.test', '192.0.2.20', 'Web application')]:
            DiscoveredHost.objects.create(engagement=self.eng, hostname=hostname,
                ip_address=address, ports=[{'port':443, 'protocol':'tcp', 'service':'https'}],
                technologies=[service])
        ReconScan.objects.create(engagement=self.eng, scan_type='port_scan', target='api.example.test', status='completed', started_by=self.user)
        credential = Credential(engagement=self.eng, username='staging-reader', service='Test API', source='Client-provided test account', found_by=self.user)
        credential.set_secret('synthetic-example-only')
        credential.save()
        FindingComment.objects.create(finding=self.finding, author=self.user,
            body='Reproduced with two staging accounts. The evidence contains only synthetic records.', is_review_feedback=True)
        FindingComment.objects.create(finding=self.finding, author=self.user,
            body='Retest after the authorization middleware is deployed. Check both direct access and the export endpoint.', internal_only=True)
        self.finding.evidence.update(request_response='GET /api/records/42 HTTP/1.1\nHost: api.example.test\n\nHTTP/1.1 200 OK\n{"record": "synthetic sample"}')
        self.eng.reports.update(title='Staging assessment - technical report')
        for action, target in [(AuditLog.Action.LOGIN_SUCCESS, 'Alex'), (AuditLog.Action.REPORT_DOWNLOADED, 'Staging assessment'), (AuditLog.Action.EVIDENCE_DOWNLOAD, 'Sanitized response')]:
            AuditLog.record(actor=self.user, action=action, target=target)
        pages = [
            ('01-dashboard', reverse('dashboard:home'), None),
            ('02-engagement', reverse('engagements:detail', args=[self.eng.pk]), None),
            ('03-scope-roe', reverse('engagements:detail', args=[self.eng.pk]), 'scope'),
            ('04-recon', reverse('recon:dashboard', args=[self.eng.pk]), None),
            ('05-methodology', reverse('methodology:dashboard', args=[self.eng.pk]), None),
            ('06-findings', reverse('vulns:list', args=[self.eng.pk]), None),
            ('07-finding-detail', reverse('vulns:detail', args=[self.finding.pk]), None),
            ('08-evidence', reverse('vulns:detail', args=[self.finding.pk]), 'evidence'),
            ('09-comments', reverse('vulns:detail', args=[self.finding.pk]), 'comments'),
            ('10-credentials', reverse('credentials:list', args=[self.eng.pk]), None),
            ('11-kill-chain', reverse('engagements:attack_path_detail', args=[self.red_team.pk, self.attack_path.pk]), None),
            ('12-reports', reverse('reports:dashboard', args=[self.eng.pk]), None),
            ('13-audit-log', reverse('accounts:audit_log'), None),
        ]
        output = ROOT / 'docs/screenshots'
        with sync_playwright() as playwright:
            options = {'headless':True}
            if os.name == 'nt': options['channel'] = 'msedge'
            browser = playwright.chromium.launch(**options)
            context = browser.new_context(viewport={'width':1440, 'height':1000}, device_scale_factor=1, reduced_motion='reduce')
            context.add_cookies([{'name':settings.SESSION_COOKIE_NAME, 'value':self.client.cookies[settings.SESSION_COOKIE_NAME].value, 'url':self.live_server_url}])
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            for name, path, tab in pages:
                page.goto('about:blank')
                response = page.goto(self.live_server_url + path + ('#'+tab if tab else ''), wait_until='networkidle')
                self.assertEqual(response.status, 200, name)
                if tab:
                    page.locator(f'[data-tab="{tab}"]').click()
                    expect(page.locator(f'#tab-{tab}')).to_be_visible()
                page.evaluate('document.fonts.ready')
                page.evaluate('window.scrollTo(0, 0)')
                self.assertFalse(page.evaluate('document.documentElement.scrollWidth > innerWidth + 1'), name)
                page.screenshot(path=str(output / (name + '.png')), full_page=True, animations='disabled')
                print('Captured', name)
            self.assertEqual(errors, [])
            browser.close()


if __name__ == '__main__':
    raise SystemExit(bool(DiscoverRunner(verbosity=1, interactive=False).run_tests(['__main__.ReadmeScreenshots.test_capture'])))
