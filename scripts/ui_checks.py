"""Opt-in real-browser checks against a disposable Django live server.
Run: myvenv/Scripts/python.exe scripts/ui_checks.py
Requires requirements-dev.txt and an installed Edge (Windows) or Playwright Chromium.
"""
import os
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ['DJANGO_SETTINGS_MODULE'] = 'vulnex.test_settings'
sys.argv.append('test')
import django
django.setup()
from django.conf import settings
from django.contrib.staticfiles.testing import StaticLiveServerTestCase
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings, Client as TestClient
from django.test.runner import DiscoverRunner
from django.urls import reverse
from playwright.sync_api import sync_playwright, expect
from accounts.models import User
from engagements.models import Engagement, EngagementMember, Client, ActivityLog, AttackPath, AttackPathNode, AttackPathEdge
from methodology.models import Methodology, ChecklistCategory, ChecklistItem, EngagementChecklist
from vulns.models import Finding, Evidence
from reports.models import Report


@override_settings(MFA_REQUIRED_ROLES=[])
class WorkspaceBrowserChecks(StaticLiveServerTestCase):
    def setUp(self):
        self.user = User.objects.create_user('preview-lead', first_name='Alex', role='pentester')
        customer = Client.objects.create(name='Acme Systems')
        self.eng = Engagement.objects.create(name='Customer platform assessment', client=customer,
            engagement_type='webapp', status='scanning', created_by=self.user,
            in_scope='app.example.test\napi.example.test', rules_of_engagement='Testing is limited to the approved staging environment.',
            description='Assess authentication, access control, and the public API before the autumn release.')
        EngagementMember.objects.create(engagement=self.eng, user=self.user, role='lead')
        methodology = Methodology.objects.create(name='Web application testing')
        category = ChecklistCategory.objects.create(methodology=methodology, name='Authorization')
        for i in range(6):
            item = ChecklistItem.objects.create(category=category, title=f'Authorization check {i+1}')
            EngagementChecklist.objects.create(engagement=self.eng, checklist_item=item, status='completed' if i < 4 else 'not_started')
        titles = ['Broken object-level authorization', 'Session remains valid after password reset', 'Missing security headers', 'Verbose API error responses']
        for i, title in enumerate(titles):
            finding = Finding.objects.create(engagement=self.eng, title=title, found_by=self.user,
                assigned_to=self.user, host='api.example.test', description='An authenticated user can access another account by changing the object identifier.\n\nThis exposes customer records outside the intended authorization boundary.',
                proof_of_concept='1. Sign in with a test account.\n2. Request a record owned by another account.\n3. Observe the returned customer details.',
                remediation='Enforce ownership checks on every request. Add regression coverage for cross-account access.',
                privileges_required='L', confidentiality_impact='H', integrity_impact='H', availability_impact='N',
                review_state='in_review' if i == 0 else 'draft')
            Finding.objects.filter(pk=finding.pk).update(severity=['high','medium','low','info'][i], cvss_score=[8.1,6.4,3.1,0][i])
            if i == 0: self.finding = finding
        for i in range(23):
            self.published = Finding.objects.create(engagement=self.eng, title=f'Cross-account authorization bypass in the customer export and scheduled report endpoint {i + 1}', assigned_to=self.user, found_by=self.user, host='api.example.test', review_state='approved' if i == 22 else 'draft')
        Evidence.objects.create(finding=self.finding, uploaded_by=self.user, caption='Sanitized response', file=SimpleUploadedFile('response.txt', b'Example evidence'))
        for action in ['Created engagement', 'Applied web testing methodology', 'Imported four findings', 'Submitted finding for review']:
            ActivityLog.objects.create(engagement=self.eng, user=self.user, action=action)
        report = Report.objects.create(engagement=self.eng, title='Report review fixture', generated_by=self.user)
        report.file.save('review.pdf', SimpleUploadedFile('review.pdf', b'%PDF-1.4 fixture'))
        self.client.force_login(self.user)
        customer_user = User.objects.create_user('preview-client', role='client')
        EngagementMember.objects.create(engagement=self.eng, user=customer_user, role='client')
        customer_client = TestClient()
        customer_client.force_login(customer_user)
        self.customer_cookie = customer_client.cookies[settings.SESSION_COOKIE_NAME].value
        self.red_team = Engagement.objects.create(name='Red-team resilience assessment', engagement_type='red_team', in_scope='staging.example.test', rules_of_engagement='Staging only. Stop on service degradation.', authorization_reference='Approved RoE v1')
        EngagementMember.objects.create(engagement=self.red_team, user=self.user, role='lead')
        self.attack_path = AttackPath.objects.create(engagement=self.red_team, name='External entry to reporting objective', description='Document observed access and supporting evidence.')
        start = AttackPathNode.objects.create(path=self.attack_path, kind='entrypoint', label='Approved entry point')
        end = AttackPathNode.objects.create(path=self.attack_path, kind='objective', label='Access test reporting dataset')
        AttackPathEdge.objects.create(path=self.attack_path, from_node=start, to_node=end, technique='Validated access')
        self.empty_engagement = Engagement.objects.create(name='New assessment', engagement_type='webapp')
        EngagementMember.objects.create(engagement=self.empty_engagement, user=customer_user, role='client')

    def test_workspace(self):
        output = ROOT / 'artifacts/ui'
        output.mkdir(parents=True, exist_ok=True)
        pages = [('dashboard', reverse('dashboard:home')), ('engagement', reverse('engagements:detail', args=[self.eng.pk])),
                 ('finding', reverse('vulns:detail', args=[self.finding.pk])), ('finding-form', reverse('vulns:create', args=[self.eng.pk])),
                 ('findings', reverse('vulns:list', args=[self.eng.pk])), ('reports', reverse('reports:dashboard', args=[self.eng.pk])),
                 ('recon', reverse('recon:dashboard', args=[self.eng.pk])), ('testing', reverse('methodology:dashboard', args=[self.eng.pk])), ('red-team', reverse('engagements:detail', args=[self.red_team.pk])), ('attack-paths', reverse('engagements:attack_path_list', args=[self.red_team.pk])), ('attack-path', reverse('engagements:attack_path_detail', args=[self.red_team.pk, self.attack_path.pk]))]
        with sync_playwright() as p:
            options = {'headless': True}
            if os.name == 'nt': options['channel'] = 'msedge'
            browser = p.chromium.launch(**options)
            context = browser.new_context()
            context.add_cookies([{'name': settings.SESSION_COOKIE_NAME, 'value': self.client.cookies[settings.SESSION_COOKIE_NAME].value, 'url': self.live_server_url}])
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('console', lambda message: errors.append(message.text + ' ' + str(message.location)) if message.type == 'error' else None)
            page.on('requestfailed', lambda request: errors.append(request.url + ' ' + str(request.failure)))
            for width, height in [(1920,1080),(1440,1000),(390,844),(320,800)]:
                page.set_viewport_size({'width':width,'height':height})
                for name,path in pages:
                    response = page.goto(self.live_server_url + path, wait_until='networkidle')
                    self.assertEqual(response.status, 200, name)
                    if name != 'dashboard': expect(page.locator('.workspace-nav')).to_be_visible()
                    if name == 'recon':
                        toggle = page.locator('[data-toggle-panel="newscanPanel"]')
                        toggle.click()
                        expect(page.locator('#newscanPanel')).to_be_visible()
                        expect(toggle).to_have_attribute('aria-expanded', 'true')
                        guidance = page.locator('.scan-scope-help')
                        expect(guidance).to_be_visible()
                        contrasts = guidance.evaluate(r"""element => {
                            const luminance = color => {
                                const rgb = color.match(/[\d.]+/g).slice(0, 3).map(Number).map(v => {
                                    v /= 255;
                                    return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
                                });
                                return rgb[0] * 0.2126 + rgb[1] * 0.7152 + rgb[2] * 0.0722;
                            };
                            const background = luminance(getComputedStyle(element).backgroundColor);
                            return [element, element.querySelector('a')].map(node => {
                                const foreground = luminance(getComputedStyle(node).color);
                                return (Math.max(background, foreground) + 0.05) /
                                       (Math.min(background, foreground) + 0.05);
                            });
                        }""")
                        for contrast in contrasts:
                            self.assertGreaterEqual(contrast, 4.5, f'Scope guidance contrast at {width}px')
                        self.assertFalse(page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 1'))
                        page.screenshot(path=str(output/f'new-scan-{width}.png'), full_page=True)
                        toggle.click()
                        expect(page.locator('#newscanPanel')).to_be_hidden()

                    page.screenshot(path=str(output/f'{name}-{width}.png'), full_page=True)
                    overflow = page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 1')

                    if overflow:
                        print(page.evaluate("Array.from(document.querySelectorAll('main *')).filter(e => e.getBoundingClientRect().right > innerWidth+1).slice(0,8).map(e => [e.tagName,e.className,e.getBoundingClientRect().width])"))
                    self.assertFalse(overflow, f'Horizontal overflow: {name} at {width}px')
                page.goto(self.live_server_url + reverse('engagements:attack_path_detail', args=[self.red_team.pk, self.attack_path.pk]), wait_until='networkidle')
                expect(page.locator('#attack-path-canvas svg')).to_be_visible()
                expect(page.locator('.workspace-nav [aria-current]')).to_have_text('Attack paths')
                page.locator('.ap-toolbar-action').first.locator('summary').click()
                expect(page.locator('#id_discovered_host')).to_be_visible()
                self.assertFalse(page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 1'), 'Attack-path form overflow')
                page.goto(self.live_server_url + reverse('engagements:detail', args=[self.red_team.pk]) + '#scope', wait_until='networkidle')
                page.screenshot(path=str(output/f'roe-{width}.png'), full_page=True)
                page.goto(self.live_server_url + pages[1][1], wait_until='networkidle')
                page.get_by_role('tab', name='Scope & RoE').click()
                self.assertTrue(page.locator('#tab-scope').is_visible())
                page.get_by_role('tab', name='Scope & RoE').press('ArrowRight')
                self.assertTrue(page.locator('#tab-activity').is_visible())
                page.get_by_role('tab', name='Team', exact=False).click()
                page.get_by_role('button', name='Invite member', exact=False).click()
                self.assertTrue(page.locator('#invitePanel').is_visible())
                self.assertFalse(page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 1'), 'Team panel overflow')
                page.goto(self.live_server_url + pages[1][1] + '#scope', wait_until='networkidle')
                self.assertTrue(page.locator('#tab-scope').is_visible())
                page.goto(self.live_server_url + pages[1][1] + '#overview', wait_until='networkidle')
                page.get_by_role('link', name='View scope', exact=True).click()
                self.assertTrue(page.locator('#tab-scope').is_visible())
                if width < 768:
                    page.get_by_role('button', name='Toggle menu').click()
                    self.assertEqual(page.locator('#mobileToggle').get_attribute('aria-expanded'), 'true')
                    page.keyboard.press('Escape')
                    self.assertEqual(page.locator('#mobileToggle').get_attribute('aria-expanded'), 'false')
                    self.assertEqual(page.evaluate('document.activeElement.id'), 'mobileToggle')
            page.goto(self.live_server_url + reverse('vulns:list', args=[self.eng.pk]) + '?review=in_review', wait_until='networkidle')
            self.assertEqual(page.locator('.workspace-nav [aria-current="page"]').inner_text(), 'Findings')
            expect(page.locator('.queue-nav [aria-current="page"]')).to_have_text('Review')
            page.goto(self.live_server_url + reverse('dashboard:home') + '?queue=mine&page=2', wait_until='networkidle')
            expect(page.locator('.queue-nav [aria-current="page"]')).to_contain_text('Assigned to me')
            self.assertEqual(page.locator('.dashboard-main .workspace-section').first.locator('tbody tr').count(), 12)
            page.screenshot(path=str(output/'work-queue-page-2.png'), full_page=True)
            page.goto(self.live_server_url + reverse('reports:dashboard', args=[self.eng.pk]), wait_until='networkidle')
            page.locator('.report-publication summary').click()
            page.get_by_role('checkbox').check()
            page.get_by_role('button', name='Publish this PDF', exact=True).click()
            expect(page.get_by_text('Published to client', exact=True)).to_be_visible()
            page.locator('.report-publication summary').click()
            page.get_by_role('button', name='Withdraw client access', exact=True).click()
            expect(page.get_by_text('Internal draft', exact=True)).to_be_visible()
            # Extracted editor scripts still calculate CVSS and render Markdown.
            page.goto(self.live_server_url + reverse('vulns:create', args=[self.eng.pk]), wait_until='networkidle')
            page.locator('#cvssVectorPaste').fill('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
            page.get_by_role('button', name='Apply', exact=True).click()
            expect(page.locator('#cvssBadge')).to_contain_text('9.8')
            page.locator('#id_description').fill('**Browser proof**')
            field = page.locator('[data-md-field]').first
            field.get_by_role('tab', name='Preview', exact=True).click()
            expect(field.locator('.md-preview-pane strong')).to_have_text('Browser proof')
            expect(page.locator('#editorSaveState')).to_have_text('Unsaved changes')
            # Dismissing the browser warning keeps all typed content in the editor.
            page.once('dialog', lambda dialog: dialog.dismiss())
            page.get_by_role('link', name='Cancel', exact=True).first.click()
            expect(page.locator('#id_description')).to_have_value('**Browser proof**')
            self.assertIn(reverse('vulns:create', args=[self.eng.pk]), page.url)
            page.on('dialog', lambda dialog: dialog.accept())
            # A client sees published findings but none of the internal navigation.
            context.clear_cookies()
            context.add_cookies([{'name': settings.SESSION_COOKIE_NAME, 'value': self.customer_cookie, 'url': self.live_server_url}])
            page.goto(self.live_server_url + reverse('engagements:detail', args=[self.eng.pk]), wait_until='networkidle')
            self.assertEqual(page.locator('.workspace-nav').get_by_role('link', name='Vault').count(), 0)
            self.assertEqual(page.locator('.workspace-nav').get_by_role('link', name='Review', exact=True).count(), 0)
            self.assertEqual(page.locator('.work-list').count(), 0)
            page.screenshot(path=str(output/'client-320.png'), full_page=True)
            page.set_viewport_size({'width':1920, 'height':1080})
            page.goto(self.live_server_url + reverse('vulns:detail', args=[self.published.pk]), wait_until='networkidle')
            expect(page.locator('.finding-header')).to_be_visible()
            self.assertFalse(page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 1'))
            page.screenshot(path=str(output/'client-finding-1920.png'), full_page=True)

            # Fresh engagement has useful empty states and stays within the viewport.
            page.goto(self.live_server_url + reverse('engagements:detail', args=[self.empty_engagement.pk]), wait_until='networkidle')
            expect(page.get_by_text('No findings yet.', exact=True)).to_be_visible()
            self.assertFalse(page.evaluate('document.documentElement.scrollWidth > window.innerWidth + 1'))
            self.assertEqual(errors, [], 'Browser errors')
            browser.close()


if __name__ == '__main__':
    raise SystemExit(bool(DiscoverRunner(verbosity=1, interactive=False).run_tests(['__main__.WorkspaceBrowserChecks'])))
