from django.test import TestCase, Client, override_settings
from django.urls import reverse
from accounts.models import User
from credentials.models import Credential
from engagements.models import Engagement, EngagementMember, Client as EngagementClient
from recon.models import DiscoveredHost
from vulns.models import Finding


@override_settings(MFA_REQUIRED_ROLES=[])
class GlobalSearchTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('admin', role='admin', password='testpass1')
        self.pentester = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.outsider = User.objects.create_user('outsider', role='pentester', password='testpass1')

        self.engagement = Engagement.objects.create(
            name='ACME Web App Pentest', client=EngagementClient.objects.get_or_create(name='ACME Corp')[0], created_by=self.admin,
        )
        EngagementMember.objects.create(
            engagement=self.engagement, user=self.pentester, role='lead',
        )
        self.finding = Finding.objects.create(
            engagement=self.engagement,
            title='SQL injection in login form',
            description='Reflected at id parameter',
            host='acme.example.com',
            found_by=self.pentester,
            confidentiality_impact='H',
        )

    def test_empty_query_shows_prompt(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('dashboard:search'))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'at least 2 characters')

    def test_short_query_treated_as_empty(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=a')
        self.assertContains(resp, 'at least 2 characters')

    def test_finding_match_by_title(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=injection')
        self.assertContains(resp, 'SQL injection in login form')

    def test_engagement_match_by_client(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=ACME')
        self.assertContains(resp, 'ACME Web App Pentest')

    def test_outsider_does_not_see_results(self):
        """Non-members must not find engagements they can't access."""
        self.client.login(username='outsider', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=ACME')
        self.assertNotContains(resp, 'ACME Web App Pentest')
        self.assertNotContains(resp, 'SQL injection in login form')

    def test_admin_sees_all(self):
        self.client.login(username='admin', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=ACME')
        self.assertContains(resp, 'ACME Web App Pentest')

    def test_unauthenticated_redirects(self):
        resp = self.client.get(reverse('dashboard:search') + '?q=anything')
        self.assertEqual(resp.status_code, 302)
        self.assertIn('login', resp.url)

    def test_credential_match_visible_to_member(self):
        Credential.objects.create(
            engagement=self.engagement, username='svc_admin', service='SSH',
            found_by=self.pentester,
        )
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=svc_admin')
        self.assertContains(resp, 'svc_admin')

    def test_credential_hidden_from_client(self):
        client_user = User.objects.create_user('cli', role='client', password='testpass1')
        EngagementMember.objects.create(
            engagement=self.engagement, user=client_user, role='client',
        )
        Credential.objects.create(
            engagement=self.engagement, username='svc_admin', service='SSH',
            found_by=self.pentester,
        )
        # Approve the existing finding so the client has at least one match in
        # the rest of the page; we need to check ONLY the credential is hidden.
        self.finding.review_state = Finding.ReviewState.APPROVED
        self.finding.save()
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=svc_admin')
        # The query string is echoed in the page title/subtitle/search input,
        # so we check that the Credentials section itself was not rendered.
        self.assertNotContains(resp, '<h2 class="card-title">Credentials</h2>')

    def test_host_match_visible_to_member(self):
        DiscoveredHost.objects.create(
            engagement=self.engagement, hostname='vault.acme.example.com',
        )
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=vault')
        self.assertContains(resp, 'vault.acme.example.com')

    def test_host_hidden_from_client(self):
        client_user = User.objects.create_user('cli2', role='client', password='testpass1')
        EngagementMember.objects.create(
            engagement=self.engagement, user=client_user, role='client',
        )
        DiscoveredHost.objects.create(
            engagement=self.engagement, hostname='vault.acme.example.com',
        )
        self.client.login(username='cli2', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=vault')
        self.assertNotContains(resp, 'vault.acme.example.com')

    def test_finding_status_chip_present(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=injection')
        # Status badge is now alongside the severity badge in results.
        self.assertContains(resp, 'badge-open')

    def test_client_only_sees_approved_findings(self):
        client_user = User.objects.create_user('cli3', role='client', password='testpass1')
        EngagementMember.objects.create(
            engagement=self.engagement, user=client_user, role='client',
        )
        # Default review_state is DRAFT — must be invisible to client.
        self.client.login(username='cli3', password='testpass1')
        resp = self.client.get(reverse('dashboard:search') + '?q=injection')
        self.assertNotContains(resp, 'SQL injection in login form')
