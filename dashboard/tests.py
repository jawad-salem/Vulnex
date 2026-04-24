from django.test import TestCase, Client, override_settings
from django.urls import reverse
from accounts.models import User
from engagements.models import Engagement, EngagementMember, Client as EngagementClient
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
