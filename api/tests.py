"""Smoke tests for /api/v1/.

Covers the four-role permission matrix (admin, pentester-on-engagement,
client, outsider) on a representative subset of endpoints, plus the two
non-session authentication paths (API key and JWT).
"""
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from accounts.models import APIKey, User
from credentials.models import Credential
from engagements.models import Engagement, EngagementMember, Client
from vulns.models import Finding


@override_settings(MFA_REQUIRED_ROLES=[])
class APIRoleMatrixTests(TestCase):
    """Each endpoint is probed from four identities to confirm scoping:
    admin (unrestricted), pentester-on-engagement (read/write), client
    (read-only and no creds), outsider (should see nothing)."""

    def setUp(self):
        self.api = APIClient()
        self.admin = User.objects.create_user('admin', role='admin', password='pw')
        self.pentester = User.objects.create_user('pt', role='pentester', password='pw')
        self.client_user = User.objects.create_user('cli', role='client', password='pw')
        self.outsider = User.objects.create_user('out', role='pentester', password='pw')

        self.engagement = Engagement.objects.create(
            name='E1', client=Client.objects.get_or_create(name='ACME')[0], created_by=self.admin,
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.pentester, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.client_user, role='client')

        self.finding = Finding.objects.create(
            engagement=self.engagement, title='SQLi', severity='high',
            description='...', found_by=self.pentester,
        )
        self.cred = Credential.objects.create(
            engagement=self.engagement, username='admin', found_by=self.pentester,
        )
        self.cred.set_secret('s3cret')
        self.cred.save()

    # ── engagement list ─────────────────────────────────────────────

    def test_admin_sees_all_engagements(self):
        self.api.force_authenticate(self.admin)
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()['results']), 1)

    def test_pentester_sees_own_engagements(self):
        self.api.force_authenticate(self.pentester)
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()['results']), 1)

    def test_client_sees_own_engagements(self):
        self.api.force_authenticate(self.client_user)
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()['results']), 1)

    def test_outsider_sees_no_engagements(self):
        self.api.force_authenticate(self.outsider)
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()['results']), 0)

    def test_outsider_cannot_retrieve_engagement(self):
        self.api.force_authenticate(self.outsider)
        resp = self.api.get(f'/api/v1/engagements/{self.engagement.pk}/')
        self.assertIn(resp.status_code, (403, 404))

    # ── findings ────────────────────────────────────────────────────

    def test_pentester_can_create_finding(self):
        self.api.force_authenticate(self.pentester)
        resp = self.api.post('/api/v1/findings/', {
            'engagement': str(self.engagement.pk),
            'title': 'New finding',
            'severity': 'medium',
            'description': 'desc',
        }, format='json')
        self.assertEqual(resp.status_code, 201, resp.content)

    def test_client_cannot_create_finding(self):
        self.api.force_authenticate(self.client_user)
        resp = self.api.post('/api/v1/findings/', {
            'engagement': str(self.engagement.pk),
            'title': 'should fail',
            'severity': 'medium',
        }, format='json')
        self.assertIn(resp.status_code, (403, 400))

    def test_outsider_cannot_list_findings(self):
        self.api.force_authenticate(self.outsider)
        resp = self.api.get('/api/v1/findings/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()['results']), 0)

    # ── credentials (clients are blocked entirely) ─────────────────

    def test_client_blocked_from_credentials(self):
        self.api.force_authenticate(self.client_user)
        resp = self.api.get('/api/v1/credentials/')
        self.assertEqual(resp.status_code, 403)

    def test_pentester_can_list_credentials(self):
        self.api.force_authenticate(self.pentester)
        resp = self.api.get('/api/v1/credentials/')
        self.assertEqual(resp.status_code, 200)

    def test_pentester_reveal_flag_returns_plaintext(self):
        self.api.force_authenticate(self.pentester)
        resp = self.api.get(f'/api/v1/credentials/{self.cred.pk}/?reveal=true')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['secret'], 's3cret')

    def test_pentester_default_retrieve_hides_plaintext(self):
        self.api.force_authenticate(self.pentester)
        resp = self.api.get(f'/api/v1/credentials/{self.cred.pk}/')
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn('secret', resp.json())

    def test_outsider_cannot_retrieve_credential(self):
        self.api.force_authenticate(self.outsider)
        resp = self.api.get(f'/api/v1/credentials/{self.cred.pk}/')
        self.assertEqual(resp.status_code, 404)

    # ── unauthenticated ────────────────────────────────────────────

    def test_unauthenticated_request_rejected(self):
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 401)


@override_settings(MFA_REQUIRED_ROLES=[])
class APIKeyAuthTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.user = User.objects.create_user('pt', role='pentester', password='pw')
        self.engagement = Engagement.objects.create(
            name='E1', client=Client.objects.get_or_create(name='ACME')[0], created_by=self.user,
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.user, role='lead')
        self.key, self.raw = APIKey.issue(user=self.user, name='test')

    def test_valid_api_key_authenticates(self):
        self.api.credentials(HTTP_AUTHORIZATION=f'ApiKey {self.raw}')
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 200)

    def test_revoked_api_key_rejected(self):
        self.key.revoke()
        self.api.credentials(HTTP_AUTHORIZATION=f'ApiKey {self.raw}')
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 401)

    def test_malformed_api_key_rejected(self):
        self.api.credentials(HTTP_AUTHORIZATION='ApiKey not-a-real-key')
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 401)

    def test_wrong_secret_rejected(self):
        tampered = f'vlnx_{self.key.key_prefix}_wrongsecretwrongsecretwrongsecret'
        self.api.credentials(HTTP_AUTHORIZATION=f'ApiKey {tampered}')
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 401)

    def test_last_used_updates_on_successful_auth(self):
        self.assertIsNone(self.key.last_used_at)
        self.api.credentials(HTTP_AUTHORIZATION=f'ApiKey {self.raw}')
        self.api.get('/api/v1/engagements/')
        self.key.refresh_from_db()
        self.assertIsNotNone(self.key.last_used_at)


@override_settings(MFA_REQUIRED_ROLES=[])
class JWTAuthTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.user = User.objects.create_user('pt', role='pentester', password='pw')

    def test_obtain_token_with_valid_credentials(self):
        resp = self.api.post('/api/v1/auth/token/', {
            'username': 'pt', 'password': 'pw',
        }, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('access', resp.json())
        self.assertIn('refresh', resp.json())

    def test_token_rejects_bad_password(self):
        resp = self.api.post('/api/v1/auth/token/', {
            'username': 'pt', 'password': 'wrong',
        }, format='json')
        self.assertEqual(resp.status_code, 401)

    def test_access_token_authenticates_request(self):
        token_resp = self.api.post('/api/v1/auth/token/', {
            'username': 'pt', 'password': 'pw',
        }, format='json')
        access = token_resp.json()['access']
        self.api.credentials(HTTP_AUTHORIZATION=f'Bearer {access}')
        resp = self.api.get('/api/v1/engagements/')
        self.assertEqual(resp.status_code, 200)


@override_settings(MFA_REQUIRED_ROLES=[])
class APIDocsTests(TestCase):
    def test_schema_accessible(self):
        user = User.objects.create_user('pt', role='pentester', password='pw')
        api = APIClient()
        api.force_authenticate(user)
        resp = api.get('/api/schema/')
        self.assertEqual(resp.status_code, 200)
