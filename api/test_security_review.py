import csv
import io
import time
from unittest.mock import patch
from django.test import TestCase, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django_otp.oath import totp
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_static.models import StaticDevice
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from accounts.models import User, AuditLog
from engagements.models import Client, Engagement, EngagementMember
from recon.models import DiscoveredHost
from vulns.models import Finding
from vulnex.exports import csv_cell


@override_settings(MFA_REQUIRED_ROLES=[])
class SecurityReviewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('tester', password='password-test', role='pentester')
        self.other = User.objects.create_user('other', password='password-test', role='pentester')
        self.customer = Client.objects.create(name='Private client', notes='confidential')
        self.eng = Engagement.objects.create(name='Private engagement', client=self.customer, created_by=self.other)
        EngagementMember.objects.create(engagement=self.eng, user=self.other, role='lead')
        self.api = APIClient()

    def issue(self, **extra):
        return self.api.post('/api/v1/auth/token/', dict(username='tester', password='password-test', **extra), format='json')

    def backup_device(self):
        device = StaticDevice.objects.create(user=self.user, name='backup', confirmed=True)
        device.token_set.create(token='BACKUP123')
        return device

    def assert_tokens_rejected(self, tokens):
        self.api.credentials(HTTP_AUTHORIZATION='Bearer '+tokens['access'])
        self.assertEqual(self.api.get('/api/v1/engagements/').status_code, 401)
        self.api.credentials()
        self.assertEqual(self.api.post('/api/v1/auth/token/refresh/', {'refresh': tokens['refresh']}).status_code, 401)

    def test_enrolled_user_requires_code_even_when_role_optional(self):
        self.backup_device()
        self.assertEqual(self.issue().status_code, 401)
        self.assertEqual(self.issue(otp_code='wrong').status_code, 401)

    def test_totp_accepted_and_replay_denied(self):
        device = TOTPDevice.objects.create(user=self.user, confirmed=True)
        code = str(totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)).zfill(device.digits)
        response = self.issue(otp_code=code)
        self.assertEqual(response.status_code, 200, response.data)
        self.assertIn('no-store', response['Cache-Control'])
        self.assertEqual(self.issue(otp_code=code).status_code, 401)
        device.refresh_from_db()
        self.assertGreater(device.throttling_failure_count, 0)

    def test_backup_code_consumed(self):
        device = self.backup_device()
        response = self.issue(otp_code='BACKUP123')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(device.token_set.exists())
        self.assertEqual(self.issue(otp_code='BACKUP123').status_code, 401)
        self.api.credentials(HTTP_AUTHORIZATION='Bearer '+response.data['access'])
        self.assertEqual(self.api.get('/api/v1/engagements/').status_code, 200)
        self.api.credentials()
        self.assertEqual(self.api.post('/api/v1/auth/token/refresh/', {'refresh':response.data['refresh']}).status_code, 200)

    def test_password_change_revokes_access_and_refresh(self):
        tokens = self.issue().data
        self.user.set_password('replacement-password')
        self.user.save()
        self.assert_tokens_rejected(tokens)

    def test_device_removal_revokes_access_and_refresh(self):
        device = self.backup_device()
        tokens = self.issue(otp_code='BACKUP123').data
        device.delete()
        self.assert_tokens_rejected(tokens)

    def test_legacy_tokens_rejected(self):
        token = RefreshToken.for_user(self.user)
        self.assert_tokens_rejected({'refresh':str(token), 'access':str(token.access_token)})

    def test_new_enrollment_invalidates_password_only_token(self):
        tokens = self.issue().data
        self.backup_device()
        self.assert_tokens_rejected(tokens)

    def test_client_edit_denied_without_lead_membership(self):
        self.client.force_login(self.user)
        url = reverse('engagements:client_edit', args=[self.customer.pk])
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.post(url, {'name':'Stolen'}).status_code, 404)
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.name, 'Private client')

    def test_client_edit_allowed_for_lead(self):
        self.client.force_login(self.other)
        response = self.client.post(reverse('engagements:client_edit', args=[self.customer.pk]), {'name':'Updated'})
        self.assertEqual(response.status_code, 302)
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.name, 'Updated')

    def test_client_link_cannot_grant_access_to_private_client(self):
        self.api.force_authenticate(self.user)
        response = self.api.post('/api/v1/engagements/', {'name':'New', 'client_name':self.customer.name}, format='json')
        self.assertEqual(response.status_code, 400)
        self.client.force_login(self.user)
        response = self.client.get(reverse('engagements:create'))
        self.assertNotContains(response, 'Private client')
        response = self.client.post(reverse('engagements:create'), {'name':'New', 'client_name':self.customer.name, 'engagement_type':'webapp', 'status':'planning'})
        self.assertFalse(Engagement.objects.filter(name='New').exists())

    def test_credential_cannot_reference_foreign_host(self):
        own = Engagement.objects.create(name='Own', created_by=self.user)
        EngagementMember.objects.create(engagement=own, user=self.user, role='lead')
        host = DiscoveredHost.objects.create(engagement=self.eng, hostname='private.test')
        self.api.force_authenticate(self.user)
        response = self.api.post('/api/v1/credentials/', {'engagement':str(own.pk), 'host':str(host.pk), 'credential_type':'password', 'username':'x'}, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('host', response.data)

    def test_csv_formulas_are_text_and_json_remains_raw(self):
        self.client.force_login(self.other)
        Finding.objects.create(engagement=self.eng, title='=1+1', description='@SUM(1,2)', found_by=self.other)
        response = self.client.get(reverse('vulns:export_csv', args=[self.eng.pk]))
        row = list(csv.DictReader(io.StringIO(response.content.decode())))[0]
        self.assertEqual(row['title'], "'=1+1")
        response = self.client.get(reverse('vulns:export_json', args=[self.eng.pk]))
        self.assertEqual(response.json()[0]['title'], '=1+1')
        for value in ['=1', '+1', '-1', '@SUM(1)', '  =1', '\ttext', '\rtext', '\ntext', '\uff1d1']:
            self.assertTrue(csv_cell(value).startswith("'"))
        self.assertEqual(csv_cell('normal'), 'normal')
        self.assertEqual(csv_cell(9.8), 9.8)

    def test_audit_export_neutralizes_untrusted_target(self):
        self.user.role='admin'
        self.user.save()
        AuditLog.record(actor=self.user, action=AuditLog.Action.LOGIN_FAILED, target='=1+1')
        self.client.force_login(self.user)
        response=self.client.get(reverse('accounts:audit_log')+'?export=csv')
        rows=list(csv.DictReader(io.StringIO(response.content.decode())))
        self.assertIn("'=1+1", [row['target'] for row in rows])

    def test_pending_mfa_invalid_after_password_change(self):
        self.backup_device()
        self.client.post(reverse('accounts:login'), {'username':'tester','password':'password-test'})
        self.user.set_password('changed-password')
        self.user.save()
        response=self.client.post(reverse('accounts:mfa_verify'), {'code':'BACKUP123'})
        self.assertRedirects(response, reverse('accounts:login'))
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_pending_mfa_expires(self):
        self.backup_device()
        self.client.post(reverse('accounts:login'), {'username':'tester','password':'password-test'})
        with patch('django.core.signing.time.time', return_value=time.time()+301):
            response=self.client.post(reverse('accounts:mfa_verify'), {'code':'BACKUP123'})
        self.assertRedirects(response, reverse('accounts:login'))

    def test_sensitive_key_page_is_not_cached(self):
        self.client.force_login(self.user)
        response=self.client.get(reverse('accounts:api_key_list'))
        self.assertIn('no-store', response['Cache-Control'])

    def test_scanner_upload_limits(self):
        from recon.forms import NmapImportForm
        from vulns.forms import ToolImportForm
        for form_class in (NmapImportForm, ToolImportForm):
            upload=SimpleUploadedFile('scan.xml', b'example')
            upload.size=form_class.MAX_FILE_SIZE+1
            form=form_class(data={'tool':'burp'}, files={'file':upload})
            self.assertFalse(form.is_valid())
            self.assertIn('file', form.errors)

    def test_markdown_avoids_vulnerable_email_linkifier(self):
        from vulns.templatetags.vulns_extras import render_markdown
        import bleach
        with patch('vulns.templatetags.vulns_extras.bleach.linkify', wraps=bleach.linkify) as linkify:
            result=render_markdown('[email](mailto:user@example.test)')
            self.assertIn('mailto:user@example.test', result)
            self.assertFalse(linkify.call_args.kwargs['parse_email'])

    def test_admin_password_form_cannot_bypass_mfa(self):
        self.user.is_staff = True
        self.user.is_superuser = True
        self.user.role = 'admin'
        self.user.save()
        self.backup_device()
        response = self.client.post('/admin/login/', {'username':'tester','password':'password-test'})
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_unverified_browser_session_is_rejected(self):
        self.backup_device()
        self.client.force_login(self.user)
        response = self.client.get(reverse('dashboard:home'))
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_verified_browser_session_reaches_application(self):
        self.backup_device()
        self.client.post(reverse('accounts:login'), {'username':'tester','password':'password-test'})
        self.client.post(reverse('accounts:mfa_verify'), {'code':'BACKUP123'})
        self.assertEqual(self.client.get(reverse('dashboard:home')).status_code, 200)

    def test_unverified_session_cannot_disable_optional_mfa(self):
        device = self.backup_device()
        self.client.force_login(self.user)
        response = self.client.post(reverse('accounts:mfa_disable'))
        self.assertEqual(response.status_code, 302)
        self.assertTrue(StaticDevice.objects.filter(pk=device.pk).exists())
        self.assertIn('/accounts/login/', response.url)
