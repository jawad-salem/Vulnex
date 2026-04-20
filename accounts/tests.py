from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django_otp.oath import totp
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from .models import User, AuditLog


class UserModelTests(TestCase):
    def test_role_choices(self):
        """Platform roles should be Admin, Pentester, Reviewer, Client."""
        values = [c[0] for c in User.Role.choices]
        self.assertEqual(values, ['admin', 'pentester', 'reviewer', 'client'])

    def test_is_admin(self):
        user = User.objects.create_user('admin1', role='admin', password='testpass1')
        self.assertTrue(user.is_admin)
        self.assertTrue(user.is_pentester)  # Admin implies pentester
        self.assertFalse(user.is_client)

    def test_is_pentester(self):
        user = User.objects.create_user('pt1', role='pentester', password='testpass1')
        self.assertFalse(user.is_admin)
        self.assertTrue(user.is_pentester)
        self.assertFalse(user.is_client)

    def test_is_reviewer(self):
        user = User.objects.create_user('rev1', role='reviewer', password='testpass1')
        self.assertFalse(user.is_admin)
        self.assertFalse(user.is_pentester)
        self.assertTrue(user.is_reviewer)
        self.assertFalse(user.is_client)

    def test_is_client(self):
        user = User.objects.create_user('cli1', role='client', password='testpass1')
        self.assertFalse(user.is_admin)
        self.assertFalse(user.is_pentester)
        self.assertTrue(user.is_client)

    def test_initials(self):
        user = User(first_name='John', last_name='Doe', username='jdoe')
        self.assertEqual(user.initials, 'JD')

    def test_initials_fallback_to_username(self):
        user = User(username='jdoe')
        self.assertEqual(user.initials, 'JD')

    def test_default_role_is_pentester(self):
        user = User.objects.create_user('default1', password='testpass1')
        self.assertEqual(user.role, 'pentester')


@override_settings(MFA_REQUIRED_ROLES=[])
class AccessControlTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('admin', role='admin', password='testpass1')
        self.pentester = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.reviewer = User.objects.create_user('rev', role='reviewer', password='testpass1')
        self.client_user = User.objects.create_user('cli', role='client', password='testpass1')

    def test_admin_can_access_user_list(self):
        self.client.login(username='admin', password='testpass1')
        resp = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(resp.status_code, 200)

    def test_pentester_cannot_access_user_list(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(resp.status_code, 302)  # Redirected

    def test_reviewer_cannot_access_user_list(self):
        self.client.login(username='rev', password='testpass1')
        resp = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(resp.status_code, 302)

    def test_client_cannot_access_user_list(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(resp.status_code, 302)

    def test_admin_can_create_user(self):
        self.client.login(username='admin', password='testpass1')
        resp = self.client.get(reverse('accounts:user_create'))
        self.assertEqual(resp.status_code, 200)

    def test_pentester_cannot_create_user(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('accounts:user_create'))
        self.assertEqual(resp.status_code, 302)

    def test_unauthenticated_redirects_to_login(self):
        resp = self.client.get(reverse('accounts:user_list'))
        self.assertEqual(resp.status_code, 302)
        self.assertIn('login', resp.url)


@override_settings(MFA_REQUIRED_ROLES=[])
class AuditLogTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('admin', role='admin', password='testpass1')
        self.pentester = User.objects.create_user('pt', role='pentester', password='testpass1')

    def test_record_creates_entry(self):
        entry = AuditLog.record(
            actor=self.admin,
            action=AuditLog.Action.USER_UPDATE,
            target='alice',
            details={'field': 'role'},
        )
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actor, self.admin)
        self.assertEqual(entry.target, 'alice')
        self.assertEqual(entry.details, {'field': 'role'})

    def test_record_with_anon_actor_stores_null(self):
        entry = AuditLog.record(actor=None, action=AuditLog.Action.LOGIN_FAILED, target='bob')
        self.assertIsNone(entry.actor)

    def test_failed_login_is_logged(self):
        resp = self.client.post(reverse('accounts:login'), {
            'username': 'nobody', 'password': 'wrong',
        })
        self.assertEqual(resp.status_code, 200)  # re-renders form with errors
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.LOGIN_FAILED, target='nobody',
            ).exists()
        )

    def test_user_create_is_logged(self):
        self.client.login(username='admin', password='testpass1')
        self.client.post(reverse('accounts:user_create'), {
            'username': 'newuser',
            'first_name': '',
            'last_name': '',
            'email': '',
            'role': 'pentester',
            'is_active': 'on',
            'password1': 'Str0ngPass!xyz',
            'password2': 'Str0ngPass!xyz',
        })
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.USER_CREATE, target='newuser',
            ).exists()
        )

    def test_user_role_change_is_logged(self):
        target = User.objects.create_user('victim', role='pentester', password='testpass1')
        self.client.login(username='admin', password='testpass1')
        self.client.post(reverse('accounts:user_edit', args=[target.pk]), {
            'username': 'victim',
            'first_name': '',
            'last_name': '',
            'email': '',
            'role': 'admin',  # role change
            'is_active': 'on',
            'password1': '',
            'password2': '',
        })
        log = AuditLog.objects.filter(
            action=AuditLog.Action.USER_ROLE_CHANGE, target='victim',
        ).first()
        self.assertIsNotNone(log)
        self.assertEqual(log.details.get('from'), 'pentester')
        self.assertEqual(log.details.get('to'), 'admin')

    def test_audit_log_admin_only(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('accounts:audit_log'))
        self.assertEqual(resp.status_code, 302)

    def test_audit_log_accessible_to_admin(self):
        self.client.login(username='admin', password='testpass1')
        resp = self.client.get(reverse('accounts:audit_log'))
        self.assertEqual(resp.status_code, 200)


def _current_totp(device):
    return f'{totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits):0{device.digits}d}'


@override_settings(MFA_REQUIRED_ROLES=['admin', 'pentester', 'reviewer'])
class MFATests(TestCase):
    def setUp(self):
        self.client = Client()
        self.pentester = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.client_user = User.objects.create_user('cli', role='client', password='testpass1')

    def test_required_role_without_device_is_forced_to_setup(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('dashboard:home'))
        self.assertEqual(resp.status_code, 302)
        self.assertIn(reverse('accounts:mfa_setup'), resp.url)

    def test_client_role_without_device_is_not_forced(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('dashboard:home'))
        self.assertEqual(resp.status_code, 200)

    def test_login_with_confirmed_device_redirects_to_verify(self):
        TOTPDevice.objects.create(user=self.pentester, name='default', confirmed=True)
        resp = self.client.post(reverse('accounts:login'), {
            'username': 'pt', 'password': 'testpass1',
        })
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, reverse('accounts:mfa_verify'))
        # Not yet logged in — session holds pending pk
        self.assertEqual(self.client.session.get('mfa_pending_user_id'), self.pentester.pk)

    def test_mfa_verify_with_valid_code_logs_in(self):
        device = TOTPDevice.objects.create(user=self.pentester, name='default', confirmed=True)
        self.client.post(reverse('accounts:login'), {
            'username': 'pt', 'password': 'testpass1',
        })
        resp = self.client.post(reverse('accounts:mfa_verify'), {
            'code': _current_totp(device),
        })
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(int(self.client.session['_auth_user_id']), self.pentester.pk)

    def test_mfa_verify_with_invalid_code_audits_failure(self):
        TOTPDevice.objects.create(user=self.pentester, name='default', confirmed=True)
        self.client.post(reverse('accounts:login'), {
            'username': 'pt', 'password': 'testpass1',
        })
        resp = self.client.post(reverse('accounts:mfa_verify'), {'code': '000000'})
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.MFA_CHALLENGE_FAILED, target='pt',
            ).exists()
        )

    def test_mfa_setup_with_valid_code_confirms_device(self):
        self.client.login(username='pt', password='testpass1')
        # Visit setup to create the unconfirmed device
        self.client.get(reverse('accounts:mfa_setup'))
        device = TOTPDevice.objects.get(user=self.pentester, confirmed=False)
        resp = self.client.post(reverse('accounts:mfa_setup'), {
            'code': _current_totp(device),
        })
        self.assertEqual(resp.status_code, 200)
        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.MFA_ENABLED, target='pt',
            ).exists()
        )
        # Backup tokens exist
        backup = StaticDevice.objects.get(user=self.pentester)
        self.assertEqual(backup.token_set.count(), 8)

    def test_backup_token_verifies(self):
        TOTPDevice.objects.create(user=self.pentester, name='default', confirmed=True)
        backup = StaticDevice.objects.create(user=self.pentester, name='backup', confirmed=True)
        backup.token_set.create(token='RESCUE01')
        self.client.post(reverse('accounts:login'), {
            'username': 'pt', 'password': 'testpass1',
        })
        resp = self.client.post(reverse('accounts:mfa_verify'), {'code': 'RESCUE01'})
        self.assertEqual(resp.status_code, 302)
        self.assertIn('_auth_user_id', self.client.session)
        # Single-use: token is consumed
        self.assertEqual(backup.token_set.count(), 0)

    def test_required_role_cannot_disable_mfa(self):
        TOTPDevice.objects.create(user=self.pentester, name='default', confirmed=True)
        backup = StaticDevice.objects.create(user=self.pentester, name='backup', confirmed=True)
        backup.token_set.create(token='RESCUE01')
        self.client.post(reverse('accounts:login'), {'username': 'pt', 'password': 'testpass1'})
        self.client.post(reverse('accounts:mfa_verify'), {'code': 'RESCUE01'})
        resp = self.client.post(reverse('accounts:mfa_disable'))
        self.assertEqual(resp.status_code, 302)
        # Device still present
        self.assertTrue(TOTPDevice.objects.filter(user=self.pentester).exists())

    def test_client_can_disable_mfa(self):
        TOTPDevice.objects.create(user=self.client_user, name='default', confirmed=True)
        self.client.login(username='cli', password='testpass1')
        resp = self.client.post(reverse('accounts:mfa_disable'))
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(TOTPDevice.objects.filter(user=self.client_user).exists())
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.MFA_DISABLED, target='cli',
            ).exists()
        )
