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
class PasswordValidationTests(TestCase):
    """Step 1.3 — AUTH_PASSWORD_VALIDATORS must run on every password-setting
    form (admin user CRUD, invitation registration, self-service change)."""

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('admin', role='admin', password='Str0ngPass!xyz')

    def test_admin_create_rejects_common_password(self):
        self.client.login(username='admin', password='Str0ngPass!xyz')
        resp = self.client.post(reverse('accounts:user_create'), {
            'username': 'newuser',
            'first_name': '',
            'last_name': '',
            'email': '',
            'role': 'pentester',
            'is_active': 'on',
            'password1': 'password1',
            'password2': 'password1',
        })
        # Form re-rendered with errors (no redirect)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(User.objects.filter(username='newuser').exists())

    def test_admin_create_rejects_too_short(self):
        self.client.login(username='admin', password='Str0ngPass!xyz')
        resp = self.client.post(reverse('accounts:user_create'), {
            'username': 'shorty',
            'first_name': '',
            'last_name': '',
            'email': '',
            'role': 'pentester',
            'is_active': 'on',
            'password1': 'abc',
            'password2': 'abc',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(User.objects.filter(username='shorty').exists())

    def test_profile_password_change_succeeds(self):
        self.client.login(username='admin', password='Str0ngPass!xyz')
        resp = self.client.post(reverse('accounts:profile'), {
            'change_password': '1',
            'old_password': 'Str0ngPass!xyz',
            'new_password1': 'An0therStr0ngPass!',
            'new_password2': 'An0therStr0ngPass!',
        })
        self.assertEqual(resp.status_code, 302)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.check_password('An0therStr0ngPass!'))
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.PASSWORD_CHANGE, target='admin',
            ).exists()
        )

    def test_profile_password_change_rejects_common(self):
        self.client.login(username='admin', password='Str0ngPass!xyz')
        resp = self.client.post(reverse('accounts:profile'), {
            'change_password': '1',
            'old_password': 'Str0ngPass!xyz',
            'new_password1': 'password1',
            'new_password2': 'password1',
        })
        self.assertEqual(resp.status_code, 200)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.check_password('Str0ngPass!xyz'))
        self.assertFalse(
            AuditLog.objects.filter(action=AuditLog.Action.PASSWORD_CHANGE).exists()
        )

    def test_profile_password_change_wrong_old_password(self):
        self.client.login(username='admin', password='Str0ngPass!xyz')
        resp = self.client.post(reverse('accounts:profile'), {
            'change_password': '1',
            'old_password': 'not-the-real-password',
            'new_password1': 'An0therStr0ngPass!',
            'new_password2': 'An0therStr0ngPass!',
        })
        self.assertEqual(resp.status_code, 200)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.check_password('Str0ngPass!xyz'))


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


@override_settings(MFA_REQUIRED_ROLES=[])
class AuditLogCoverageTests(TestCase):
    """Each security-relevant action writes exactly one AuditLog row with
    the expected actor/target/details. Narrower than the per-view tests —
    these focus on audit-trail completeness."""

    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user(
            'lead', role='pentester', password='testpass1', email='lead@x.test',
        )

    def _only(self, action):
        rows = AuditLog.objects.filter(action=action)
        self.assertEqual(rows.count(), 1, f'expected exactly one {action} row')
        return rows.get()

    def test_login_success_logged(self):
        self.client.post(reverse('accounts:login'),
                         {'username': 'lead', 'password': 'testpass1'})
        row = self._only(AuditLog.Action.LOGIN_SUCCESS)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, 'lead')

    def test_logout_logged(self):
        self.client.force_login(self.lead)
        self.client.post(reverse('accounts:logout'))
        row = self._only(AuditLog.Action.LOGOUT)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, 'lead')

    def test_password_change_logged(self):
        self.client.login(username='lead', password='testpass1')
        self.client.post(reverse('accounts:profile'), {
            'change_password': '1',
            'old_password': 'testpass1',
            'new_password1': 'Z7kqP!nc9Lm2',
            'new_password2': 'Z7kqP!nc9Lm2',
        })
        row = self._only(AuditLog.Action.PASSWORD_CHANGE)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, 'lead')

    def test_mfa_enabled_logged(self):
        self.client.login(username='lead', password='testpass1')
        # Create unconfirmed device then POST a valid TOTP code.
        from django_otp.plugins.otp_totp.models import TOTPDevice
        device = TOTPDevice.objects.create(
            user=self.lead, name='default', confirmed=False,
        )
        code = totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)
        self.client.post(reverse('accounts:mfa_setup'), {'code': str(code).zfill(6)})
        row = self._only(AuditLog.Action.MFA_ENABLED)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, 'lead')

    def test_mfa_disabled_logged(self):
        from django_otp.plugins.otp_totp.models import TOTPDevice
        TOTPDevice.objects.create(user=self.lead, name='default', confirmed=True)
        self.client.login(username='lead', password='testpass1')
        self.client.post(reverse('accounts:mfa_disable'))
        row = self._only(AuditLog.Action.MFA_DISABLED)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, 'lead')

    def test_credential_create_logged(self):
        from engagements.models import Engagement, EngagementMember
        engagement = Engagement.objects.create(
            name='E1', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=engagement, user=self.lead, role='lead',
        )
        self.client.login(username='lead', password='testpass1')
        self.client.post(
            reverse('credentials:create', args=[engagement.pk]),
            {
                'credential_type': 'password',
                'username': 'admin',
                'secret': 'hunter2',
                'hash_type': '',
                'host': '',
                'service': 'SSH',
                'source': 'bruteforce',
                'status': 'valid',
                'notes': '',
            },
        )
        row = self._only(AuditLog.Action.CREDENTIAL_CREATE)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.details['engagement'], 'E1')
        self.assertEqual(row.details['username'], 'admin')

    def test_credential_delete_logged(self):
        from engagements.models import Engagement, EngagementMember
        from credentials.models import Credential
        engagement = Engagement.objects.create(
            name='E2', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=engagement, user=self.lead, role='lead',
        )
        cred = Credential(
            engagement=engagement, credential_type='password',
            username='root', found_by=self.lead,
        )
        cred.set_secret('p')
        cred.save()
        self.client.login(username='lead', password='testpass1')
        self.client.post(reverse('credentials:delete', args=[engagement.pk, cred.pk]))
        row = self._only(AuditLog.Action.CREDENTIAL_DELETE)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, str(cred.pk))

    def test_credential_reveal_logged(self):
        from engagements.models import Engagement, EngagementMember
        from credentials.models import Credential
        engagement = Engagement.objects.create(
            name='E3', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=engagement, user=self.lead, role='lead',
        )
        cred = Credential(
            engagement=engagement, credential_type='password',
            username='admin', found_by=self.lead,
        )
        cred.set_secret('hunter2')
        cred.save()
        self.client.login(username='lead', password='testpass1')
        self.client.post(reverse('credentials:reveal', args=[engagement.pk, cred.pk]))
        row = self._only(AuditLog.Action.CREDENTIAL_REVEAL)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, str(cred.pk))
        self.assertEqual(row.details['username'], 'admin')

    def test_evidence_download_logged(self):
        import shutil
        import tempfile
        from django.core.files.storage import FileSystemStorage
        from django.core.files.uploadedfile import SimpleUploadedFile
        from engagements.models import Engagement, EngagementMember
        from vulns.models import Finding, Evidence

        tmpdir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmpdir, ignore_errors=True)
        field = Evidence._meta.get_field('file')
        orig = field.storage
        field.storage = FileSystemStorage(location=tmpdir)
        self.addCleanup(lambda: setattr(field, 'storage', orig))

        engagement = Engagement.objects.create(
            name='E4', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=engagement, user=self.lead, role='lead',
        )
        finding = Finding.objects.create(
            engagement=engagement, title='X', found_by=self.lead,
            confidentiality_impact='H',
        )
        ev = Evidence.objects.create(
            finding=finding,
            file=SimpleUploadedFile('p.png', b'data', content_type='image/png'),
            uploaded_by=self.lead,
        )
        self.client.login(username='lead', password='testpass1')
        resp = self.client.get(reverse('vulns:evidence_download', args=[ev.pk]))
        b''.join(resp.streaming_content)  # close the handle
        row = self._only(AuditLog.Action.EVIDENCE_DOWNLOAD)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, str(ev.pk))

    def test_report_generated_and_downloaded_logged(self):
        from engagements.models import Engagement, EngagementMember
        engagement = Engagement.objects.create(
            name='E5', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=engagement, user=self.lead, role='lead',
        )
        self.client.login(username='lead', password='testpass1')
        self.client.post(reverse('reports:generate', args=[engagement.pk]),
                         {'report_type': 'full'})
        gen = self._only(AuditLog.Action.REPORT_GENERATED)
        self.assertEqual(gen.actor, self.lead)

        from reports.models import Report
        report = Report.objects.get(engagement=engagement)
        self.client.get(reverse('reports:download', args=[report.pk]))
        dl = self._only(AuditLog.Action.REPORT_DOWNLOADED)
        self.assertEqual(dl.actor, self.lead)
        self.assertEqual(dl.target, str(report.pk))

    def test_invitation_sent_logged(self):
        from engagements.models import Engagement, EngagementMember
        engagement = Engagement.objects.create(
            name='E6', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=engagement, user=self.lead, role='lead',
        )
        self.client.login(username='lead', password='testpass1')
        self.client.post(reverse('engagements:invite', args=[engagement.pk]), {
            'email': 'new@x.test', 'role': 'pentester',
        })
        row = self._only(AuditLog.Action.INVITATION_SENT)
        self.assertEqual(row.actor, self.lead)
        self.assertEqual(row.target, 'new@x.test')
        self.assertEqual(row.details['role'], 'pentester')

    def test_invitation_accepted_logged(self):
        from engagements.models import Engagement, EngagementMember, Invitation
        engagement = Engagement.objects.create(
            name='E7', client_name='ACME', created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=engagement, user=self.lead, role='lead',
        )
        invitee = User.objects.create_user(
            'newbie', role='client', password='testpass1', email='inv@x.test',
        )
        invitation = Invitation.objects.create(
            engagement=engagement, email='inv@x.test', role='pentester',
            invited_by=self.lead,
        )
        self.client.login(username='newbie', password='testpass1')
        self.client.get(reverse('engagements:accept_invitation', args=[invitation.token]))
        row = self._only(AuditLog.Action.INVITATION_ACCEPTED)
        self.assertEqual(row.actor, invitee)
        self.assertEqual(row.target, 'inv@x.test')


@override_settings(MFA_REQUIRED_ROLES=[])
class SecurityHeadersTests(TestCase):
    """Hit /dashboard/ as an authenticated user and assert every security
    header is present with the expected value."""

    def setUp(self):
        self.user = User.objects.create_user(
            'pt', role='pentester', password='testpass1',
        )
        self.client.force_login(self.user)

    def _response(self):
        return self.client.get(reverse('dashboard:home'))

    def test_csp_header(self):
        csp = self._response()['Content-Security-Policy']
        self.assertIn("default-src 'self'", csp)
        self.assertRegex(csp, r"script-src 'self' 'nonce-[^']+' https://cdn\.jsdelivr\.net")
        self.assertIn("style-src 'self' 'unsafe-inline'", csp)
        self.assertIn("img-src 'self' data:", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("base-uri 'self'", csp)
        self.assertIn("form-action 'self'", csp)

    def test_referrer_policy(self):
        self.assertEqual(
            self._response()['Referrer-Policy'],
            'strict-origin-when-cross-origin',
        )

    def test_permissions_policy(self):
        value = self._response()['Permissions-Policy']
        self.assertIn('camera=()', value)
        self.assertIn('microphone=()', value)
        self.assertIn('geolocation=()', value)

    def test_coop_header(self):
        self.assertEqual(
            self._response()['Cross-Origin-Opener-Policy'], 'same-origin',
        )

    def test_x_frame_options(self):
        self.assertEqual(self._response()['X-Frame-Options'], 'DENY')

    def test_nosniff(self):
        self.assertEqual(
            self._response()['X-Content-Type-Options'], 'nosniff',
        )

    def test_samesite_cookies(self):
        # Trigger a response that sets the CSRF cookie.
        resp = self.client.get(reverse('dashboard:home'))
        csrf = resp.cookies.get('csrftoken')
        if csrf is not None:
            self.assertEqual(csrf['samesite'], 'Strict')

    def test_samesite_session_setting(self):
        from django.conf import settings
        self.assertEqual(settings.SESSION_COOKIE_SAMESITE, 'Strict')
        self.assertEqual(settings.CSRF_COOKIE_SAMESITE, 'Strict')


@override_settings(
    MFA_REQUIRED_ROLES=[],
    AXES_ENABLED=True,
    AXES_FAILURE_LIMIT=5,
    AXES_RESET_ON_SUCCESS=True,
    AXES_LOCKOUT_PARAMETERS=[['username', 'ip_address']],
)
class LoginLockoutTests(TestCase):
    def setUp(self):
        from axes.utils import reset
        reset()
        self.client = Client()
        self.user = User.objects.create_user('victim', role='pentester', password='testpass1')

    def tearDown(self):
        from axes.utils import reset
        reset()

    def test_sixth_attempt_is_locked_out(self):
        url = reverse('accounts:login')
        # 5 failed attempts hit AXES_FAILURE_LIMIT and trigger lockout.
        for _ in range(5):
            self.client.post(url, {'username': 'victim', 'password': 'wrong'})
        # Subsequent attempt is blocked with the axes lockout response.
        resp = self.client.post(url, {'username': 'victim', 'password': 'wrong'})
        self.assertIn(resp.status_code, (403, 429))
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.LOGIN_LOCKED, target='victim',
            ).exists()
        )

    def test_login_success_is_logged(self):
        self.client.post(reverse('accounts:login'), {'username': 'victim', 'password': 'testpass1'})
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.LOGIN_SUCCESS, target='victim',
            ).exists()
        )

    def test_logout_is_logged(self):
        # force_login bypasses authenticate() — needed because axes is
        # re-enabled here and rejects test client's request-less login.
        self.client.force_login(self.user)
        self.client.post(reverse('accounts:logout'))
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.LOGOUT, target='victim',
            ).exists()
        )
