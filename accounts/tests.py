from django.test import TestCase, Client
from django.urls import reverse
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
