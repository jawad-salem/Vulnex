from django.test import TestCase, Client
from django.urls import reverse
from .models import User


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
