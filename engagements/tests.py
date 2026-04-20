from django.test import TestCase, Client, override_settings
from django.urls import reverse
from accounts.models import User
from .models import Engagement, EngagementMember, Invitation


@override_settings(MFA_REQUIRED_ROLES=[])
class EngagementAccessTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('admin', role='admin', password='testpass1')
        self.pentester = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.reviewer = User.objects.create_user('rev', role='reviewer', password='testpass1')
        self.client_user = User.objects.create_user('cli', role='client', password='testpass1', email='cli@test.com')
        self.outsider = User.objects.create_user('outsider', role='pentester', password='testpass1')

        self.engagement = Engagement.objects.create(
            name='Test Engagement',
            client_name='ACME',
            created_by=self.admin,
        )
        # Add members
        EngagementMember.objects.create(engagement=self.engagement, user=self.pentester, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.reviewer, role='reviewer')
        EngagementMember.objects.create(engagement=self.engagement, user=self.client_user, role='client')

    def test_admin_can_access_any_engagement(self):
        self.client.login(username='admin', password='testpass1')
        resp = self.client.get(reverse('engagements:detail', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 200)

    def test_member_can_access_engagement(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('engagements:detail', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 200)

    def test_outsider_cannot_access_engagement(self):
        self.client.login(username='outsider', password='testpass1')
        resp = self.client.get(reverse('engagements:detail', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 302)  # Redirected

    def test_client_can_access_engagement_detail(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('engagements:detail', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 200)

    def test_client_blocked_from_recon(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('recon:dashboard', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 302)

    def test_client_blocked_from_methodology(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('methodology:dashboard', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 302)

    def test_reviewer_can_view_recon(self):
        self.client.login(username='rev', password='testpass1')
        resp = self.client.get(reverse('recon:dashboard', args=[self.engagement.pk]))
        self.assertEqual(resp.status_code, 200)

    def test_only_pentester_can_create_engagement(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('engagements:create'))
        self.assertEqual(resp.status_code, 200)

    def test_reviewer_cannot_create_engagement(self):
        self.client.login(username='rev', password='testpass1')
        resp = self.client.get(reverse('engagements:create'))
        self.assertEqual(resp.status_code, 302)

    def test_client_cannot_create_engagement(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('engagements:create'))
        self.assertEqual(resp.status_code, 302)


class EngagementModelTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user('admin', role='admin', password='testpass1')
        self.pentester = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Test', client_name='ACME', created_by=self.admin,
        )
        self.membership = EngagementMember.objects.create(
            engagement=self.engagement, user=self.pentester, role='lead',
        )

    def test_user_can_access_admin(self):
        self.assertTrue(self.engagement.user_can_access(self.admin))

    def test_user_can_access_member(self):
        self.assertTrue(self.engagement.user_can_access(self.pentester))

    def test_user_can_access_non_member(self):
        outsider = User.objects.create_user('out', role='pentester', password='testpass1')
        self.assertFalse(self.engagement.user_can_access(outsider))

    def test_user_can_edit_lead(self):
        self.assertTrue(self.engagement.user_can_edit(self.pentester))

    def test_user_can_edit_reviewer(self):
        reviewer = User.objects.create_user('rev', role='reviewer', password='testpass1')
        EngagementMember.objects.create(
            engagement=self.engagement, user=reviewer, role='reviewer',
        )
        self.assertFalse(self.engagement.user_can_edit(reviewer))

    def test_user_can_edit_client(self):
        cli = User.objects.create_user('cli', role='client', password='testpass1')
        EngagementMember.objects.create(
            engagement=self.engagement, user=cli, role='client',
        )
        self.assertFalse(self.engagement.user_can_edit(cli))

    def test_user_is_lead_admin(self):
        self.assertTrue(self.engagement.user_is_lead(self.admin))

    def test_user_is_lead_actual_lead(self):
        self.assertTrue(self.engagement.user_is_lead(self.pentester))


@override_settings(MFA_REQUIRED_ROLES=[])
class InvitationFlowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user(
            'admin', role='admin', password='testpass1', email='admin@test.com',
        )
        self.engagement = Engagement.objects.create(
            name='Test', client_name='ACME', created_by=self.admin,
        )
        EngagementMember.objects.create(
            engagement=self.engagement, user=self.admin, role='lead',
        )

    def test_invite_existing_user_auto_adds(self):
        """Inviting an existing user should auto-add them as a member."""
        existing = User.objects.create_user(
            'existing', role='pentester', password='testpass1', email='existing@test.com',
        )
        self.client.login(username='admin', password='testpass1')
        self.client.post(reverse('engagements:invite', args=[self.engagement.pk]), {
            'email': 'existing@test.com',
            'role': 'pentester',
        })
        self.assertTrue(
            EngagementMember.objects.filter(
                engagement=self.engagement, user=existing,
            ).exists()
        )

    def test_invite_new_user_creates_pending_invitation(self):
        """Inviting a non-existing email should create a pending invitation."""
        self.client.login(username='admin', password='testpass1')
        self.client.post(reverse('engagements:invite', args=[self.engagement.pk]), {
            'email': 'newuser@test.com',
            'role': 'client',
        })
        self.assertTrue(
            Invitation.objects.filter(
                engagement=self.engagement, email='newuser@test.com', status='pending',
            ).exists()
        )

    def test_accept_invitation_logged_in_user(self):
        """Logged-in user with matching email should be added to engagement."""
        user = User.objects.create_user(
            'invitee', role='reviewer', password='testpass1', email='invitee@test.com',
        )
        invitation = Invitation.objects.create(
            engagement=self.engagement, email='invitee@test.com',
            role='reviewer', invited_by=self.admin,
        )
        self.client.login(username='invitee', password='testpass1')
        resp = self.client.get(reverse('engagements:accept_invitation', args=[invitation.token]))
        self.assertEqual(resp.status_code, 302)  # Redirect to engagement detail
        self.assertTrue(
            EngagementMember.objects.filter(
                engagement=self.engagement, user=user, role='reviewer',
            ).exists()
        )
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, 'accepted')

    def test_accept_invitation_wrong_email_blocked(self):
        """Logged-in user with wrong email should be blocked."""
        User.objects.create_user(
            'wronguser', role='pentester', password='testpass1', email='wrong@test.com',
        )
        invitation = Invitation.objects.create(
            engagement=self.engagement, email='correct@test.com',
            role='pentester', invited_by=self.admin,
        )
        self.client.login(username='wronguser', password='testpass1')
        resp = self.client.get(reverse('engagements:accept_invitation', args=[invitation.token]))
        self.assertEqual(resp.status_code, 302)
        # Should NOT be a member
        self.assertFalse(
            EngagementMember.objects.filter(
                engagement=self.engagement, user__email='wrong@test.com',
            ).exists()
        )

    def test_accept_invitation_anon_new_user_shows_registration(self):
        """Anonymous user with no account should see a registration form."""
        invitation = Invitation.objects.create(
            engagement=self.engagement, email='brand-new@test.com',
            role='client', invited_by=self.admin,
        )
        resp = self.client.get(reverse('engagements:accept_invitation', args=[invitation.token]))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Create account')

    def test_accept_invitation_anon_new_user_registers(self):
        """Anonymous user should be able to register via invitation."""
        invitation = Invitation.objects.create(
            engagement=self.engagement, email='newclient@test.com',
            role='client', invited_by=self.admin,
        )
        resp = self.client.post(
            reverse('engagements:accept_invitation', args=[invitation.token]),
            {
                'username': 'newclient',
                'first_name': 'New',
                'last_name': 'Client',
                'password1': 'securepass123',
                'password2': 'securepass123',
            },
        )
        self.assertEqual(resp.status_code, 302)  # Redirect to engagement

        # User created with correct role
        new_user = User.objects.get(username='newclient')
        self.assertEqual(new_user.email, 'newclient@test.com')
        self.assertEqual(new_user.role, 'client')

        # Member added
        self.assertTrue(
            EngagementMember.objects.filter(
                engagement=self.engagement, user=new_user, role='client',
            ).exists()
        )

        # Invitation accepted
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, 'accepted')

    def test_accept_invitation_anon_existing_user_redirects_to_login(self):
        """Anonymous user with existing account should be told to log in."""
        User.objects.create_user(
            'existinguser', role='pentester', password='testpass1', email='exists@test.com',
        )
        invitation = Invitation.objects.create(
            engagement=self.engagement, email='exists@test.com',
            role='pentester', invited_by=self.admin,
        )
        resp = self.client.get(reverse('engagements:accept_invitation', args=[invitation.token]))
        self.assertEqual(resp.status_code, 302)
        self.assertIn('login', resp.url)

    def test_duplicate_invite_blocked(self):
        """Duplicate pending invitation should show warning."""
        Invitation.objects.create(
            engagement=self.engagement, email='dup@test.com',
            role='pentester', invited_by=self.admin,
        )
        self.client.login(username='admin', password='testpass1')
        self.client.post(reverse('engagements:invite', args=[self.engagement.pk]), {
            'email': 'dup@test.com',
            'role': 'pentester',
        })
        # Should still be just 1 invitation
        self.assertEqual(
            Invitation.objects.filter(email='dup@test.com').count(), 1
        )
