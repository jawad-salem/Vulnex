from django.test import TestCase, Client, override_settings
from django.urls import reverse
from accounts.models import User
from .models import (
    Engagement, EngagementMember, Invitation, Client as EngagementClient,
    AttackPath, AttackPathNode, AttackPathEdge,
)


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
            client=EngagementClient.objects.get_or_create(name='ACME')[0],
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
            name='Test', client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.admin,
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
            name='Test', client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.admin,
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

    def test_accept_invitation_does_not_promote_global_role(self):
        """Step 1.4 — a Client invited as 'lead' on engagement B must keep
        role='client' globally and only gain lead privileges on engagement B.
        Prior behavior (_maybe_promote_global_role) leaked privilege across
        engagements.
        """
        client_user = User.objects.create_user(
            'clientuser', role='client', password='testpass1',
            email='clientuser@test.com',
        )
        engagement_b = Engagement.objects.create(
            name='Other', client=EngagementClient.objects.get_or_create(name='OtherCo')[0], created_by=self.admin,
        )
        invitation = Invitation.objects.create(
            engagement=engagement_b, email='clientuser@test.com',
            role='lead', invited_by=self.admin,
        )
        self.client.login(username='clientuser', password='testpass1')
        resp = self.client.get(
            reverse('engagements:accept_invitation', args=[invitation.token])
        )
        self.assertEqual(resp.status_code, 302)

        client_user.refresh_from_db()
        self.assertEqual(client_user.role, 'client')  # global role untouched
        self.assertTrue(
            EngagementMember.objects.filter(
                engagement=engagement_b, user=client_user, role='lead',
            ).exists()
        )
        # No USER_ROLE_CHANGE audit entry should have been written.
        from accounts.models import AuditLog
        self.assertFalse(
            AuditLog.objects.filter(
                action=AuditLog.Action.USER_ROLE_CHANGE,
                target='clientuser',
            ).exists()
        )

    def test_invite_existing_user_does_not_promote_global_role(self):
        """Admin inviting an existing Client as 'pentester' on engagement A
        must not change the client's global role."""
        client_user = User.objects.create_user(
            'cli2', role='client', password='testpass1', email='cli2@test.com',
        )
        self.client.login(username='admin', password='testpass1')
        self.client.post(reverse('engagements:invite', args=[self.engagement.pk]), {
            'email': 'cli2@test.com',
            'role': 'pentester',
        })
        client_user.refresh_from_db()
        self.assertEqual(client_user.role, 'client')
        self.assertTrue(
            EngagementMember.objects.filter(
                engagement=self.engagement, user=client_user, role='pentester',
            ).exists()
        )

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


@override_settings(MFA_REQUIRED_ROLES=[])
class AttackPathTests(TestCase):
    """Attack path mapper: red-team gating, role enforcement, CRUD, JSON, PDF."""

    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='pw')
        self.outsider = User.objects.create_user('out', role='pentester', password='pw')
        self.client_user = User.objects.create_user('cli', role='client', password='pw')
        self.eng_client = EngagementClient.objects.get_or_create(name='ACME')[0]

        self.red_team = Engagement.objects.create(
            name='RT-1', client=self.eng_client, created_by=self.lead,
            engagement_type='red_team',
        )
        EngagementMember.objects.create(engagement=self.red_team, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.red_team, user=self.client_user, role='client')

        self.web_eng = Engagement.objects.create(
            name='Web-1', client=self.eng_client, created_by=self.lead,
            engagement_type='webapp',
        )
        EngagementMember.objects.create(engagement=self.web_eng, user=self.lead, role='lead')

    def _login(self, user):
        self.client.login(username=user, password='pw')

    def test_non_red_team_blocked(self):
        self._login('lead')
        resp = self.client.get(reverse('engagements:attack_path_list', args=[self.web_eng.pk]))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(self.web_eng.attack_paths.count(), 0)

    def test_outsider_cannot_access(self):
        self._login('out')
        resp = self.client.get(reverse('engagements:attack_path_list', args=[self.red_team.pk]))
        self.assertEqual(resp.status_code, 302)

    def test_lead_creates_path(self):
        self._login('lead')
        resp = self.client.post(
            reverse('engagements:attack_path_list', args=[self.red_team.pk]),
            {'name': 'External → DA', 'description': 'phish to DA'},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(self.red_team.attack_paths.count(), 1)
        path = self.red_team.attack_paths.get()
        self.assertEqual(path.created_by, self.lead)

    def test_client_can_view_but_not_edit(self):
        path = AttackPath.objects.create(
            engagement=self.red_team, name='P1', created_by=self.lead,
        )
        self._login('cli')
        resp = self.client.get(
            reverse('engagements:attack_path_detail', args=[self.red_team.pk, path.pk]),
        )
        self.assertEqual(resp.status_code, 200)
        # Client cannot create nodes (engagement_edit_required redirects).
        resp = self.client.post(
            reverse('engagements:attack_path_node_create', args=[self.red_team.pk, path.pk]),
            {'label': 'Foo', 'kind': 'host'},
        )
        self.assertIn(resp.status_code, (302, 403))
        self.assertEqual(path.nodes.count(), 0)

    def test_lead_adds_nodes_and_edge(self):
        path = AttackPath.objects.create(
            engagement=self.red_team, name='P1', created_by=self.lead,
        )
        self._login('lead')
        self.client.post(
            reverse('engagements:attack_path_node_create', args=[self.red_team.pk, path.pk]),
            {'label': 'Phish', 'kind': 'entrypoint'},
        )
        self.client.post(
            reverse('engagements:attack_path_node_create', args=[self.red_team.pk, path.pk]),
            {'label': 'DA', 'kind': 'objective'},
        )
        self.assertEqual(path.nodes.count(), 2)
        a, b = path.nodes.all()
        self.client.post(
            reverse('engagements:attack_path_edge_create', args=[self.red_team.pk, path.pk]),
            {'from_node': str(a.pk), 'to_node': str(b.pk),
             'technique': 'Pass-the-Hash', 'mitre_attack_id': 'T1550'},
        )
        self.assertEqual(path.edges.count(), 1)
        self.assertEqual(path.edges.get().mitre_attack_id, 'T1550')

    def test_self_loop_rejected(self):
        path = AttackPath.objects.create(
            engagement=self.red_team, name='P1', created_by=self.lead,
        )
        node = AttackPathNode.objects.create(path=path, label='X', kind='host')
        self._login('lead')
        self.client.post(
            reverse('engagements:attack_path_edge_create', args=[self.red_team.pk, path.pk]),
            {'from_node': str(node.pk), 'to_node': str(node.pk), 'technique': 'X'},
        )
        self.assertEqual(path.edges.count(), 0)

    def test_data_endpoint_shape(self):
        path = AttackPath.objects.create(
            engagement=self.red_team, name='P1', created_by=self.lead,
        )
        a = AttackPathNode.objects.create(path=path, label='Phish', kind='entrypoint')
        b = AttackPathNode.objects.create(path=path, label='DA', kind='objective')
        AttackPathEdge.objects.create(
            path=path, from_node=a, to_node=b,
            technique='Phishing', mitre_attack_id='T1566',
        )
        self._login('lead')
        resp = self.client.get(
            reverse('engagements:attack_path_data', args=[self.red_team.pk, path.pk]),
        )
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertEqual(len(payload['nodes']), 2)
        self.assertEqual(len(payload['edges']), 1)
        self.assertEqual(payload['edges'][0]['technique'], 'Phishing')
        self.assertEqual(payload['edges'][0]['mitre'], 'T1566')

    def test_data_endpoint_blocked_on_non_red_team(self):
        # Manually plant a path on the wrong engagement type to confirm the
        # type-check guard fires on the JSON endpoint too.
        path = AttackPath.objects.create(
            engagement=self.web_eng, name='P1', created_by=self.lead,
        )
        self._login('lead')
        resp = self.client.get(
            reverse('engagements:attack_path_data', args=[self.web_eng.pk, path.pk]),
        )
        self.assertEqual(resp.status_code, 403)

    def test_pdf_includes_attack_paths_section(self):
        path = AttackPath.objects.create(
            engagement=self.red_team, name='External-to-DA', created_by=self.lead,
        )
        a = AttackPathNode.objects.create(path=path, label='Phish', kind='entrypoint')
        b = AttackPathNode.objects.create(path=path, label='DA', kind='objective')
        AttackPathEdge.objects.create(
            path=path, from_node=a, to_node=b,
            technique='Pass-the-Hash', mitre_attack_id='T1550',
        )
        from reports.generator import generate_report_pdf
        pdf = generate_report_pdf(self.red_team, report_type='technical')
        self.assertTrue(pdf.startswith(b'%PDF'))
        # The report should be larger than a no-attack-path baseline; this is a
        # smoke test that the section was emitted without raising.
        self.assertGreater(len(pdf), 5000)
