from django.test import TestCase, override_settings
from django.urls import reverse
from django.core.exceptions import ValidationError, PermissionDenied
from accounts.models import User, AuditLog
from engagements.models import Engagement, EngagementMember, AttackPath, AttackPathNode, AttackPathEdge
from engagements.services import confirm_scope
from engagements.forms import AttackPathEdgeForm
from engagements.selectors import attack_path_context
from vulns.models import Finding


@override_settings(MFA_REQUIRED_ROLES=[])
class RedTeamWorkflowTests(TestCase):
    def setUp(self):
        self.lead = User.objects.create_user('lead', role='pentester')
        self.customer = User.objects.create_user('customer', role='client')
        self.eng = Engagement.objects.create(name='Assessment', engagement_type='red_team', in_scope='test.example', rules_of_engagement='Staging only', authorization_reference='Approved RoE v1')
        EngagementMember.objects.create(engagement=self.eng, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.eng, user=self.customer, role='client')
        self.path = AttackPath.objects.create(engagement=self.eng, name='Entry to objective')
        self.entry = AttackPathNode.objects.create(path=self.path, kind='entrypoint', label='Entry')
        self.goal = AttackPathNode.objects.create(path=self.path, kind='objective', label='Goal')
        self.client.force_login(self.lead)

    def test_confirmation_is_explicit_idempotent_and_audited(self):
        kwargs = dict(actor=self.lead, engagement=self.eng, action='confirm', acknowledged=True)
        confirm_scope(**kwargs)
        confirm_scope(**kwargs)
        self.eng.refresh_from_db()
        self.assertTrue(self.eng.roe_signed_off)
        self.assertEqual(AuditLog.objects.filter(action='scope_confirmation').count(), 1)
        self.assertEqual(AuditLog.objects.get(action='scope_confirmation').details['authorization_reference'], 'Approved RoE v1')
        with self.assertRaises(ValidationError):
            confirm_scope(actor=self.lead, engagement=self.eng, action='reopen')
        confirm_scope(actor=self.lead, engagement=self.eng, action='reopen', reason='New target requested')
        self.eng.refresh_from_db()
        self.assertFalse(self.eng.roe_signed_off)

    def test_confirmation_requires_reference_acknowledgement_and_lead(self):
        with self.assertRaises(PermissionDenied):
            confirm_scope(actor=self.customer, engagement=self.eng, action='confirm', acknowledged=True)
        with self.assertRaises(ValidationError):
            confirm_scope(actor=self.lead, engagement=self.eng, action='confirm')
        self.eng.authorization_reference = ''
        self.eng.save()
        with self.assertRaises(ValidationError):
            confirm_scope(actor=self.lead, engagement=self.eng, action='confirm', acknowledged=True)

    def test_http_confirmation_does_not_toggle_on_repeat(self):
        url = reverse('engagements:toggle_roe_signoff', args=[self.eng.pk])
        for _ in range(2):
            self.assertEqual(self.client.post(url, {'action':'confirm', 'acknowledged':'on'}).status_code, 302)
        self.eng.refresh_from_db()
        self.assertTrue(self.eng.roe_signed_off)

    def test_cycle_rejected_and_objective_reachability(self):
        self.assertFalse(attack_path_context(self.path, self.lead)['path_connected'])
        AttackPathEdge.objects.create(path=self.path, from_node=self.entry, to_node=self.goal, technique='Validated access')
        self.assertTrue(attack_path_context(self.path, self.lead)['path_connected'])
        form = AttackPathEdgeForm({'from_node':self.goal.pk, 'to_node':self.entry.pk, 'technique':'Return'}, path=self.path)
        self.assertFalse(form.is_valid())
        self.assertIn('cycle', str(form.errors))

    def test_client_path_does_not_expose_unpublished_finding(self):
        finding = Finding.objects.create(engagement=self.eng, title='Private draft', review_state='draft')
        AttackPathEdge.objects.create(path=self.path, from_node=self.entry, to_node=self.goal, technique='Validated access', finding=finding)
        self.client.force_login(self.customer)
        response = self.client.get(reverse('engagements:attack_path_detail', args=[self.eng.pk, self.path.pk]))
        self.assertNotContains(response, 'Private draft')
        data = self.client.get(reverse('engagements:attack_path_data', args=[self.eng.pk, self.path.pk])).json()
        self.assertIsNone(data['edges'][0]['finding_pk'])
        self.assertIsNone(data['edges'][0]['finding_title'])

    def test_path_can_be_renamed_by_lead_but_not_client(self):
        url = reverse('engagements:attack_path_detail', args=[self.eng.pk, self.path.pk])
        self.assertEqual(self.client.post(url, {'name':'Revised objective', 'description':'Observed route'}).status_code, 302)
        self.path.refresh_from_db()
        self.assertEqual(self.path.name, 'Revised objective')
        self.client.force_login(self.customer)
        self.assertEqual(self.client.post(url, {'name':'Unwanted change'}).status_code, 403)
