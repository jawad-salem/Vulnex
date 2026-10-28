"""Regression coverage for rules shared by UI and API."""
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIClient
from accounts.models import User
from credentials.models import Credential
from engagements.models import Engagement, EngagementMember
from vulns.models import Finding


@override_settings(MFA_REQUIRED_ROLES=[])
class WorkflowBoundaryTests(TestCase):
    def setUp(self):
        self.api = APIClient()
        self.lead = User.objects.create_user('lead', role='pentester')
        self.tester = User.objects.create_user('tester', role='pentester')
        self.reviewer = User.objects.create_user('reviewer', role='reviewer')
        self.customer = User.objects.create_user('customer', role='client')
        self.eng = Engagement.objects.create(name='Assessment', engagement_type='webapp', created_by=self.lead)
        for user, role in [(self.lead, 'lead'), (self.tester, 'pentester'), (self.reviewer, 'reviewer'), (self.customer, 'client')]:
            EngagementMember.objects.create(engagement=self.eng, user=user, role=role)
        self.finding = Finding.objects.create(engagement=self.eng, title='Draft evidence', found_by=self.tester)
        self.url = f'/api/v1/findings/{self.finding.pk}/'
        self.api.force_authenticate(self.tester)

    def test_api_creator_becomes_lead_and_can_retrieve(self):
        response = self.api.post('/api/v1/engagements/', {'name': 'New', 'engagement_type': 'webapp'}, format='json')
        self.assertEqual(response.status_code, 201, response.data)
        pk = response.data['id']
        self.assertTrue(EngagementMember.objects.filter(engagement_id=pk, user=self.tester, role='lead').exists())
        self.assertEqual(self.api.get(f'/api/v1/engagements/{pk}/').status_code, 200)

    def test_signed_off_scope_is_locked_on_both_surfaces(self):
        self.eng.roe_signed_off = True
        self.eng.save()
        response = self.api.patch(f'/api/v1/engagements/{self.eng.pk}/', {'in_scope': 'changed.example'}, format='json')
        self.assertEqual(response.status_code, 400)
        self.client.force_login(self.tester)
        self.assertEqual(self.client.get(reverse('engagements:edit', args=[self.eng.pk])).status_code, 302)
        self.eng.refresh_from_db()
        self.assertEqual(self.eng.in_scope, '')

    def test_editor_cannot_delete_engagement(self):
        response = self.api.delete(f'/api/v1/engagements/{self.eng.pk}/')
        self.assertEqual(response.status_code, 403)
        self.assertTrue(Engagement.objects.filter(pk=self.eng.pk).exists())

    def test_direct_review_field_cannot_approve(self):
        self.api.patch(self.url, {'review_state': 'approved'}, format='json')
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, 'draft')

    def test_review_transition_requires_reviewer_and_valid_state(self):
        response = self.api.post(self.url + 'review/', {'state': 'in_review'}, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(self.api.post(self.url + 'review/', {'state': 'approved'}, format='json').status_code, 403)
        self.api.force_authenticate(self.reviewer)
        self.assertEqual(self.api.post(self.url + 'review/', {'state': 'changes_requested'}, format='json').status_code, 400)
        self.assertEqual(self.api.post(self.url + 'review/', {'state': 'approved'}, format='json').status_code, 200)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.reviewed_by, self.reviewer)
        self.assertIsNotNone(self.finding.reviewed_at)
        self.assertEqual(self.api.post(self.url + 'review/', {'state': 'approved'}, format='json').status_code, 400)

    def test_client_cannot_read_draft_through_any_finding_route(self):
        self.api.force_authenticate(self.customer)
        self.assertEqual(self.api.get(self.url).status_code, 404)
        self.assertEqual(self.api.get(self.url + 'evidence/').status_code, 404)
        self.assertEqual(self.api.get('/api/v1/findings/').data['count'], 0)
        self.assertEqual(self.api.get(f'/api/v1/engagements/{self.eng.pk}/findings/').data, [])
        Finding.objects.filter(pk=self.finding.pk).update(review_state='approved')
        self.assertEqual(self.api.get(self.url).status_code, 200)

    def test_engagement_role_controls_visibility_even_for_global_pentester(self):
        EngagementMember.objects.filter(engagement=self.eng, user=self.tester).update(role='client')
        self.assertEqual(self.api.get('/api/v1/findings/').data['count'], 0)
        self.assertEqual(self.api.get(self.url).status_code, 404)
        cred = Credential(engagement=self.eng, username='secret-owner')
        cred.set_secret('secret')
        cred.save()
        self.assertEqual(self.api.get('/api/v1/credentials/').data['count'], 0)

    def test_cannot_move_records_to_another_engagement(self):
        other = Engagement.objects.create(name='Other', engagement_type='webapp')
        response = self.api.patch(self.url, {'engagement': str(other.pk)}, format='json')
        self.assertEqual(response.status_code, 400)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.engagement_id, self.eng.pk)
        cred = Credential(engagement=self.eng, username='owner')
        cred.set_secret('secret')
        cred.save()
        response = self.api.patch(f'/api/v1/credentials/{cred.pk}/', {'engagement': str(other.pk)}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_overview_work_queue_and_retest_filter(self):
        self.client.force_login(self.lead)
        response = self.client.get(reverse('engagements:detail', args=[self.eng.pk]))
        self.assertContains(response, 'Move this engagement forward')
        self.assertContains(response, 'Confirmation pending')
        Finding.objects.filter(pk=self.finding.pk).update(status='remediated', retest_status='fixed')
        response = self.client.get(reverse('vulns:list', args=[self.eng.pk]), {'retest': 'not_retested'})
        self.assertNotContains(response, 'Draft evidence')
        self.client.force_login(self.customer)
        response = self.client.get(reverse('engagements:detail', args=[self.eng.pk]))
        self.assertNotContains(response, 'Move this engagement forward')
        self.assertNotContains(response, 'Assets &amp; recon')

    def test_client_summary_and_recon_match_ui_visibility(self):
        from recon.models import DiscoveredHost
        DiscoveredHost.objects.create(engagement=self.eng, hostname='internal.example')
        self.api.force_authenticate(self.customer)
        response = self.api.get(f'/api/v1/engagements/{self.eng.pk}/')
        self.assertEqual(response.data['finding_count'], 0)
        self.assertEqual(self.api.get('/api/v1/hosts/').data['count'], 0)
        self.api.force_authenticate(self.tester)
        self.assertEqual(self.api.get('/api/v1/hosts/').data['count'], 1)

    def test_client_finding_page_hides_internal_navigation(self):
        Finding.objects.filter(pk=self.finding.pk).update(review_state='approved')
        self.client.force_login(self.customer)
        response = self.client.get(reverse('vulns:detail', args=[self.finding.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Assets &amp; recon')
        self.assertContains(response, 'aria-label="Engagement workspace"')

    def test_browser_and_api_share_the_review_transition(self):
        self.client.force_login(self.tester)
        self.client.post(reverse('vulns:submit_review', args=[self.finding.pk]))
        self.api.force_authenticate(self.reviewer)
        response = self.api.post(self.url + 'review/', {'state': 'changes_requested', 'notes': 'Add proof.'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_notes, 'Add proof.')
        self.client.post(reverse('vulns:submit_review', args=[self.finding.pk]))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, 'in_review')
        self.assertIsNone(self.finding.reviewed_by)
