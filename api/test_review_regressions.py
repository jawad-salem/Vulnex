from django.test import TestCase, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient
from accounts.models import User
from engagements.models import Engagement, EngagementMember
from vulns.models import Finding
from methodology.models import Methodology, ChecklistCategory, ChecklistItem, EngagementChecklist


@override_settings(MFA_REQUIRED_ROLES=[])
class ReviewRegressionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('operator', role='pentester')
        self.other = User.objects.create_user('other', role='pentester')
        self.eng = Engagement.objects.create(name='Assessment', engagement_type='webapp')
        for user in [self.user, self.other]:
            EngagementMember.objects.create(engagement=self.eng, user=user, role='lead')
        self.finding = Finding.objects.create(engagement=self.eng, title='Assigned to operator', assigned_to=self.user)
        Finding.objects.create(engagement=self.eng, title='Assigned elsewhere', assigned_to=self.other)
        self.client.force_login(self.user)
        self.api = APIClient()
        self.api.force_authenticate(self.user)

    def test_assignee_filter_and_invalid_filter(self):
        url = reverse('vulns:list', args=[self.eng.pk])
        response = self.client.get(url, {'assigned':str(self.user.pk)})
        self.assertEqual(list(response.context['findings']), [self.finding])
        self.assertEqual(self.client.get(url, {'assigned':'bad-id'}).context['page_obj'].paginator.count, 0)

    def test_api_evidence_obeys_ui_file_policy(self):
        url = f'/api/v1/findings/{self.finding.pk}/evidence/'
        response = self.api.post(url, {'file':SimpleUploadedFile('payload.html', b'<script>test</script>')}, format='multipart')
        self.assertEqual(response.status_code, 400)
        response = self.api.post(url, {'file':SimpleUploadedFile('response.txt', b'Captured response')}, format='multipart')
        self.assertEqual(response.status_code, 201, response.data)

    def test_checklist_get_does_not_mutate_and_reopening_clears_completion(self):
        method = Methodology.objects.create(name='Method')
        category = ChecklistCategory.objects.create(methodology=method, name='Checks')
        item = ChecklistItem.objects.create(category=category, title='Check')
        from methodology.views import apply_methodology, update_checklist_item
        from django.test import RequestFactory
        factory = RequestFactory()
        request = factory.get('/')
        request.user = self.user
        self.assertEqual(apply_methodology(request, engagement_pk=self.eng.pk, methodology_pk=method.pk).status_code, 405)
        self.assertEqual(update_checklist_item(request, engagement_pk=self.eng.pk, item_id=item.pk).status_code, 405)
        self.assertFalse(EngagementChecklist.objects.exists())
        from django.contrib.messages.storage.fallback import FallbackStorage
        def update(status):
            req = factory.post('/', {'status':status})
            req.user = self.user
            req.session = {}
            req._messages = FallbackStorage(req)
            return update_checklist_item(req, engagement_pk=self.eng.pk, item_id=item.pk)
        update('completed')
        update('not_started')
        ec = EngagementChecklist.objects.get()
        self.assertIsNone(ec.completed_at)
        self.assertIsNone(ec.completed_by)

    def test_changing_approved_content_returns_it_to_draft(self):
        self.finding.review_state = 'approved'
        self.finding.save()
        response = self.api.patch(f'/api/v1/findings/{self.finding.pk}/', {'description':'New, unreviewed content'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, 'draft')
        self.assertIsNone(self.finding.reviewed_by)

    def test_status_only_update_preserves_approval(self):
        self.finding.review_state = 'approved'
        self.finding.save()
        response = self.api.patch(f'/api/v1/findings/{self.finding.pk}/', {'status':'confirmed'}, format='json')
        self.assertEqual(response.status_code, 200)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, 'approved')

    def test_partial_content_save_also_invalidates_review(self):
        self.finding.review_state = 'in_review'
        self.finding.save()
        self.finding.title = 'Changed finding title'
        self.finding.save(update_fields=['title'])
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, 'draft')
