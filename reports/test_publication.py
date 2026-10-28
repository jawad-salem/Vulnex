from django.test import TestCase, override_settings
from django.urls import reverse
from django.core.files.base import ContentFile
from rest_framework.test import APIClient
from accounts.models import User
from engagements.models import Engagement, EngagementMember
from reports.models import Report


@override_settings(MFA_REQUIRED_ROLES=[])
class PublicationTests(TestCase):
    def setUp(self):
        self.lead = User.objects.create_user('lead', role='pentester')
        self.customer = User.objects.create_user('customer', role='client')
        self.tester = User.objects.create_user('tester', role='pentester')
        self.eng = Engagement.objects.create(name='Assessment', engagement_type='webapp')
        for user, role in [(self.lead,'lead'), (self.customer,'client'), (self.tester,'pentester')]:
            EngagementMember.objects.create(engagement=self.eng, user=user, role=role)
        self.report = Report.objects.create(engagement=self.eng, title='Private report')
        self.report.file.save('example.pdf', ContentFile(b'%PDF-1.4 test'))
        self.url = reverse('reports:publish', args=[self.report.pk])
        self.api = APIClient()

    def test_drafts_hidden_from_clients_on_all_surfaces(self):
        self.client.force_login(self.customer)
        self.assertNotContains(self.client.get(reverse('reports:dashboard', args=[self.eng.pk])), 'Private report')
        self.assertEqual(self.client.get(reverse('reports:download', args=[self.report.pk])).status_code, 404)
        self.assertEqual(self.client.get(reverse('reports:preview', args=[self.eng.pk])).status_code, 302)
        self.api.force_authenticate(self.customer)
        self.assertEqual(self.api.get(f'/api/v1/reports/{self.report.pk}/').status_code, 404)
        self.assertEqual(self.api.get(f'/api/v1/reports/{self.report.pk}/pdf/').status_code, 404)

    def test_publish_and_withdraw_control_both_download_paths(self):
        self.client.force_login(self.lead)
        self.client.post(self.url, {'action':'publish', 'acknowledged':'on'})
        self.report.refresh_from_db()
        self.assertEqual(self.report.published_by, self.lead)
        self.client.force_login(self.customer)
        response = self.client.get(reverse('reports:download', args=[self.report.pk]))
        self.assertEqual(response.status_code, 200)
        response.close()
        self.api.force_authenticate(self.customer)
        response = self.api.get(f'/api/v1/reports/{self.report.pk}/pdf/')
        self.assertEqual(response.status_code, 200)
        response.close()
        self.client.force_login(self.lead)
        self.client.post(self.url, {'action':'withdraw'})
        self.assertEqual(self.api.get(f'/api/v1/reports/{self.report.pk}/pdf/').status_code, 404)

    def test_publication_requires_lead_confirmation_and_post(self):
        self.client.force_login(self.lead)
        self.assertEqual(self.client.get(self.url).status_code, 405)
        self.client.post(self.url, {'action':'publish'})
        self.report.refresh_from_db()
        self.assertIsNone(self.report.published_at)
        self.client.force_login(self.tester)
        self.assertEqual(self.client.post(self.url, {'action':'publish', 'acknowledged':'on'}).status_code, 403)

    def test_missing_report_file_returns_404(self):
        self.client.force_login(self.lead)
        self.report.file.delete(save=True)
        self.assertEqual(self.client.get(reverse('reports:download', args=[self.report.pk])).status_code, 404)
