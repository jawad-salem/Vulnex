from django.test import TestCase, override_settings
from django.urls import reverse
from accounts.models import User
from engagements.models import Engagement, EngagementMember, ActivityLog
from vulns.models import Finding


@override_settings(MFA_REQUIRED_ROLES=[])
class WorkspaceQueueTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('operator', role='pentester')
        self.eng = Engagement.objects.create(name='Assessment')
        self.member = EngagementMember.objects.create(engagement=self.eng, user=self.user, role='pentester')
        self.finding = Finding.objects.create(engagement=self.eng, title='Private review', review_state='in_review', assigned_to=self.user)
        self.client.force_login(self.user)

    def test_review_queue_requires_review_role(self):
        response = self.client.get(reverse('dashboard:home'), {'queue': 'review'})
        self.assertEqual(response.context['page_obj'].paginator.count, 0)
        self.member.role = 'reviewer'
        self.member.save()
        response = self.client.get(reverse('dashboard:home'), {'queue': 'review'})
        self.assertEqual(list(response.context['triage_findings']), [self.finding])

    def test_client_membership_does_not_leak_draft_counts_or_activity(self):
        self.member.role = 'client'
        self.member.save()
        ActivityLog.objects.create(engagement=self.eng, action='Private review', user=self.user)
        response = self.client.get(reverse('dashboard:home'), {'queue': 'attention'})
        self.assertEqual(response.context['open_findings_count'], 0)
        self.assertEqual(response.context['recent_engagements'][0].visible_finding_count, 0)
        self.assertEqual(list(response.context['recent_activity']), [])

    def test_personal_queue_paginates_and_excludes_other_engagements(self):
        for i in range(17):
            Finding.objects.create(engagement=self.eng, title=f'Assigned issue {i}', assigned_to=self.user)
        private = Engagement.objects.create(name='Other team')
        Finding.objects.create(engagement=private, title='Hidden issue', assigned_to=self.user)
        response = self.client.get(reverse('dashboard:home'), {'queue': 'mine', 'page': 2})
        self.assertEqual(response.context['page_obj'].paginator.count, 18)
        self.assertEqual(len(response.context['triage_findings']), 3)
        self.assertNotContains(response, 'Hidden issue')

    def test_finding_search_pagination_encodes_special_characters(self):
        response = self.client.get(reverse('vulns:list', args=[self.eng.pk]), {'q': 'A&B + C', 'assigned': 'invalid'})
        self.assertEqual(response.status_code, 200)
        self.assertIn('q=A%26B+%2B+C', response.context['query_string'])
        self.assertContains(response, 'No findings match these filters.')
