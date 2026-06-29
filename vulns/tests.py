import shutil
import tempfile
from datetime import timedelta
from django.core.files.storage import FileSystemStorage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.utils import timezone
from accounts.models import User, AuditLog
from engagements.models import Engagement, EngagementMember, ActivityLog, Client as EngagementClient
from .models import Finding, Evidence, FindingComment
from .templatetags.vulns_extras import render_markdown


class CVSSCalculationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Test Engagement',
            client=EngagementClient.objects.get_or_create(name='Test Client')[0],
            created_by=self.user,
        )

    def _make_finding(self, **kwargs):
        defaults = {
            'engagement': self.engagement,
            'title': 'Test Finding',
            'attack_vector': 'N',
            'attack_complexity': 'L',
            'privileges_required': 'N',
            'user_interaction': 'N',
            'confidentiality_impact': 'N',
            'integrity_impact': 'N',
            'availability_impact': 'N',
        }
        defaults.update(kwargs)
        return Finding.objects.create(**defaults)

    def test_all_none_impact_scores_zero(self):
        """All None impacts should produce CVSS 0.0 and severity 'info'."""
        f = self._make_finding()
        self.assertEqual(f.cvss_score, 0.0)
        self.assertEqual(f.severity, 'info')

    def test_critical_severity(self):
        """Network/Low/None/None with all High impacts -> Critical."""
        f = self._make_finding(
            confidentiality_impact='H',
            integrity_impact='H',
            availability_impact='H',
        )
        self.assertGreaterEqual(f.cvss_score, 9.0)
        self.assertEqual(f.severity, 'critical')

    def test_high_severity(self):
        """Should produce High severity (7.0-8.9)."""
        f = self._make_finding(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='L',
            user_interaction='N',
            confidentiality_impact='H',
            integrity_impact='H',
            availability_impact='N',
        )
        self.assertGreaterEqual(f.cvss_score, 7.0)
        self.assertLess(f.cvss_score, 9.0)
        self.assertEqual(f.severity, 'high')

    def test_medium_severity(self):
        """Should produce Medium severity (4.0-6.9)."""
        f = self._make_finding(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='L',
            user_interaction='R',
            confidentiality_impact='L',
            integrity_impact='L',
            availability_impact='N',
        )
        self.assertGreaterEqual(f.cvss_score, 4.0)
        self.assertLess(f.cvss_score, 7.0)
        self.assertEqual(f.severity, 'medium')

    def test_low_severity(self):
        """Should produce Low severity (0.1-3.9)."""
        f = self._make_finding(
            attack_vector='P',
            attack_complexity='H',
            privileges_required='H',
            user_interaction='R',
            confidentiality_impact='L',
            integrity_impact='N',
            availability_impact='N',
        )
        self.assertGreaterEqual(f.cvss_score, 0.1)
        self.assertLess(f.cvss_score, 4.0)
        self.assertEqual(f.severity, 'low')

    def test_cvss_score_never_exceeds_10(self):
        """CVSS score should be capped at 10.0."""
        f = self._make_finding(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='N',
            user_interaction='N',
            confidentiality_impact='H',
            integrity_impact='H',
            availability_impact='H',
        )
        self.assertLessEqual(f.cvss_score, 10.0)

    def test_cvss_vector_string(self):
        f = self._make_finding(
            attack_vector='N',
            attack_complexity='L',
            privileges_required='H',
            user_interaction='R',
            confidentiality_impact='H',
            integrity_impact='L',
            availability_impact='N',
        )
        self.assertEqual(
            f.cvss_vector_string,
            'CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:H/I:L/A:N'
        )

    def test_severity_auto_set_on_save(self):
        """Severity should be auto-calculated from CVSS, not manually set."""
        f = self._make_finding(
            severity='info',  # Manually set to info
            confidentiality_impact='H',
            integrity_impact='H',
            availability_impact='H',
        )
        # Should be overridden to critical by save()
        self.assertEqual(f.severity, 'critical')


class CVSSVectorParsingTests(TestCase):
    def test_parse_full_vector(self):
        parsed = Finding.parse_cvss_vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        self.assertEqual(parsed['attack_vector'], 'N')
        self.assertEqual(parsed['attack_complexity'], 'L')
        self.assertEqual(parsed['scope'], 'U')
        self.assertEqual(parsed['confidentiality_impact'], 'H')
        self.assertEqual(parsed['availability_impact'], 'H')

    def test_parse_scope_changed(self):
        parsed = Finding.parse_cvss_vector('CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N')
        self.assertEqual(parsed['scope'], 'C')
        self.assertEqual(parsed['privileges_required'], 'L')
        self.assertEqual(parsed['user_interaction'], 'R')

    def test_parse_cvss_3_0_also_accepted(self):
        parsed = Finding.parse_cvss_vector('CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N')
        self.assertEqual(parsed['attack_vector'], 'L')

    def test_parse_lowercase_values_accepted(self):
        parsed = Finding.parse_cvss_vector('cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h')
        self.assertEqual(parsed['attack_vector'], 'N')

    def test_parse_partial_vector(self):
        parsed = Finding.parse_cvss_vector('CVSS:3.1/AV:N/C:H')
        self.assertEqual(parsed, {'attack_vector': 'N', 'confidentiality_impact': 'H'})

    def test_parse_empty_raises(self):
        with self.assertRaises(ValueError):
            Finding.parse_cvss_vector('')

    def test_parse_wrong_prefix_raises(self):
        with self.assertRaises(ValueError):
            Finding.parse_cvss_vector('CVSS:2.0/AV:N/C:H')

    def test_parse_invalid_metric_value_raises(self):
        with self.assertRaises(ValueError):
            Finding.parse_cvss_vector('CVSS:3.1/AV:X')

    def test_parse_malformed_metric_raises(self):
        with self.assertRaises(ValueError):
            Finding.parse_cvss_vector('CVSS:3.1/AVN')

    def test_unknown_metric_skipped_not_raised(self):
        """Unknown metrics (e.g. temporal/environmental prefixes) should be ignored."""
        parsed = Finding.parse_cvss_vector('CVSS:3.1/AV:N/E:F/RL:O')
        self.assertEqual(parsed, {'attack_vector': 'N'})


@override_settings(MFA_REQUIRED_ROLES=[])
class RetestWorkflowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.pentester = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Test', client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.pentester,
        )
        EngagementMember.objects.create(
            engagement=self.engagement, user=self.pentester, role='lead',
        )
        self.finding = Finding.objects.create(
            engagement=self.engagement, title='Test Finding',
            description='test', found_by=self.pentester,
            confidentiality_impact='H',
        )

    def test_default_retest_status_is_not_retested(self):
        self.assertEqual(self.finding.retest_status, 'not_retested')
        self.assertIsNone(self.finding.retest_date)
        self.assertIsNone(self.finding.retested_by)

    def test_record_retest_sets_retested_by(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.post(reverse('vulns:detail', args=[self.finding.pk]), {
            'record_retest': '1',
            'retest_status': 'fixed',
            'retest_date': '2026-04-01',
            'retest_notes': 'Verified via curl — returns 403.',
        })
        self.assertEqual(resp.status_code, 302)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.retest_status, 'fixed')
        self.assertEqual(self.finding.retested_by, self.pentester)

    def test_retest_fixed_flips_status_to_remediated(self):
        self.client.login(username='pt', password='testpass1')
        self.client.post(reverse('vulns:detail', args=[self.finding.pk]), {
            'record_retest': '1',
            'retest_status': 'fixed',
            'retest_date': '2026-04-01',
            'retest_notes': '',
        })
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, Finding.Status.REMEDIATED)

    def test_retest_still_present_keeps_status(self):
        self.client.login(username='pt', password='testpass1')
        self.client.post(reverse('vulns:detail', args=[self.finding.pk]), {
            'record_retest': '1',
            'retest_status': 'still_present',
            'retest_date': '2026-04-01',
            'retest_notes': 'Still exploitable.',
        })
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.status, Finding.Status.OPEN)
        self.assertEqual(self.finding.retest_status, 'still_present')

    def test_client_cannot_record_retest(self):
        cli = User.objects.create_user('cli', role='client', password='testpass1')
        EngagementMember.objects.create(
            engagement=self.engagement, user=cli, role='client',
        )
        self.client.login(username='cli', password='testpass1')
        self.client.post(reverse('vulns:detail', args=[self.finding.pk]), {
            'record_retest': '1',
            'retest_status': 'fixed',
            'retest_date': '2026-04-01',
            'retest_notes': 'hax',
        })
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.retest_status, 'not_retested')


@override_settings(MFA_REQUIRED_ROLES=[])
class SLATrackingTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='T', client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.user,
        )
        EngagementMember.objects.create(
            engagement=self.engagement, user=self.user, role='lead',
        )

    def _make_finding(self, **kwargs):
        defaults = {
            'engagement': self.engagement,
            'title': 'f',
            'description': 'd',
            'confidentiality_impact': 'H',
            'integrity_impact': 'H',
            'availability_impact': 'H',
        }
        defaults.update(kwargs)
        return Finding.objects.create(**defaults)

    def test_due_date_auto_set_from_severity(self):
        """Critical findings get a 7-day SLA from creation."""
        f = self._make_finding()
        self.assertEqual(f.severity, 'critical')
        expected = f.created_at.date() + timedelta(days=7)
        self.assertEqual(f.due_date, expected)

    def test_due_date_scales_with_severity(self):
        """Lower severity = longer SLA window."""
        low = self._make_finding(
            attack_vector='P', attack_complexity='H',
            privileges_required='H', user_interaction='R',
            confidentiality_impact='L', integrity_impact='N', availability_impact='N',
        )
        self.assertEqual(low.severity, 'low')
        self.assertEqual(low.due_date, low.created_at.date() + timedelta(days=60))

    def test_due_date_recomputed_when_severity_changes(self):
        """Reclassifying a critical as low should extend the SLA window."""
        f = self._make_finding()
        original_due = f.due_date
        f.attack_vector = 'P'
        f.attack_complexity = 'H'
        f.privileges_required = 'H'
        f.user_interaction = 'R'
        f.confidentiality_impact = 'L'
        f.integrity_impact = 'N'
        f.availability_impact = 'N'
        f.save()
        self.assertEqual(f.severity, 'low')
        self.assertEqual(f.due_date, f.created_at.date() + timedelta(days=60))
        self.assertGreater(f.due_date, original_due)

    def test_is_overdue_true_for_past_due_date(self):
        f = self._make_finding()
        f.due_date = timezone.now().date() - timedelta(days=1)
        f.save()
        self.assertTrue(f.is_overdue)
        self.assertEqual(f.sla_status, 'overdue')

    def test_is_overdue_false_when_remediated(self):
        """Closed findings are never overdue, even if past due date."""
        f = self._make_finding()
        f.due_date = timezone.now().date() - timedelta(days=10)
        f.status = Finding.Status.REMEDIATED
        f.save()
        self.assertFalse(f.is_overdue)
        self.assertEqual(f.sla_status, 'closed')

    def test_is_overdue_false_for_accepted_risk(self):
        f = self._make_finding()
        f.due_date = timezone.now().date() - timedelta(days=5)
        f.status = Finding.Status.ACCEPTED
        f.save()
        self.assertFalse(f.is_overdue)

    def test_sla_status_due_soon_within_3_days(self):
        f = self._make_finding()
        f.due_date = timezone.now().date() + timedelta(days=2)
        f.save()
        self.assertEqual(f.sla_status, 'due_soon')

    def test_sla_status_on_track_beyond_3_days(self):
        f = self._make_finding()
        f.due_date = timezone.now().date() + timedelta(days=10)
        f.save()
        self.assertEqual(f.sla_status, 'on_track')

    def test_overdue_days_positive_for_overdue(self):
        f = self._make_finding()
        f.due_date = timezone.now().date() - timedelta(days=5)
        f.save()
        self.assertEqual(f.overdue_days, 5)

    def test_overdue_days_zero_when_not_overdue(self):
        f = self._make_finding()
        f.due_date = timezone.now().date() + timedelta(days=5)
        f.save()
        self.assertEqual(f.overdue_days, 0)

    def test_finding_list_overdue_filter(self):
        """?sla=overdue should only show open findings past due date."""
        overdue = self._make_finding(title='Overdue one')
        overdue.due_date = timezone.now().date() - timedelta(days=1)
        overdue.save()
        on_track = self._make_finding(title='On track one')
        on_track.due_date = timezone.now().date() + timedelta(days=20)
        on_track.save()
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(
            reverse('vulns:list', args=[self.engagement.pk]) + '?sla=overdue'
        )
        self.assertContains(resp, 'Overdue one')
        self.assertNotContains(resp, 'On track one')

    def test_overdue_filter_excludes_closed(self):
        """Remediated findings should not appear in overdue filter."""
        f = self._make_finding(title='Was overdue')
        f.due_date = timezone.now().date() - timedelta(days=10)
        f.status = Finding.Status.REMEDIATED
        f.save()
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(
            reverse('vulns:list', args=[self.engagement.pk]) + '?sla=overdue'
        )
        self.assertNotContains(resp, 'Was overdue')


@override_settings(MFA_REQUIRED_ROLES=[])
class FindingAssignmentTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='testpass1')
        self.alice = User.objects.create_user('alice', role='pentester', password='testpass1')
        self.bob = User.objects.create_user('bob', role='pentester', password='testpass1')
        self.cli = User.objects.create_user('cli', role='client', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='T', client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.lead,
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.alice, role='pentester')
        EngagementMember.objects.create(engagement=self.engagement, user=self.bob, role='pentester')
        EngagementMember.objects.create(engagement=self.engagement, user=self.cli, role='client')
        self.finding = Finding.objects.create(
            engagement=self.engagement, title='SQLi in login',
            description='x', found_by=self.lead, confidentiality_impact='H',
        )

    def test_default_assignee_is_none(self):
        self.assertIsNone(self.finding.assigned_to)

    def test_assigned_findings_reverse_relation(self):
        self.finding.assigned_to = self.alice
        self.finding.save()
        self.assertIn(self.finding, self.alice.assigned_findings.all())

    def test_assign_logs_activity_on_create(self):
        self.client.login(username='lead', password='testpass1')
        resp = self.client.post(
            reverse('vulns:create', args=[self.engagement.pk]),
            self._form_data(title='New one', assigned_to=self.alice.pk),
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(
            ActivityLog.objects.filter(
                engagement=self.engagement,
                action__icontains=f'Assigned finding "New one" to {self.alice}',
            ).exists()
        )

    def test_reassignment_logs_activity_on_edit(self):
        self.finding.assigned_to = self.alice
        self.finding.save()
        self.client.login(username='lead', password='testpass1')
        resp = self.client.post(
            reverse('vulns:edit', args=[self.finding.pk]),
            self._form_data(title=self.finding.title, assigned_to=self.bob.pk),
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(
            ActivityLog.objects.filter(
                engagement=self.engagement, action__icontains='Reassigned finding',
            ).exists()
        )

    def test_no_log_when_assignee_unchanged(self):
        self.finding.assigned_to = self.alice
        self.finding.save()
        self.client.login(username='lead', password='testpass1')
        self.client.post(
            reverse('vulns:edit', args=[self.finding.pk]),
            self._form_data(title=self.finding.title, assigned_to=self.alice.pk),
        )
        self.assertFalse(
            ActivityLog.objects.filter(action__icontains='Reassigned').exists()
        )

    def test_assigned_to_me_filter(self):
        other = Finding.objects.create(
            engagement=self.engagement, title='Other',
            description='x', found_by=self.lead,
            assigned_to=self.bob, confidentiality_impact='H',
        )
        self.finding.assigned_to = self.alice
        self.finding.save()
        self.client.login(username='alice', password='testpass1')
        resp = self.client.get(
            reverse('vulns:list', args=[self.engagement.pk]) + '?assigned=me'
        )
        self.assertContains(resp, 'SQLi in login')
        self.assertNotContains(resp, 'Other')

    def test_unassigned_filter(self):
        """?assigned=unassigned shows only findings with no owner."""
        self.finding.assigned_to = self.alice
        self.finding.save()
        Finding.objects.create(
            engagement=self.engagement, title='Orphan',
            description='x', found_by=self.lead, confidentiality_impact='H',
        )
        self.client.login(username='lead', password='testpass1')
        resp = self.client.get(
            reverse('vulns:list', args=[self.engagement.pk]) + '?assigned=unassigned'
        )
        self.assertContains(resp, 'Orphan')
        self.assertNotContains(resp, 'SQLi in login')

    def test_client_not_in_assignable_list(self):
        """Form should not offer clients as assignable members."""
        self.client.login(username='lead', password='testpass1')
        resp = self.client.get(reverse('vulns:create', args=[self.engagement.pk]))
        # The form's assigned_to dropdown queryset excludes clients
        form = resp.context['form']
        assignable = list(form.fields['assigned_to'].queryset)
        self.assertIn(self.alice, assignable)
        self.assertIn(self.bob, assignable)
        self.assertNotIn(self.cli, assignable)

    def _form_data(self, **overrides):
        """Minimum valid form payload for a Finding."""
        data = {
            'title': 'Finding title',
            'description': 'desc',
            'status': 'open',
            'attack_vector': 'N',
            'attack_complexity': 'L',
            'privileges_required': 'N',
            'user_interaction': 'N',
            'scope': 'U',
            'confidentiality_impact': 'H',
            'integrity_impact': 'H',
            'availability_impact': 'H',
        }
        data.update({k: v for k, v in overrides.items() if v is not None})
        return data


@override_settings(MFA_REQUIRED_ROLES=[])
class ReviewWorkflowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='testpass1')
        self.pt = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.rev = User.objects.create_user('rev', role='reviewer', password='testpass1')
        self.cli = User.objects.create_user('cli', role='client', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='T', client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.lead,
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.pt, role='pentester')
        EngagementMember.objects.create(engagement=self.engagement, user=self.rev, role='reviewer')
        EngagementMember.objects.create(engagement=self.engagement, user=self.cli, role='client')
        self.finding = Finding.objects.create(
            engagement=self.engagement, title='SQLi', description='x',
            found_by=self.pt, confidentiality_impact='H',
        )

    def test_default_state_is_draft(self):
        self.assertEqual(self.finding.review_state, Finding.ReviewState.DRAFT)

    def test_pentester_can_submit_for_review(self):
        self.client.login(username='pt', password='testpass1')
        resp = self.client.post(reverse('vulns:submit_review', args=[self.finding.pk]))
        self.assertEqual(resp.status_code, 302)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.IN_REVIEW)
        self.assertTrue(
            ActivityLog.objects.filter(
                engagement=self.engagement,
                action__icontains='Submitted finding for review',
            ).exists()
        )

    def test_reviewer_cannot_submit_for_review(self):
        """Reviewers review — they don't author. Only edit-privileged users submit."""
        self.client.login(username='rev', password='testpass1')
        resp = self.client.post(reverse('vulns:submit_review', args=[self.finding.pk]))
        self.assertEqual(resp.status_code, 302)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.DRAFT)

    def test_submit_requires_post(self):
        self.client.login(username='pt', password='testpass1')
        self.client.get(reverse('vulns:submit_review', args=[self.finding.pk]))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.DRAFT)

    def test_submit_rejected_from_approved(self):
        self.finding.review_state = Finding.ReviewState.APPROVED
        self.finding.save()
        self.client.login(username='pt', password='testpass1')
        self.client.post(reverse('vulns:submit_review', args=[self.finding.pk]))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.APPROVED)

    def test_reviewer_can_approve(self):
        self.finding.review_state = Finding.ReviewState.IN_REVIEW
        self.finding.save()
        self.client.login(username='rev', password='testpass1')
        self.client.post(reverse('vulns:approve', args=[self.finding.pk]))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.APPROVED)
        self.assertEqual(self.finding.reviewed_by, self.rev)
        self.assertIsNotNone(self.finding.reviewed_at)
        self.assertTrue(
            ActivityLog.objects.filter(
                engagement=self.engagement,
                action__icontains='Approved finding',
            ).exists()
        )

    def test_lead_can_approve(self):
        self.finding.review_state = Finding.ReviewState.IN_REVIEW
        self.finding.save()
        self.client.login(username='lead', password='testpass1')
        self.client.post(reverse('vulns:approve', args=[self.finding.pk]))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.APPROVED)

    def test_pentester_cannot_approve(self):
        self.finding.review_state = Finding.ReviewState.IN_REVIEW
        self.finding.save()
        self.client.login(username='pt', password='testpass1')
        self.client.post(reverse('vulns:approve', args=[self.finding.pk]))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.IN_REVIEW)

    def test_approve_rejected_from_draft(self):
        """Can only approve findings that are currently in review."""
        self.client.login(username='rev', password='testpass1')
        self.client.post(reverse('vulns:approve', args=[self.finding.pk]))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.DRAFT)

    def test_request_changes_stores_notes(self):
        self.finding.review_state = Finding.ReviewState.IN_REVIEW
        self.finding.save()
        self.client.login(username='rev', password='testpass1')
        self.client.post(
            reverse('vulns:request_changes', args=[self.finding.pk]),
            {'review_notes': 'PoC missing — add screenshots.'},
        )
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.CHANGES_REQUESTED)
        self.assertEqual(self.finding.review_notes, 'PoC missing — add screenshots.')
        self.assertEqual(self.finding.reviewed_by, self.rev)

    def test_request_changes_requires_notes(self):
        self.finding.review_state = Finding.ReviewState.IN_REVIEW
        self.finding.save()
        self.client.login(username='rev', password='testpass1')
        self.client.post(
            reverse('vulns:request_changes', args=[self.finding.pk]),
            {'review_notes': '   '},
        )
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.IN_REVIEW)

    def test_resubmit_clears_review_notes(self):
        """After re-submitting CHANGES_REQUESTED → IN_REVIEW, old notes clear."""
        self.finding.review_state = Finding.ReviewState.CHANGES_REQUESTED
        self.finding.review_notes = 'old feedback'
        self.finding.save()
        self.client.login(username='pt', password='testpass1')
        self.client.post(reverse('vulns:submit_review', args=[self.finding.pk]))
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.review_state, Finding.ReviewState.IN_REVIEW)
        self.assertEqual(self.finding.review_notes, '')

    def test_client_only_sees_approved_in_list(self):
        draft = self.finding  # draft
        approved = Finding.objects.create(
            engagement=self.engagement, title='Approved-One', description='x',
            found_by=self.pt, confidentiality_impact='H',
            review_state=Finding.ReviewState.APPROVED,
        )
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('vulns:list', args=[self.engagement.pk]))
        self.assertContains(resp, 'Approved-One')
        self.assertNotContains(resp, draft.title)

    def test_pentester_sees_all_states_in_list(self):
        Finding.objects.create(
            engagement=self.engagement, title='Approved-One', description='x',
            found_by=self.pt, confidentiality_impact='H',
            review_state=Finding.ReviewState.APPROVED,
        )
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(reverse('vulns:list', args=[self.engagement.pk]))
        self.assertContains(resp, 'Approved-One')
        self.assertContains(resp, self.finding.title)

    def test_client_blocked_from_unapproved_detail(self):
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('vulns:detail', args=[self.finding.pk]))
        self.assertEqual(resp.status_code, 302)

    def test_client_can_view_approved_detail(self):
        self.finding.review_state = Finding.ReviewState.APPROVED
        self.finding.save()
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('vulns:detail', args=[self.finding.pk]))
        self.assertEqual(resp.status_code, 200)

    def test_review_filter_for_pentester(self):
        approved = Finding.objects.create(
            engagement=self.engagement, title='Approved-One', description='x',
            found_by=self.pt, confidentiality_impact='H',
            review_state=Finding.ReviewState.APPROVED,
        )
        self.client.login(username='pt', password='testpass1')
        resp = self.client.get(
            reverse('vulns:list', args=[self.engagement.pk]) + '?review=approved'
        )
        self.assertContains(resp, 'Approved-One')
        self.assertNotContains(resp, self.finding.title)

    def test_client_export_only_includes_approved(self):
        Finding.objects.create(
            engagement=self.engagement, title='Approved-Export', description='x',
            found_by=self.pt, confidentiality_impact='H',
            review_state=Finding.ReviewState.APPROVED,
        )
        self.client.login(username='cli', password='testpass1')
        resp = self.client.get(reverse('vulns:export_csv', args=[self.engagement.pk]))
        body = resp.content.decode()
        self.assertIn('Approved-Export', body)
        self.assertNotIn(self.finding.title, body)


@override_settings(MFA_REQUIRED_ROLES=[])
class EvidenceDownloadTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmpdir = tempfile.mkdtemp()
        cls._field = Evidence._meta.get_field('file')
        cls._orig_storage = cls._field.storage
        cls._field.storage = FileSystemStorage(location=cls._tmpdir)

    @classmethod
    def tearDownClass(cls):
        cls._field.storage = cls._orig_storage
        shutil.rmtree(cls._tmpdir, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='testpass1')
        self.outsider = User.objects.create_user('out', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='X', client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=self.engagement, user=self.lead, role='lead',
        )
        self.finding = Finding.objects.create(
            engagement=self.engagement, title='SQLi',
            found_by=self.lead, confidentiality_impact='H',
        )
        self.evidence = Evidence.objects.create(
            finding=self.finding,
            file=SimpleUploadedFile('proof.png', b'fake-bytes', content_type='image/png'),
            uploaded_by=self.lead,
        )

    def test_unauthenticated_redirects_to_login(self):
        resp = self.client.get(
            reverse('vulns:evidence_download', args=[self.evidence.pk])
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn('login', resp.url)

    def test_non_member_gets_403(self):
        self.client.login(username='out', password='testpass1')
        resp = self.client.get(
            reverse('vulns:evidence_download', args=[self.evidence.pk])
        )
        self.assertEqual(resp.status_code, 403)

    def test_member_gets_200(self):
        self.client.login(username='lead', password='testpass1')
        resp = self.client.get(
            reverse('vulns:evidence_download', args=[self.evidence.pk])
        )
        self.assertEqual(resp.status_code, 200)
        body = b''.join(resp.streaming_content)
        self.assertEqual(body, b'fake-bytes')


@override_settings(MFA_REQUIRED_ROLES=[])
class EvidenceDeleteTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tmpdir = tempfile.mkdtemp()
        cls._field = Evidence._meta.get_field('file')
        cls._orig_storage = cls._field.storage
        cls._field.storage = FileSystemStorage(location=cls._tmpdir)

    @classmethod
    def tearDownClass(cls):
        cls._field.storage = cls._orig_storage
        shutil.rmtree(cls._tmpdir, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='testpass1')
        self.reviewer = User.objects.create_user('rev', role='reviewer', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='X', client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.lead,
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.reviewer, role='reviewer')
        self.finding = Finding.objects.create(
            engagement=self.engagement, title='SQLi', found_by=self.lead, confidentiality_impact='H',
        )

    def _make_evidence(self):
        return Evidence.objects.create(
            finding=self.finding,
            file=SimpleUploadedFile('proof.png', b'fake-bytes', content_type='image/png'),
            uploaded_by=self.lead,
        )

    def test_editor_can_delete_evidence(self):
        ev = self._make_evidence()
        self.client.login(username='lead', password='testpass1')
        resp = self.client.post(
            reverse('vulns:detail', args=[self.finding.pk]),
            {'delete_evidence': '1', 'evidence_id': ev.pk},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(Evidence.objects.filter(pk=ev.pk).exists())

    def test_reviewer_cannot_delete_evidence(self):
        # Reviewers can sign off evidence but not delete it (not an editor).
        ev = self._make_evidence()
        self.client.login(username='rev', password='testpass1')
        self.client.post(
            reverse('vulns:detail', args=[self.finding.pk]),
            {'delete_evidence': '1', 'evidence_id': ev.pk},
        )
        self.assertTrue(Evidence.objects.filter(pk=ev.pk).exists())


# ── Scanner parsers (step 2.2) ────────────────────────────────────────────

from .parsers import (  # noqa: E402
    parse_burp_xml,
    parse_nessus_xml,
    parse_semgrep_json,
    parse_zap_json,
)


BURP_SAMPLE = b"""<?xml version="1.0"?>
<issues>
  <issue>
    <serialNumber>1</serialNumber>
    <type>1048832</type>
    <name>Cross-site scripting (reflected)</name>
    <host ip="192.0.2.10">http://example.com</host>
    <path><![CDATA[/search]]></path>
    <location><![CDATA[/search [q parameter]]]></location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[XSS background]]></issueBackground>
    <issueDetail><![CDATA[The q parameter reflects user input.]]></issueDetail>
    <remediationDetail><![CDATA[HTML-encode output.]]></remediationDetail>
    <vulnerabilityClassifications><![CDATA[CWE-79: XSS]]></vulnerabilityClassifications>
  </issue>
  <issue>
    <serialNumber>2</serialNumber>
    <name>HTTP TRACE method is enabled</name>
    <host ip="192.0.2.10">http://example.com</host>
    <path><![CDATA[/]]></path>
    <severity>Information</severity>
    <issueDetail><![CDATA[TRACE is on.]]></issueDetail>
  </issue>
</issues>
"""


NESSUS_SAMPLE = b"""<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="Scan">
    <ReportHost name="host.example.com">
      <HostProperties>
        <tag name="host-ip">192.0.2.20</tag>
        <tag name="host-fqdn">host.example.com</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="https" protocol="tcp" severity="3" pluginID="12345" pluginName="TLS Version 1.0 Protocol Detection">
        <risk_factor>High</risk_factor>
        <synopsis>Legacy TLS.</synopsis>
        <description>The service supports TLS 1.0.</description>
        <solution>Disable TLSv1.0.</solution>
        <cvss3_base_score>7.4</cvss3_base_score>
        <cve>CVE-2011-3389</cve>
        <cwe>327</cwe>
      </ReportItem>
      <ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information">
        <risk_factor>None</risk_factor>
        <description>Scan metadata.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


ZAP_SAMPLE = b"""{
  "site": [{
    "@name": "http://example.com",
    "@host": "example.com",
    "@port": "80",
    "alerts": [
      {
        "pluginid": "40012",
        "alert": "Cross Site Scripting (Reflected)",
        "riskdesc": "High (Medium)",
        "riskcode": "3",
        "desc": "Reflected XSS in q parameter.",
        "solution": "Encode output.",
        "reference": "https://owasp.org/xss",
        "cweid": "79",
        "instances": [
          {"uri": "http://example.com/search?q=1", "method": "GET", "param": "q"}
        ]
      },
      {
        "pluginid": "10020",
        "alert": "X-Frame-Options Header Missing",
        "riskdesc": "Medium (Medium)",
        "riskcode": "2",
        "desc": "Missing XFO header.",
        "instances": [{"uri": "http://example.com/", "method": "GET"}]
      }
    ]
  }]
}
"""


SEMGREP_SAMPLE = b"""{
  "results": [
    {
      "check_id": "python.django.security.injection.sql.sql-injection",
      "path": "app/views.py",
      "start": {"line": 42, "col": 8},
      "end": {"line": 42, "col": 80},
      "extra": {
        "message": "Potential SQL injection via string concatenation.",
        "severity": "ERROR",
        "metadata": {"cwe": ["CWE-89: SQL Injection"], "owasp": ["A03:2021"]},
        "lines": "query = 'SELECT * FROM users WHERE id=' + user_id"
      }
    },
    {
      "check_id": "generic.secrets.security.detected-aws-key",
      "path": "config/prod.py",
      "start": {"line": 3, "col": 1},
      "end": {"line": 3, "col": 40},
      "extra": {
        "message": "AWS key detected",
        "severity": "WARNING",
        "metadata": {}
      }
    }
  ]
}
"""


class BurpParserTests(TestCase):
    def test_parses_issues_and_maps_severity(self):
        results = parse_burp_xml(BURP_SAMPLE)
        self.assertEqual(len(results), 2)
        xss, trace = results
        self.assertEqual(xss['title'], 'Cross-site scripting (reflected)')
        self.assertEqual(xss['severity'], 'high')
        self.assertEqual(xss['parameter'], 'q')
        self.assertEqual(xss['endpoint'], '/search')
        self.assertEqual(xss['port'], 80)
        self.assertEqual(xss['cwe_id'], 'CWE-79')
        self.assertEqual(trace['severity'], 'info')


class NessusParserTests(TestCase):
    def test_parses_report_items(self):
        results = parse_nessus_xml(NESSUS_SAMPLE)
        self.assertEqual(len(results), 2)
        tls, meta = results
        self.assertEqual(tls['severity'], 'high')
        self.assertEqual(tls['port'], 443)
        self.assertEqual(tls['host'], 'host.example.com')
        self.assertAlmostEqual(tls['cvss_score'], 7.4)
        self.assertEqual(tls['cwe_id'], 'CWE-327')
        self.assertIn('CVE-2011-3389', tls['references'])
        self.assertEqual(meta['severity'], 'info')
        self.assertNotIn('port', meta)  # port 0 is dropped


class ZapParserTests(TestCase):
    def test_parses_alerts_and_instances(self):
        results = parse_zap_json(ZAP_SAMPLE)
        self.assertEqual(len(results), 2)
        xss, xfo = results
        self.assertEqual(xss['severity'], 'high')
        self.assertEqual(xss['parameter'], 'q')
        self.assertEqual(xss['endpoint'], '/search')
        self.assertEqual(xss['http_method'], 'GET')
        self.assertEqual(xss['cwe_id'], 'CWE-79')
        self.assertEqual(xfo['severity'], 'medium')


class SemgrepParserTests(TestCase):
    def test_parses_results_and_maps_severity(self):
        results = parse_semgrep_json(SEMGREP_SAMPLE)
        self.assertEqual(len(results), 2)
        sqli, aws = results
        self.assertEqual(sqli['severity'], 'high')
        self.assertEqual(sqli['cwe_id'], 'CWE-89')
        self.assertIn('app/views.py:42', sqli['endpoint'])
        self.assertEqual(aws['severity'], 'medium')


@override_settings(MFA_REQUIRED_ROLES=[])
class ToolImportDedupTests(TestCase):
    """Dedup uses (title, host, port, endpoint, parameter) — a second import
    of the same Burp report must not create duplicate findings."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user('pt', role='pentester', password='pw')
        self.engagement = Engagement.objects.create(
            name='E', client=EngagementClient.objects.get_or_create(name='C')[0], created_by=self.user,
        )
        EngagementMember.objects.create(
            engagement=self.engagement, user=self.user, role='lead',
        )
        self.client.force_login(self.user)

    def _import(self, payload, filename, tool):
        return self.client.post(
            reverse('vulns:import', args=[self.engagement.pk]),
            {
                'tool': tool,
                'file': SimpleUploadedFile(filename, payload, content_type='application/octet-stream'),
            },
            follow=True,
        )

    def test_burp_import_then_reimport_skips_duplicates(self):
        self._import(BURP_SAMPLE, 'burp.xml', 'burp')
        self.assertEqual(Finding.objects.filter(engagement=self.engagement).count(), 2)
        self._import(BURP_SAMPLE, 'burp.xml', 'burp')
        self.assertEqual(Finding.objects.filter(engagement=self.engagement).count(), 2)

    def test_zap_import_creates_one_finding_per_instance(self):
        self._import(ZAP_SAMPLE, 'zap.json', 'zap')
        self.assertEqual(Finding.objects.filter(engagement=self.engagement).count(), 2)


class MarkdownRenderingTests(TestCase):
    """Sanitization of Markdown → HTML for comments and finding bodies."""

    def test_basic_markdown_renders(self):
        html = render_markdown('**bold** and `code`')
        self.assertIn('<strong>bold</strong>', html)
        self.assertIn('<code>code</code>', html)

    def test_script_stripped(self):
        html = render_markdown('<script>alert(1)</script>hi')
        self.assertNotIn('<script', html)
        self.assertIn('hi', html)

    def test_iframe_stripped(self):
        html = render_markdown('<iframe src="evil"></iframe>after')
        self.assertNotIn('<iframe', html)

    def test_fenced_code_block_renders(self):
        html = render_markdown('```\nprint("x")\n```')
        self.assertIn('<pre>', html)
        self.assertIn('<code', html)

    def test_javascript_link_stripped(self):
        html = render_markdown('[click](javascript:alert(1))')
        self.assertNotIn('javascript:', html)

    def test_table_renders(self):
        raw = '| h1 | h2 |\n| --- | --- |\n| a | b |'
        html = render_markdown(raw)
        self.assertIn('<table>', html)
        self.assertIn('<th>h1</th>', html)
        self.assertIn('<td>a</td>', html)

    def test_heading_renders(self):
        html = render_markdown('# Big')
        self.assertIn('<h1', html)
        self.assertIn('Big', html)

    def test_nl2br_makes_single_newline_a_break(self):
        html = render_markdown('line1\nline2')
        self.assertIn('<br', html)


class MarkdownToPlatypusTests(TestCase):
    """The PDF helper that lowers Markdown into ReportLab flowables."""

    def setUp(self):
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle('BodyText2', parent=self.styles['Normal']))

    def test_empty_input_returns_empty_list(self):
        from reports.markdown import markdown_to_platypus
        self.assertEqual(markdown_to_platypus('', self.styles), [])

    def test_plain_paragraph_emits_one_flowable(self):
        from reports.markdown import markdown_to_platypus
        flows = markdown_to_platypus('Just a sentence.', self.styles)
        self.assertEqual(len(flows), 1)

    def test_code_fence_emits_courier_paragraph(self):
        from reports.markdown import markdown_to_platypus
        flows = markdown_to_platypus('```\nprint(1)\n```', self.styles)
        self.assertTrue(any('Courier' in getattr(f, 'text', '') for f in flows))

    def test_table_emits_table_flowable(self):
        from reportlab.platypus import Table
        from reports.markdown import markdown_to_platypus
        flows = markdown_to_platypus(
            '| a | b |\n| --- | --- |\n| 1 | 2 |', self.styles,
        )
        self.assertTrue(any(isinstance(f, Table) for f in flows))

    def test_list_emits_multiple_paragraphs(self):
        from reports.markdown import markdown_to_platypus
        flows = markdown_to_platypus('- one\n- two\n- three', self.styles)
        # at least three flowables for the three list items
        self.assertGreaterEqual(len(flows), 3)

    def test_link_with_ampersand_in_href_does_not_crash(self):
        # Regression: a URL containing '&' (or '<'/'>') must be XML-escaped so
        # ReportLab's paragraph parser doesn't raise and abort PDF generation.
        from reports.markdown import markdown_to_platypus
        flows = markdown_to_platypus(
            '[search](https://example.com/?a=1&b=2)', self.styles,
        )
        self.assertTrue(flows)


@override_settings(MFA_REQUIRED_ROLES=[])
class MarkdownPreviewEndpointTests(TestCase):
    """The /api/markdown-preview/ endpoint used by the finding form."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user('u', role='pentester', password='pw')

    def test_anonymous_redirects_to_login(self):
        resp = self.client.post(reverse('vulns:markdown_preview'), {'text': '**hi**'})
        self.assertEqual(resp.status_code, 302)

    def test_get_not_allowed(self):
        self.client.login(username='u', password='pw')
        resp = self.client.get(reverse('vulns:markdown_preview'))
        self.assertEqual(resp.status_code, 405)

    def test_post_renders_sanitized_html(self):
        self.client.login(username='u', password='pw')
        resp = self.client.post(
            reverse('vulns:markdown_preview'),
            {'text': '**bold** <script>alert(1)</script>'},
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode('utf-8')
        self.assertIn('<strong>bold</strong>', body)
        self.assertNotIn('<script', body)


@override_settings(MFA_REQUIRED_ROLES=[])
class FindingCommentTests(TestCase):
    """Comment thread: posting, edit window, internal-only, review feedback."""

    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='pw')
        self.client_user = User.objects.create_user('cli', role='client', password='pw')
        self.reviewer = User.objects.create_user('rv', role='pentester', password='pw')
        self.engagement = Engagement.objects.create(
            name='E1',
            client=EngagementClient.objects.get_or_create(name='ACME')[0],
            created_by=self.lead,
            engagement_type='external',
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.client_user, role='client')
        EngagementMember.objects.create(engagement=self.engagement, user=self.reviewer, role='reviewer')
        self.finding = Finding.objects.create(
            engagement=self.engagement, title='SQLi',
            description='x', severity=Finding.Severity.HIGH,
            review_state=Finding.ReviewState.APPROVED,
        )

    def _post_comment(self, user, password, **extra):
        self.client.login(username=user.username, password=password)
        data = {'post_comment': '1', 'body': 'hello **world**'}
        data.update(extra)
        return self.client.post(reverse('vulns:detail', args=[self.finding.pk]), data)

    def test_lead_can_post_comment_and_audit_logged(self):
        resp = self._post_comment(self.lead, 'pw')
        self.assertEqual(resp.status_code, 302)
        c = FindingComment.objects.get()
        self.assertEqual(c.author, self.lead)
        self.assertFalse(c.internal_only)
        self.assertTrue(AuditLog.objects.filter(
            action=AuditLog.Action.COMMENT_POST, target=str(c.pk),
        ).exists())

    def test_client_cannot_set_internal_only(self):
        self._post_comment(self.client_user, 'pw', internal_only='on')
        c = FindingComment.objects.get()
        self.assertFalse(c.internal_only)

    def test_client_cannot_see_internal_comment(self):
        FindingComment.objects.create(
            finding=self.finding, author=self.lead,
            body='internal note', internal_only=True,
        )
        self.client.login(username='cli', password='pw')
        resp = self.client.get(reverse('vulns:detail', args=[self.finding.pk]))
        self.assertNotContains(resp, 'internal note')

    def test_lead_can_set_internal_only(self):
        self._post_comment(self.lead, 'pw', internal_only='on')
        c = FindingComment.objects.get()
        self.assertTrue(c.internal_only)

    def test_only_reviewer_can_mark_review_feedback(self):
        # Client attempts → stripped
        self._post_comment(self.client_user, 'pw', is_review_feedback='on')
        c = FindingComment.objects.get()
        self.assertFalse(c.is_review_feedback)
        # Reviewer can set it
        c.delete()
        self._post_comment(self.reviewer, 'pw', is_review_feedback='on')
        c = FindingComment.objects.get()
        self.assertTrue(c.is_review_feedback)

    def test_edit_within_window(self):
        c = FindingComment.objects.create(
            finding=self.finding, author=self.lead, body='orig',
        )
        self.client.login(username='lead', password='pw')
        resp = self.client.post(
            reverse('vulns:comment_edit', args=[c.pk]),
            {'body': 'edited'},
        )
        self.assertEqual(resp.status_code, 302)
        c.refresh_from_db()
        self.assertEqual(c.body, 'edited')
        self.assertIsNotNone(c.edited_at)

    def test_edit_after_window_refused(self):
        c = FindingComment.objects.create(
            finding=self.finding, author=self.lead, body='orig',
        )
        # Age the comment past the 15-minute window.
        FindingComment.objects.filter(pk=c.pk).update(
            created_at=timezone.now() - timedelta(minutes=16),
        )
        c.refresh_from_db()
        self.client.login(username='lead', password='pw')
        resp = self.client.post(
            reverse('vulns:comment_edit', args=[c.pk]),
            {'body': 'edited'},
        )
        self.assertEqual(resp.status_code, 302)
        c.refresh_from_db()
        self.assertEqual(c.body, 'orig')

    def test_other_user_cannot_edit(self):
        c = FindingComment.objects.create(
            finding=self.finding, author=self.lead, body='orig',
        )
        self.client.login(username='rv', password='pw')
        resp = self.client.post(
            reverse('vulns:comment_edit', args=[c.pk]),
            {'body': 'edited'},
        )
        c.refresh_from_db()
        self.assertEqual(c.body, 'orig')

    def test_admin_can_delete_any_comment(self):
        c = FindingComment.objects.create(
            finding=self.finding, author=self.lead, body='orig',
        )
        admin = User.objects.create_user('admin1', role='admin', password='pw')
        self.client.login(username='admin1', password='pw')
        resp = self.client.post(reverse('vulns:comment_delete', args=[c.pk]))
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(FindingComment.objects.filter(pk=c.pk).exists())

    def test_outsider_cannot_comment(self):
        outsider = User.objects.create_user('out', role='pentester', password='pw')
        self.client.login(username='out', password='pw')
        resp = self.client.post(
            reverse('vulns:detail', args=[self.finding.pk]),
            {'post_comment': '1', 'body': 'x'},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(FindingComment.objects.exists())


@override_settings(MFA_REQUIRED_ROLES=[])
class FindingMergeTests(TestCase):
    """Merge two findings: evidence + comments move, body fields append, source deletes."""

    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='pw')
        self.pentester = User.objects.create_user('pt', role='pentester', password='pw')
        self.client_user = User.objects.create_user('cli', role='client', password='pw')
        self.engagement = Engagement.objects.create(
            name='E1',
            client=EngagementClient.objects.get_or_create(name='ACME')[0],
            created_by=self.lead, engagement_type='external',
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.pentester, role='pentester')
        EngagementMember.objects.create(engagement=self.engagement, user=self.client_user, role='client')
        self.source = Finding.objects.create(
            engagement=self.engagement, title='SQLi (dup)',
            description='source desc', proof_of_concept='source poc',
            remediation='source rem', severity=Finding.Severity.HIGH,
        )
        self.target = Finding.objects.create(
            engagement=self.engagement, title='SQLi',
            description='target desc', severity=Finding.Severity.HIGH,
        )

    def test_pentester_cannot_merge(self):
        self.client.login(username='pt', password='pw')
        resp = self.client.post(
            reverse('vulns:merge', args=[self.source.pk]),
            {'target': str(self.target.pk)},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(Finding.objects.filter(pk=self.source.pk).exists())

    def test_lead_can_merge_and_audit_logged(self):
        FindingComment.objects.create(
            finding=self.source, author=self.lead, body='note',
        )
        self.client.login(username='lead', password='pw')
        resp = self.client.post(
            reverse('vulns:merge', args=[self.source.pk]),
            {'target': str(self.target.pk)},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertFalse(Finding.objects.filter(pk=self.source.pk).exists())
        self.target.refresh_from_db()
        self.assertIn('source desc', self.target.description)
        self.assertIn('source poc', self.target.description)
        self.assertIn('source rem', self.target.description)
        self.assertEqual(self.target.comments.count(), 1)
        self.assertTrue(AuditLog.objects.filter(
            action=AuditLog.Action.FINDING_MERGE, target=str(self.target.pk),
        ).exists())

    def test_evidence_moves_to_target(self):
        ev = Evidence.objects.create(
            finding=self.source, uploaded_by=self.lead,
            file=SimpleUploadedFile('e.txt', b'x', content_type='text/plain'),
        )
        self.client.login(username='lead', password='pw')
        self.client.post(
            reverse('vulns:merge', args=[self.source.pk]),
            {'target': str(self.target.pk)},
        )
        ev.refresh_from_db()
        self.assertEqual(ev.finding_id, self.target.pk)

    def test_cross_engagement_target_rejected(self):
        other_eng = Engagement.objects.create(
            name='E2',
            client=EngagementClient.objects.get_or_create(name='Other')[0],
            created_by=self.lead, engagement_type='external',
        )
        EngagementMember.objects.create(engagement=other_eng, user=self.lead, role='lead')
        other_finding = Finding.objects.create(
            engagement=other_eng, title='X', description='x',
            severity=Finding.Severity.LOW,
        )
        self.client.login(username='lead', password='pw')
        resp = self.client.post(
            reverse('vulns:merge', args=[self.source.pk]),
            {'target': str(other_finding.pk)},
        )
        # Form's queryset filters out cross-engagement targets, so the form
        # is invalid → page re-renders without performing the merge.
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(Finding.objects.filter(pk=self.source.pk).exists())

    def test_get_with_target_param_renders_preview(self):
        self.client.login(username='lead', password='pw')
        resp = self.client.get(
            reverse('vulns:merge', args=[self.source.pk]) + f'?target={self.target.pk}',
        )
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.target.title)
        self.assertContains(resp, 'Confirm merge')


@override_settings(MFA_REQUIRED_ROLES=[])
class ToolImportPreviewTests(TestCase):
    """Two-step import preview flow: upload → preview → confirm."""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user('pt', role='pentester', password='pw')
        self.engagement = Engagement.objects.create(
            name='E1',
            client=EngagementClient.objects.get_or_create(name='ACME')[0],
            created_by=self.user, engagement_type='external',
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.user, role='lead')
        self.client.login(username='pt', password='pw')

    def _upload(self, payload, preview=False):
        data = {
            'tool': 'nuclei',
            'file': SimpleUploadedFile('out.json', payload, content_type='application/json'),
        }
        if preview:
            data['preview'] = 'on'
        return self.client.post(
            reverse('vulns:import', args=[self.engagement.pk]),
            data,
        )

    def test_preview_does_not_commit(self):
        payload = b'[{"templateID":"x","info":{"name":"XSS","severity":"high","description":"d"},"host":"h"}]'
        resp = self._upload(payload, preview=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(Finding.objects.count(), 0)
        self.assertContains(resp, 'Confirm')

    def test_confirm_commits_pending(self):
        payload = b'[{"templateID":"x","info":{"name":"XSS","severity":"high","description":"d"},"host":"h"}]'
        self._upload(payload, preview=True)
        resp = self.client.post(
            reverse('vulns:import', args=[self.engagement.pk]),
            {'confirm_import': '1'},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Finding.objects.count(), 1)

    def test_confirm_without_pending_redirects(self):
        resp = self.client.post(
            reverse('vulns:import', args=[self.engagement.pk]),
            {'confirm_import': '1'},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Finding.objects.count(), 0)


@override_settings(MFA_REQUIRED_ROLES=[])
class CsvImportTests(TestCase):
    """Bulk CSV import: header validation, per-row errors, dedup, role gating."""

    HEADER = b'title,severity,host,port,endpoint,parameter,description,status\n'

    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='pw')
        self.client_user = User.objects.create_user('cli', role='client', password='pw')
        self.outsider = User.objects.create_user('out', role='pentester', password='pw')
        self.engagement = Engagement.objects.create(
            name='E1',
            client=EngagementClient.objects.get_or_create(name='ACME')[0],
            created_by=self.lead, engagement_type='external',
        )
        EngagementMember.objects.create(engagement=self.engagement, user=self.lead, role='lead')
        EngagementMember.objects.create(engagement=self.engagement, user=self.client_user, role='client')

    def _post(self, payload, preview=False, user='lead'):
        self.client.login(username=user, password='pw')
        data = {
            'file': SimpleUploadedFile('findings.csv', payload, content_type='text/csv'),
        }
        if preview:
            data['preview'] = 'on'
        return self.client.post(
            reverse('vulns:import_csv', args=[self.engagement.pk]),
            data,
        )

    def test_outsider_blocked(self):
        payload = self.HEADER + b'XSS,high,h,80,/,,,\n'
        resp = self._post(payload, user='out')
        self.assertIn(resp.status_code, (302, 403))
        self.assertEqual(Finding.objects.count(), 0)

    def test_client_blocked(self):
        payload = self.HEADER + b'XSS,high,h,80,/,,,\n'
        resp = self._post(payload, user='cli')
        self.assertIn(resp.status_code, (302, 403))
        self.assertEqual(Finding.objects.count(), 0)

    def test_missing_required_column(self):
        # Missing `severity` column.
        payload = b'title,host\nXSS,h\n'
        resp = self._post(payload)
        self.assertEqual(Finding.objects.count(), 0)
        self.assertContains(resp, 'Missing required column', status_code=200)

    def test_unknown_column_rejected(self):
        payload = b'title,severity,bogus_col\nXSS,high,whatever\n'
        resp = self._post(payload)
        self.assertEqual(Finding.objects.count(), 0)
        self.assertContains(resp, 'Unknown column', status_code=200)

    def test_valid_rows_imported_without_preview(self):
        payload = self.HEADER + (
            b'SQLi,critical,db.example.com,5432,/api/login,id,Description here,open\n'
            b'XSS,high,web.example.com,443,/search,q,Reflected,confirmed\n'
        )
        resp = self._post(payload, preview=False)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Finding.objects.count(), 2)
        f = Finding.objects.get(title='SQLi')
        # Note: Finding.save() auto-computes severity from CVSS vector, so the
        # CSV's severity column is treated as a hint that may be overridden.
        self.assertEqual(f.host, 'db.example.com')
        self.assertEqual(f.port, 5432)
        self.assertEqual(f.endpoint, '/api/login')
        self.assertEqual(f.parameter, 'id')
        self.assertEqual(f.tool_source, 'Csv')

    def test_row_errors_reported_in_preview(self):
        # Row 2 valid, row 3 bad severity, row 4 bad port.
        payload = self.HEADER + (
            b'OK,high,h,80,/,,,\n'
            b'BadSev,nonsense,h2,80,/,,,\n'
            b'BadPort,medium,h3,abc,/,,,\n'
        )
        resp = self._post(payload, preview=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(Finding.objects.count(), 0)
        self.assertContains(resp, 'Row errors')
        self.assertContains(resp, 'severity')
        self.assertContains(resp, 'port')

    def test_preview_then_confirm_imports_only_valid(self):
        payload = self.HEADER + (
            b'OK,high,h,80,/,,,\n'
            b'BadSev,nonsense,h2,80,/,,,\n'
        )
        self._post(payload, preview=True)
        resp = self.client.post(
            reverse('vulns:import_csv', args=[self.engagement.pk]),
            {'confirm_import': '1'},
        )
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Finding.objects.count(), 1)
        self.assertTrue(Finding.objects.filter(title='OK').exists())

    def test_dedup_against_existing_finding(self):
        Finding.objects.create(
            engagement=self.engagement, title='SQLi', host='db', port=5432,
            endpoint='/api/login', parameter='id',
            severity='critical', found_by=self.lead,
        )
        payload = self.HEADER + (
            b'SQLi,critical,db,5432,/api/login,id,Already filed,open\n'
            b'New,high,web,443,/x,,,\n'
        )
        resp = self._post(payload, preview=False)
        self.assertEqual(resp.status_code, 302)
        # Original + the New row only — the SQLi row is a duplicate.
        self.assertEqual(Finding.objects.count(), 2)
        self.assertTrue(Finding.objects.filter(title='New').exists())

    def test_utf8_bom_tolerated(self):
        payload = b'\xef\xbb\xbf' + self.HEADER + b'OK,high,h,80,/,,,\n'
        resp = self._post(payload, preview=False)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Finding.objects.count(), 1)

    def test_non_csv_extension_rejected(self):
        self.client.login(username='lead', password='pw')
        resp = self.client.post(
            reverse('vulns:import_csv', args=[self.engagement.pk]),
            {'file': SimpleUploadedFile('findings.txt', self.HEADER, content_type='text/plain')},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(Finding.objects.count(), 0)
        self.assertContains(resp, '.csv')
