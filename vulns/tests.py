from datetime import timedelta
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from accounts.models import User
from engagements.models import Engagement, EngagementMember, ActivityLog
from .models import Finding


class CVSSCalculationTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Test Engagement',
            client_name='Test Client',
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


class RetestWorkflowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.pentester = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='Test', client_name='ACME', created_by=self.pentester,
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


class SLATrackingTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user('pt', role='pentester', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='T', client_name='ACME', created_by=self.user,
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


class FindingAssignmentTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user('lead', role='pentester', password='testpass1')
        self.alice = User.objects.create_user('alice', role='pentester', password='testpass1')
        self.bob = User.objects.create_user('bob', role='pentester', password='testpass1')
        self.cli = User.objects.create_user('cli', role='client', password='testpass1')
        self.engagement = Engagement.objects.create(
            name='T', client_name='ACME', created_by=self.lead,
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
