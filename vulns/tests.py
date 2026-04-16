from django.test import TestCase, Client
from django.urls import reverse
from accounts.models import User
from engagements.models import Engagement, EngagementMember
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
