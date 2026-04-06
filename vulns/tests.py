from django.test import TestCase
from accounts.models import User
from engagements.models import Engagement
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
