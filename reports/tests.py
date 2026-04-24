from django.core.files.base import ContentFile
from django.test import TestCase, Client, override_settings
from django.urls import reverse

from accounts.models import User
from engagements.models import Engagement, EngagementMember, Client as EngagementClient
from .models import Report


@override_settings(MFA_REQUIRED_ROLES=[])
class DownloadReportContentDispositionTests(TestCase):
    """The download URL's Content-Disposition must be robust against filenames
    that try to escape the header (quotes, CRLF, path separators)."""

    def setUp(self):
        self.client = Client()
        self.lead = User.objects.create_user(
            'lead', role='pentester', password='testpass1',
        )

    def _make_report(self, engagement_name: str, filename: str = 'pentest.pdf') -> Report:
        engagement = Engagement.objects.create(
            name=engagement_name, client=EngagementClient.objects.get_or_create(name='ACME')[0], created_by=self.lead,
        )
        EngagementMember.objects.create(
            engagement=engagement, user=self.lead, role='lead',
        )
        report = Report.objects.create(
            engagement=engagement,
            title=f'{engagement_name} — Full',
            report_type='full',
            generated_by=self.lead,
        )
        report.file.save(filename, ContentFile(b'%PDF-1.4 fake'))
        return report

    def test_quote_in_engagement_name_is_not_unescaped(self):
        """An engagement name with a literal double-quote must not produce a
        Content-Disposition whose quoted filename gets terminated early."""
        report = self._make_report('foo"; download=x', filename='foo"; download=x.pdf')
        self.client.login(username='lead', password='testpass1')
        resp = self.client.get(reverse('reports:download', args=[report.pk]))
        cd = resp['Content-Disposition']
        # The ASCII filename must not contain the raw quote from the input.
        ascii_part = cd.split(';', 2)[1].strip()  # filename="..."
        self.assertTrue(ascii_part.startswith('filename="'))
        self.assertTrue(ascii_part.endswith('"'))
        inside = ascii_part[len('filename="'):-1]
        self.assertNotIn('"', inside)
        self.assertNotIn('download=x', inside.split('"', 1)[0])

    def test_crlf_is_stripped(self):
        report = self._make_report('CRLFTest', filename='line1\r\nline2.pdf')
        self.client.login(username='lead', password='testpass1')
        resp = self.client.get(reverse('reports:download', args=[report.pk]))
        cd = resp['Content-Disposition']
        self.assertNotIn('\r', cd)
        self.assertNotIn('\n', cd)

    def test_unicode_filename_uses_rfc5987(self):
        report = self._make_report('Report', filename='répørt.pdf')
        self.client.login(username='lead', password='testpass1')
        resp = self.client.get(reverse('reports:download', args=[report.pk]))
        cd = resp['Content-Disposition']
        self.assertIn("filename*=UTF-8''", cd)
        # Percent-encoded bytes for the non-ASCII chars.
        self.assertIn('%C3%A9', cd)
