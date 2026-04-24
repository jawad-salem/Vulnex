import io

from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client, override_settings
from django.urls import reverse

from accounts.models import User
from engagements.models import Engagement, EngagementMember, Client as EngagementClient
from .forms import ReportTemplateForm
from .generator import _resolve_template, _build_brand
from .models import Report, ReportTemplate


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


def _png_bytes(size=(4, 4)):
    try:
        from PIL import Image as PILImage
    except Exception:
        # PNG header + single-pixel payload is enough to pass Pillow.verify.
        return (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
            b'\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
            b'\x00\x00\x00\x0cIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe'
            b'\xdc\xccY\xe7\x00\x00\x00\x00IEND\xaeB`\x82'
        )
    buf = io.BytesIO()
    PILImage.new('RGB', size, (255, 0, 0)).save(buf, format='PNG')
    return buf.getvalue()


@override_settings(MFA_REQUIRED_ROLES=[])
class ReportTemplateResolutionTests(TestCase):
    """_resolve_template picks explicit > client default > global default."""

    def setUp(self):
        self.user = User.objects.create_user('u', role='admin', password='x')
        self.client_org = EngagementClient.objects.create(name='ACME')
        self.engagement = Engagement.objects.create(
            name='Eng', client=self.client_org, created_by=self.user,
            engagement_type='external',
        )
        self.global_default = ReportTemplate.objects.create(
            name='Global', is_default=True,
            primary_color='#111111', accent_color='#222222',
        )
        self.client_template = ReportTemplate.objects.create(
            name='Client-pinned',
            primary_color='#AAAAAA', accent_color='#BBBBBB',
        )
        self.explicit = ReportTemplate.objects.create(
            name='Explicit',
            primary_color='#CCCCCC', accent_color='#DDDDDD',
        )

    def test_explicit_wins(self):
        self.client_org.default_report_template = self.client_template
        self.client_org.save()
        resolved = _resolve_template(self.engagement, template=self.explicit)
        self.assertEqual(resolved, self.explicit)

    def test_client_default_wins_over_global(self):
        self.client_org.default_report_template = self.client_template
        self.client_org.save()
        resolved = _resolve_template(self.engagement, template=None)
        self.assertEqual(resolved, self.client_template)

    def test_global_default_fallback(self):
        resolved = _resolve_template(self.engagement, template=None)
        self.assertEqual(resolved, self.global_default)

    def test_brand_uses_template_colors(self):
        from reportlab.lib.colors import HexColor
        brand = _build_brand(self.engagement, self.client_template)
        self.assertEqual(brand.primary, HexColor('#AAAAAA'))
        self.assertEqual(brand.accent, HexColor('#BBBBBB'))

    def test_setting_default_clears_others(self):
        self.client_template.is_default = True
        self.client_template.save()
        self.global_default.refresh_from_db()
        self.assertFalse(self.global_default.is_default)


@override_settings(MFA_REQUIRED_ROLES=[])
class ReportTemplateLogoValidationTests(TestCase):
    """ReportTemplateForm must reject oversize uploads and non-PNG/JPG formats."""

    def test_png_under_limit_is_valid(self):
        upload = SimpleUploadedFile('logo.png', _png_bytes(), content_type='image/png')
        form = ReportTemplateForm(
            data={
                'name': 'Brand', 'primary_color': '#123456',
                'accent_color': '#789ABC', 'preamble_markdown': '',
                'disclaimer_markdown': '', 'footer_text': '',
            },
            files={'cover_logo': upload},
        )
        self.assertTrue(form.is_valid(), form.errors)

    def test_oversize_logo_rejected(self):
        big = b'\x00' * (1024 * 1024 + 10)
        upload = SimpleUploadedFile('big.png', big, content_type='image/png')
        form = ReportTemplateForm(
            data={
                'name': 'Too big', 'primary_color': '#123456',
                'accent_color': '#789ABC', 'preamble_markdown': '',
                'disclaimer_markdown': '', 'footer_text': '',
            },
            files={'cover_logo': upload},
        )
        self.assertFalse(form.is_valid())
        self.assertIn('cover_logo', form.errors)

    def test_gif_rejected(self):
        gif = b'GIF89a\x01\x00\x01\x00\x00\x00\x00;'
        upload = SimpleUploadedFile('logo.gif', gif, content_type='image/gif')
        form = ReportTemplateForm(
            data={
                'name': 'Gif', 'primary_color': '#123456',
                'accent_color': '#789ABC', 'preamble_markdown': '',
                'disclaimer_markdown': '', 'footer_text': '',
            },
            files={'cover_logo': upload},
        )
        self.assertFalse(form.is_valid())
        self.assertIn('cover_logo', form.errors)


@override_settings(MFA_REQUIRED_ROLES=[])
class TemplatePreviewAccessTests(TestCase):
    """Template CRUD and preview endpoints must be admin-only."""

    def setUp(self):
        self.client = Client()
        self.admin = User.objects.create_user('admin1', role='admin', password='p')
        self.pentester = User.objects.create_user('p1', role='pentester', password='p')
        self.template = ReportTemplate.objects.create(
            name='Brand', primary_color='#123456', accent_color='#789ABC',
        )

    def test_non_admin_blocked_from_list(self):
        self.client.login(username='p1', password='p')
        resp = self.client.get(reverse('reports:template_list'))
        self.assertEqual(resp.status_code, 302)

    def test_non_admin_blocked_from_preview(self):
        self.client.login(username='p1', password='p')
        resp = self.client.get(reverse('reports:template_preview', args=[self.template.pk]))
        self.assertEqual(resp.status_code, 302)

    def test_admin_can_list(self):
        self.client.login(username='admin1', password='p')
        resp = self.client.get(reverse('reports:template_list'))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Brand')
