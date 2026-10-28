import importlib
from pathlib import Path
from tempfile import TemporaryDirectory
from django.conf import settings
from django.core.files.base import ContentFile
from django.test import TestCase, override_settings
from reports.models import Report
from engagements.models import Engagement


class ProtectedReportTests(TestCase):
    def test_reports_are_saved_outside_public_media(self):
        engagement = Engagement.objects.create(name='Storage test', engagement_type='webapp')
        report = Report.objects.create(engagement=engagement, title='Private report')
        report.file.save('private.pdf', ContentFile(b'%PDF-test'))
        path = Path(report.file.path).resolve()
        self.assertTrue(path.is_relative_to(Path(settings.PROTECTED_MEDIA_ROOT).resolve()))
        self.assertFalse(path.is_relative_to(Path(settings.MEDIA_ROOT).resolve()))
        self.assertEqual(report.file.read(), b'%PDF-test')
        report.file.close()

    def test_migration_preserves_files_and_refuses_conflicting_destination(self):
        migration = importlib.import_module('reports.migrations.0003_protect_report_storage')
        with TemporaryDirectory() as tmp:
            public = Path(tmp) / 'public'
            private = Path(tmp) / 'private'
            source = public / 'reports/2026/example.pdf'
            target = private / 'reports/2026/example.pdf'
            source.parent.mkdir(parents=True)
            target.parent.mkdir(parents=True)
            source.write_bytes(b'original')
            target.write_bytes(b'conflict')
            with override_settings(MEDIA_ROOT=public, PROTECTED_MEDIA_ROOT=private):
                with self.assertRaises(RuntimeError):
                    migration.move_reports(None, None)
                self.assertEqual(source.read_bytes(), b'original')
                self.assertEqual(target.read_bytes(), b'conflict')
                target.write_bytes(b'original')
                migration.move_reports(None, None)
                self.assertFalse(source.exists())
                self.assertEqual(target.read_bytes(), b'original')
                migration.move_reports(None, None)
