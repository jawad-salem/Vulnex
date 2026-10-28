"""Move existing reports outside publicly served media before changing storage."""
from pathlib import Path
import filecmp
import shutil
from django.conf import settings
from django.db import migrations, models
import vulnex.storage


def move_reports(apps, schema_editor):
    source = (Path(settings.MEDIA_ROOT) / 'reports').resolve()
    destination = (Path(settings.PROTECTED_MEDIA_ROOT) / 'reports').resolve()
    if source == destination or not source.exists():
        return
    files = list(source.rglob('*'))
    for src in files:
        if src.is_symlink():
            raise RuntimeError('Report storage contains a symlink; resolve it before migrating.')
        if not src.is_file():
            continue
        dst = destination / src.relative_to(source)
        if not dst.resolve().is_relative_to(destination):
            raise RuntimeError('Report destination escapes protected storage.')
        if dst.exists() and not filecmp.cmp(src, dst, shallow=False):
            raise RuntimeError(f'Conflicting protected report: {src.relative_to(source)}')
    for src in files:
        if src.is_file():
            dst = destination / src.relative_to(source)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                src.unlink()  # identical copy verified above
            else:
                shutil.move(str(src), str(dst))


class Migration(migrations.Migration):
    dependencies = [('reports', '0002_report_template')]
    operations = [
        migrations.RunPython(move_reports),
        migrations.AlterField(model_name='report', name='file',
            field=models.FileField(blank=True, storage=vulnex.storage.protected_storage,
                                   upload_to='reports/%Y/%m/')),
    ]
