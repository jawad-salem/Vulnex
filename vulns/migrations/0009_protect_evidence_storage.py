import shutil
from pathlib import Path

from django.conf import settings
from django.db import migrations, models

import vulns.models


def _move_tree(src_root: Path, dst_root: Path):
    if not src_root.exists():
        return
    for src in src_root.rglob('*'):
        if not src.is_file():
            continue
        rel = src.relative_to(src_root)
        dst = dst_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if not dst.exists():
            shutil.move(str(src), str(dst))


def move_evidence_to_protected(apps, schema_editor):
    _move_tree(
        Path(settings.MEDIA_ROOT) / 'evidence',
        Path(settings.PROTECTED_MEDIA_ROOT) / 'evidence',
    )


def move_evidence_to_media(apps, schema_editor):
    _move_tree(
        Path(settings.PROTECTED_MEDIA_ROOT) / 'evidence',
        Path(settings.MEDIA_ROOT) / 'evidence',
    )


class Migration(migrations.Migration):

    dependencies = [
        ('vulns', '0008_add_review_workflow'),
    ]

    operations = [
        migrations.AlterField(
            model_name='evidence',
            name='file',
            field=models.FileField(
                storage=vulns.models.protected_storage,
                upload_to='evidence/%Y/%m/',
            ),
        ),
        migrations.RunPython(move_evidence_to_protected, move_evidence_to_media),
    ]
