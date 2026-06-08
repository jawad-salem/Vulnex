"""Finding-merge service.

Moves one finding's evidence/comments/body into another and deletes the source,
all in a single transaction. Extracted from ``vulns.views`` so the operation is
testable and reusable without an HTTP request.
"""
from django.db import transaction

from ..models import Finding


def merge_findings(source: Finding, target: Finding, actor) -> dict:
    """Move source's evidence + comments into target, append source's body
    fields as a labelled section, then delete source. Returns a small summary
    suitable for the audit log details payload.

    Caller must check both belong to the same engagement and that ``actor``
    has permission. The whole operation runs in a single transaction.
    """
    moved_evidence = source.evidence.count()
    moved_comments = source.comments.count()

    sections = []
    label = f'Merged from "{source.title}" ({source.get_severity_display()})'
    if source.description:
        sections.append(f'### {label} — Description\n\n{source.description}')
    if source.proof_of_concept:
        sections.append(f'### {label} — Proof of concept\n\n{source.proof_of_concept}')
    if source.remediation:
        sections.append(f'### {label} — Remediation\n\n{source.remediation}')
    extra = '\n\n'.join(sections)

    with transaction.atomic():
        if extra:
            target.description = (
                (target.description or '').rstrip() + '\n\n' + extra
            ).strip()
        # Reparent evidence and comments. Bulk update keeps queries to one each.
        source.evidence.update(finding=target)
        source.comments.update(finding=target)
        target.save()
        source_id = source.pk
        source_title = source.title
        source.delete()

    return {
        'source_id': str(source_id),
        'source_title': source_title,
        'target_id': str(target.pk),
        'target_title': target.title,
        'moved_evidence': moved_evidence,
        'moved_comments': moved_comments,
    }
