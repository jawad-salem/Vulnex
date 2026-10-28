"""Finding visibility and review transitions shared across transports."""
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from engagements.models import ActivityLog
from vulns.models import Finding


def visible_findings(user, queryset=None):
    qs = queryset if queryset is not None else Finding.objects.all()
    if not user.is_authenticated:
        return qs.none()
    if user.role == 'admin':
        return qs
    return qs.filter(
        Q(engagement__members__user=user) & (
            Q(engagement__members__role__in=('lead', 'pentester', 'reviewer')) | Q(review_state=Finding.ReviewState.APPROVED)
        )
    ).distinct()


@transaction.atomic
def transition_review(*, actor, finding, target, notes=''):
    finding = Finding.objects.select_for_update().select_related('engagement').get(pk=finding.pk)
    state = Finding.ReviewState
    if target == state.IN_REVIEW:
        if not finding.engagement.user_can_edit(actor):
            raise PermissionDenied('You cannot submit findings for review.')
        allowed = (state.DRAFT, state.CHANGES_REQUESTED)
        label = 'Submitted finding for review'
    elif target in (state.APPROVED, state.CHANGES_REQUESTED):
        if not finding.engagement.user_can_review(actor):
            raise PermissionDenied('Only leads and reviewers can review findings.')
        allowed = (state.IN_REVIEW,)
        label = 'Approved finding' if target == state.APPROVED else 'Requested changes on finding'
    else:
        raise ValidationError('Unsupported review transition.')
    if finding.review_state not in allowed:
        raise ValidationError('This finding is not in a state that permits this review action.')
    notes = notes.strip()
    if target == state.CHANGES_REQUESTED and not notes:
        raise ValidationError('Please explain what needs to change.')
    finding.review_state = target
    finding.review_notes = notes if target == state.CHANGES_REQUESTED else ''
    finding.reviewed_by = actor if target != state.IN_REVIEW else None
    finding.reviewed_at = timezone.now() if target != state.IN_REVIEW else None
    finding.save(update_fields=['review_state', 'review_notes', 'reviewed_by', 'reviewed_at', 'updated_at'])
    ActivityLog.objects.create(engagement=finding.engagement, user=actor, action=f'{label}: {finding.title}')
    return finding
