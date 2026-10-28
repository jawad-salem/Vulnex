"""Report visibility is shared by HTML and API transports."""
from django.db.models import Q
from .models import Report


def visible_reports(user, queryset=None):
    qs = queryset if queryset is not None else Report.objects.all()
    if not user.is_authenticated:
        return qs.none()
    if user.role == 'admin':
        return qs
    return qs.filter(
        Q(engagement__members__user=user) & (
            Q(engagement__members__role__in=['lead', 'pentester', 'reviewer']) |
            Q(published_at__isnull=False)
        )
    ).distinct()
