"""DRF permission classes that mirror the engagement-role decorators used by
the HTML views. Object-level checks delegate to ``Engagement.user_can_*`` so
the rules stay in one place.
"""
from rest_framework.permissions import SAFE_METHODS, BasePermission

from engagements.models import Engagement


def _engagement_from_obj(obj):
    """Return the Engagement instance the object belongs to, or ``None``."""
    if isinstance(obj, Engagement):
        return obj
    return getattr(obj, 'engagement', None) or getattr(
        getattr(obj, 'finding', None), 'engagement', None,
    )


def _engagement_from_view(view, request):
    """Pick up an engagement id from the URL kwargs for list/create actions."""
    eng_pk = view.kwargs.get('engagement_pk') or view.kwargs.get('pk')
    if not eng_pk:
        return None
    try:
        return Engagement.objects.get(pk=eng_pk)
    except Engagement.DoesNotExist:
        return None


class IsEngagementMember(BasePermission):
    """Any member of the engagement (including client role) can read."""

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        eng = _engagement_from_view(view, request)
        if eng is None:
            return True  # list endpoint; queryset is scoped per-user
        return eng.user_can_access(request.user)

    def has_object_permission(self, request, view, obj):
        eng = _engagement_from_obj(obj)
        return bool(eng and eng.user_can_access(request.user))


class IsEngagementEditor(BasePermission):
    """Read for any member, write for lead/pentester (or admin)."""

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        eng = _engagement_from_view(view, request)
        if eng is None:
            return True
        if request.method in SAFE_METHODS:
            return eng.user_can_access(request.user)
        return eng.user_can_edit(request.user)

    def has_object_permission(self, request, view, obj):
        eng = _engagement_from_obj(obj)
        if eng is None:
            return False
        if request.method in SAFE_METHODS:
            return eng.user_can_access(request.user)
        return eng.user_can_edit(request.user)


class IsEngagementReviewer(BasePermission):
    """Read for any member, write for lead/reviewer (or admin)."""

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        eng = _engagement_from_view(view, request)
        if eng is None:
            return True
        if request.method in SAFE_METHODS:
            return eng.user_can_access(request.user)
        return eng.user_can_review(request.user)

    def has_object_permission(self, request, view, obj):
        eng = _engagement_from_obj(obj)
        if eng is None:
            return False
        if request.method in SAFE_METHODS:
            return eng.user_can_access(request.user)
        return eng.user_can_review(request.user)


class CredentialVaultPermission(BasePermission):
    """Credentials are hidden from client role entirely, matching the HTML
    view (``credentials/views.py``). Inside the engagement, lead/pentester
    can write; reviewer reads; client is denied."""

    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        if request.user.role == 'client':
            return False
        eng = _engagement_from_view(view, request)
        if eng is None:
            return True
        role = eng.get_user_role(request.user)
        if request.user.role == 'admin':
            return True
        if role is None or role == 'client':
            return False
        if request.method in SAFE_METHODS:
            return role in ('lead', 'pentester', 'reviewer')
        return role in ('lead', 'pentester')

    def has_object_permission(self, request, view, obj):
        eng = _engagement_from_obj(obj)
        if eng is None or request.user.role == 'client':
            return False
        if request.user.role == 'admin':
            return True
        role = eng.get_user_role(request.user)
        if role is None or role == 'client':
            return False
        if request.method in SAFE_METHODS:
            return role in ('lead', 'pentester', 'reviewer')
        return role in ('lead', 'pentester')
