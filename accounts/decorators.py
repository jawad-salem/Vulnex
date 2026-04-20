from functools import wraps
from django.conf import settings
from django.shortcuts import redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.mixins import UserPassesTestMixin
from django_otp import user_has_device


def mfa_required_for_role(view_func):
    """Per-view belt-and-suspenders for MFA. MFARequiredMiddleware already
    enforces this globally; this decorator makes the requirement local and
    explicit on security-sensitive views (useful if the middleware is ever
    reordered or removed)."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')
        required = getattr(settings, 'MFA_REQUIRED_ROLES', [])
        if request.user.role in required and not user_has_device(request.user, confirmed=True):
            return redirect('accounts:mfa_setup')
        return view_func(request, *args, **kwargs)
    return _wrapped


def role_required(*roles):
    """Decorator: restrict view to users with specified global roles."""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('accounts:login')
            if request.user.role not in roles:
                messages.error(request, 'You do not have permission to access this page.')
                return redirect('dashboard:home')
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def engagement_access(allow_client=True):
    """
    Decorator: restrict view to engagement members.
    Looks for engagement_pk or pk in kwargs to find the engagement.
    Sets request.engagement and request.membership on the request.

    allow_client=False blocks client role from accessing (e.g., recon, methodology).
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect('accounts:login')

            from engagements.models import Engagement, EngagementMember

            # Find engagement from URL kwargs
            eng_pk = kwargs.get('engagement_pk') or kwargs.get('pk')
            engagement = get_object_or_404(Engagement, pk=eng_pk)

            # Global admins always have access
            if request.user.role == 'admin':
                request.engagement = engagement
                request.membership = None
                request.eng_role = 'admin'
                return view_func(request, *args, **kwargs)

            # Check membership
            try:
                member = EngagementMember.objects.get(
                    engagement=engagement, user=request.user
                )
            except EngagementMember.DoesNotExist:
                messages.error(request, 'You are not a member of this engagement.')
                return redirect('engagements:list')

            # Client restriction
            if not allow_client and member.role == 'client':
                messages.error(request, 'Clients do not have access to this section.')
                return redirect('engagements:detail', pk=engagement.pk)

            request.engagement = engagement
            request.membership = member
            request.eng_role = member.role
            return view_func(request, *args, **kwargs)
        return _wrapped
    return decorator


def engagement_edit_required(view_func):
    """Decorator: require lead or pentester role on the engagement."""
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('accounts:login')

        from engagements.models import Engagement, EngagementMember

        eng_pk = kwargs.get('engagement_pk') or kwargs.get('pk')
        engagement = get_object_or_404(Engagement, pk=eng_pk)

        if request.user.role == 'admin':
            request.engagement = engagement
            request.membership = None
            request.eng_role = 'admin'
            return view_func(request, *args, **kwargs)

        try:
            member = EngagementMember.objects.get(
                engagement=engagement, user=request.user
            )
        except EngagementMember.DoesNotExist:
            messages.error(request, 'You are not a member of this engagement.')
            return redirect('engagements:list')

        if member.role not in ('lead', 'pentester'):
            messages.error(request, 'You do not have edit permissions on this engagement.')
            return redirect('engagements:detail', pk=engagement.pk)

        request.engagement = engagement
        request.membership = member
        request.eng_role = member.role
        return view_func(request, *args, **kwargs)
    return _wrapped


class AdminRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_authenticated and self.request.user.is_admin


class PentesterRequiredMixin(UserPassesTestMixin):
    def test_func(self):
        return self.request.user.is_authenticated and self.request.user.is_pentester

