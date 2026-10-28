"""Engagement operations shared by browser and API entry points."""
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from accounts.models import AuditLog
from .models import Engagement, EngagementMember, ActivityLog


def ensure_scope_editable(engagement):
    if engagement.roe_signed_off:
        raise ValidationError('Scope and rules of engagement are locked. Reopen scope before editing.')


@transaction.atomic
def create_engagement(*, actor, engagement):
    if actor.role not in ('admin', 'pentester'):
        raise PermissionDenied('Only admins or pentesters can create engagements.')
    engagement.created_by = actor
    engagement.save()
    EngagementMember.objects.create(engagement=engagement, user=actor, role=EngagementMember.Role.LEAD)
    ActivityLog.objects.create(engagement=engagement, user=actor, action='Created engagement')
    AuditLog.record(actor=actor, action=AuditLog.Action.ENGAGEMENT_CREATE,
                    target=str(engagement.pk), details={'engagement': engagement.name})
    return engagement


@transaction.atomic
def confirm_scope(*, actor, engagement, action, acknowledged=False, reason=''):
    """Explicit, idempotent lead confirmation; this does not create a client signature."""
    from django.utils import timezone
    engagement = Engagement.objects.select_for_update().get(pk=engagement.pk)
    if not engagement.user_is_lead(actor):
        raise PermissionDenied('Only a lead or administrator can confirm scope.')
    if action == 'confirm':
        if engagement.roe_signed_off:
            return
        if not acknowledged:
            raise ValidationError('Confirm that the scope matches the externally approved authorization.')
        if not all(value.strip() for value in [engagement.in_scope, engagement.rules_of_engagement, engagement.authorization_reference]):
            raise ValidationError('Add scope targets, rules of engagement, and an authorization reference before confirming.')
        engagement.roe_signed_off = True
        engagement.roe_signed_off_by = actor
        engagement.roe_signed_off_at = timezone.now()
        message = 'Confirmed scope against external authorization and locked RoE'
    elif action == 'reopen':
        if not engagement.roe_signed_off:
            return
        if not reason.strip():
            raise ValidationError('Provide a reason for reopening the scope.')
        engagement.roe_signed_off = False
        engagement.roe_signed_off_by = None
        engagement.roe_signed_off_at = None
        message = 'Reopened scope for changes: ' + reason.strip()
    else:
        raise ValidationError('Choose confirm or reopen.')
    engagement.save(update_fields=['roe_signed_off', 'roe_signed_off_by', 'roe_signed_off_at', 'updated_at'])
    ActivityLog.objects.create(engagement=engagement, user=actor, action=message[:200])
    AuditLog.record(actor=actor, action=AuditLog.Action.SCOPE_CONFIRMATION, target=str(engagement.pk), details={
        'operation': action, 'reason': reason.strip(), 'authorization_reference': engagement.authorization_reference,
        'in_scope': engagement.in_scope, 'out_of_scope': engagement.out_of_scope,
        'rules_of_engagement': engagement.rules_of_engagement,
    })
