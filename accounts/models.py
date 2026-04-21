import logging

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models

logger = logging.getLogger(__name__)


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'admin', 'Admin'
        PENTESTER = 'pentester', 'Pentester'
        REVIEWER = 'reviewer', 'Reviewer'
        CLIENT = 'client', 'Client'

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.PENTESTER)
    bio = models.TextField(blank=True)
    avatar_color = models.CharField(max_length=7, default='#534AB7')

    @property
    def initials(self):
        first = self.first_name[:1].upper() if self.first_name else ''
        last = self.last_name[:1].upper() if self.last_name else ''
        return first + last or self.username[:2].upper()

    @property
    def is_admin(self):
        return self.role == self.Role.ADMIN

    @property
    def is_pentester(self):
        return self.role in (self.Role.ADMIN, self.Role.PENTESTER)

    @property
    def is_reviewer(self):
        return self.role == self.Role.REVIEWER

    @property
    def is_client(self):
        return self.role == self.Role.CLIENT

    def __str__(self):
        return self.get_full_name() or self.username


class AuditLog(models.Model):
    """Platform-wide audit trail for admin-level and security-relevant actions.

    Distinct from engagements.ActivityLog, which is scoped per engagement and
    logs pentesting workflow events. AuditLog records things an admin needs to
    answer "who did what": role changes, user CRUD, report downloads, deletions.
    """

    class Action(models.TextChoices):
        USER_CREATE = 'user_create', 'User created'
        USER_UPDATE = 'user_update', 'User updated'
        USER_DELETE = 'user_delete', 'User deleted'
        USER_ROLE_CHANGE = 'user_role_change', 'User role changed'
        ENGAGEMENT_CREATE = 'engagement_create', 'Engagement created'
        ENGAGEMENT_DELETE = 'engagement_delete', 'Engagement deleted'
        REPORT_DOWNLOADED = 'report_downloaded', 'Report downloaded'
        REPORT_GENERATED = 'report_generated', 'Report generated'
        LOGIN_FAILED = 'login_failed', 'Login failed'
        LOGIN_SUCCESS = 'login_success', 'Login succeeded'
        LOGIN_LOCKED = 'login_locked', 'Login locked out'
        LOGOUT = 'logout', 'Logout'
        MFA_ENABLED = 'mfa_enabled', 'MFA enabled'
        MFA_DISABLED = 'mfa_disabled', 'MFA disabled'
        MFA_CHALLENGE_FAILED = 'mfa_challenge_failed', 'MFA challenge failed'
        PASSWORD_CHANGE = 'password_change', 'Password changed'
        CREDENTIAL_CREATE = 'credential_create', 'Credential created'
        CREDENTIAL_DELETE = 'credential_delete', 'Credential deleted'
        CREDENTIAL_REVEAL = 'credential_reveal', 'Credential revealed'
        EVIDENCE_DOWNLOAD = 'evidence_download', 'Evidence downloaded'
        INVITATION_SENT = 'invitation_sent', 'Invitation sent'
        INVITATION_ACCEPTED = 'invitation_accepted', 'Invitation accepted'

    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        null=True, blank=True, related_name='audit_actions',
        help_text='User who performed the action (null for system/failed login)',
    )
    action = models.CharField(max_length=40, choices=Action.choices)
    target = models.CharField(
        max_length=300, blank=True,
        help_text='Subject of the action — username, engagement name, report id, etc.',
    )
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['action', '-timestamp']),
        ]

    def __str__(self):
        who = self.actor.username if self.actor else '<system>'
        return f'[{self.timestamp:%Y-%m-%d %H:%M}] {who} — {self.get_action_display()}'

    @classmethod
    def record(cls, actor, action, target='', details=None, request=None):
        """Helper to create an audit entry. Failures are logged but not
        re-raised — an unreachable DB shouldn't break the user-facing action.
        The `request` arg is kept for API compatibility (e.g. deriving actor
        from request.user in contexts where `actor` is omitted)."""
        try:
            return cls.objects.create(
                actor=actor if actor and getattr(actor, 'is_authenticated', False) else None,
                action=action,
                target=target or '',
                details=details or {},
            )
        except Exception:
            logger.exception('AuditLog.record failed (action=%s, target=%s)', action, target)
            return None

