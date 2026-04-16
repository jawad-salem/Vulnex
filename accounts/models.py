from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.db import models


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
        REPORT_DOWNLOAD = 'report_download', 'Report downloaded'
        REPORT_GENERATE = 'report_generate', 'Report generated'
        LOGIN_FAILED = 'login_failed', 'Login failed'

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
    ip_address = models.GenericIPAddressField(null=True, blank=True)
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
        """Helper to create an audit entry. Silently no-ops on failure so
        callers aren't forced to wrap every event in try/except."""
        ip = None
        if request is not None:
            xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
            ip = xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR')
        try:
            return cls.objects.create(
                actor=actor if actor and getattr(actor, 'is_authenticated', False) else None,
                action=action,
                target=target or '',
                details=details or {},
                ip_address=ip,
            )
        except Exception:
            return None

