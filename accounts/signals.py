from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver

from .models import AuditLog


@receiver(user_logged_in)
def _record_login_success(sender, request, user, **kwargs):
    AuditLog.record(actor=user, action=AuditLog.Action.LOGIN_SUCCESS, target=user.username)


@receiver(user_logged_out)
def _record_logout(sender, request, user, **kwargs):
    if user is None:
        return
    AuditLog.record(actor=user, action=AuditLog.Action.LOGOUT, target=user.username)


try:
    from axes.signals import user_locked_out
except ImportError:
    user_locked_out = None


if user_locked_out is not None:
    @receiver(user_locked_out)
    def _record_login_locked(sender, request, username=None, ip_address=None, **kwargs):
        AuditLog.record(
            actor=None,
            action=AuditLog.Action.LOGIN_LOCKED,
            target=username or '',
            details={'ip': ip_address or ''},
        )
