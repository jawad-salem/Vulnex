"""Serialize OTP consumption so concurrent requests cannot reuse a code."""
from django.db import transaction
from django_otp import devices_for_user


def verify_code(user, code):
    if not code:
        return None
    # Commit failed-attempt counters too; callers raise only after we return.
    with transaction.atomic():
        for device in devices_for_user(user, confirmed=True, for_verify=True):
            if device.verify_token(code):
                return device
    return None
