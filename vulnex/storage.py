"""Private artifacts are only served through authorized download views."""
from django.conf import settings
from django.core.files.storage import FileSystemStorage


def protected_storage():
    return FileSystemStorage(location=settings.PROTECTED_MEDIA_ROOT)
