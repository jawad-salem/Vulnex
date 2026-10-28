"""Isolated test configuration: python manage.py test --settings=vulnex.test_settings."""
import os
import tempfile
from pathlib import Path
os.environ.setdefault('DJANGO_SECRET_KEY', 'vulnex-test-only-secret-key-never-use-in-production')
from .settings import *  # noqa: F403,E402

DEBUG = False
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}}
_test_files = tempfile.TemporaryDirectory(prefix='vulnex-tests-')
MEDIA_ROOT = Path(_test_files.name) / 'media'
PROTECTED_MEDIA_ROOT = Path(_test_files.name) / 'protected_media'
STATIC_ROOT = Path(_test_files.name) / 'static'
STATIC_ROOT.mkdir()
STORAGES = {
    'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
    'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'},
}
# Public, deterministic key used exclusively for disposable test data.
VAULT_MASTER_KEY = 'dGVzdC1vbmx5LWtleS1uZXZlci11c2UtaW4tcHJvZCE='
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'
CELERY_TASK_ALWAYS_EAGER = True
CELERY_TASK_EAGER_PROPAGATES = True
REST_FRAMEWORK = {**REST_FRAMEWORK, 'DEFAULT_RENDERER_CLASSES': ['rest_framework.renderers.JSONRenderer']}
