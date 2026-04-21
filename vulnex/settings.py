import os
import sys
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError(
        'DJANGO_SECRET_KEY must be set in the .env file. '
        'Generate one with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"'
    )
DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    # Third-party
    'django_celery_beat',
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django_otp.plugins.otp_static',
    'axes',
    # Local apps
    'accounts',
    'dashboard',
    'engagements',
    'vulns',
    'recon',
    'methodology',
    'reports',
    'credentials',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django_otp.middleware.OTPMiddleware',
    'accounts.middleware.MFARequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    # django-axes: must come last so failed logins from earlier middleware
    # are still observed.
    'axes.middleware.AxesMiddleware',
]

AUTHENTICATION_BACKENDS = [
    # Axes runs first — it short-circuits locked-out credentials before
    # the underlying ModelBackend performs the hash check.
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]

ROOT_URLCONF = 'vulnex.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'engagements.context_processors.engagement_role',
            ],
        },
    },
]

WSGI_APPLICATION = 'vulnex.wsgi.application'

# Database — SQLite for dev, PostgreSQL for prod
if os.environ.get('DATABASE_URL'):
    import dj_database_url
    DATABASES = {'default': dj_database_url.parse(os.environ['DATABASE_URL'])}
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

AUTH_USER_MODEL = 'accounts.User'

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'
STORAGES = {
    'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
    'staticfiles': {'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage'},
}

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_URL = '/accounts/login/'
LOGIN_REDIRECT_URL = '/dashboard/'
LOGOUT_REDIRECT_URL = '/accounts/login/'

# Email
# Console backend for development (prints emails to terminal)
# Switch to SMTP for production
EMAIL_BACKEND = os.environ.get(
    'EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend'
)
EMAIL_HOST = os.environ.get('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL', 'Vulnex <noreply@vulnex.local>')

# Base URL for invitation links
SITE_URL = os.environ.get('SITE_URL', 'http://localhost:8000')

# ── Security headers ──
# Prevent clickjacking
X_FRAME_OPTIONS = 'DENY'
# Prevent MIME type sniffing
SECURE_CONTENT_TYPE_NOSNIFF = True

# HTTPS hardening — opt-in via env var so local/native runs don't force TLS.
# Set DJANGO_USE_HTTPS=True only when deploying behind a TLS-terminating proxy.
USE_HTTPS = os.environ.get('DJANGO_USE_HTTPS', 'False').lower() == 'true'
if USE_HTTPS:
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Celery (for background tasks like recon pipelines and scheduled scans).
# If CELERY_BROKER_URL is not set in the environment, fall back to eager mode
# so native `manage.py runserver` setups work without needing Redis.
_broker = os.environ.get('CELERY_BROKER_URL')
CELERY_BROKER_URL = _broker or 'memory://'
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'cache+memory://')
CELERY_TASK_ALWAYS_EAGER = not _broker
CELERY_TASK_EAGER_PROPAGATES = True
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

# ── Credentials vault ──
# VAULT_MASTER_KEY must be a Fernet key (32 bytes, base64url-encoded).
# Generate one with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Optional in DEBUG (falls back to a SECRET_KEY-derived key with a warning).
# Required when DEBUG=False — credentials/checks.py surfaces the error via
# `manage.py check --deploy` and _fernet() raises ImproperlyConfigured on use.
VAULT_MASTER_KEY = os.environ.get('VAULT_MASTER_KEY', '').strip()

# ── MFA ──
# Roles that must complete TOTP setup before accessing the app. Clients can
# opt in via the profile page but aren't forced.
MFA_REQUIRED_ROLES = ['admin', 'pentester', 'reviewer']

# ── django-axes: login rate limit & lockout ──
# 5 failed attempts per (username, IP) combination trigger a 30-minute
# lockout. Successful logins reset the counter for that pair.
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=30)
AXES_LOCKOUT_PARAMETERS = [['username', 'ip_address']]
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_TEMPLATE = 'axes/locked_out.html'
# Disable axes during the test runner — Django's `client.login()` calls
# `authenticate()` without a request, which the axes backend rejects. The
# dedicated lockout test re-enables axes via `@override_settings`.
if 'test' in sys.argv:
    AXES_ENABLED = False

# CVSS severity thresholds
SEVERITY_THRESHOLDS = {
    'critical': 9.0,
    'high': 7.0,
    'medium': 4.0,
    'low': 0.1,
    'info': 0.0,
}
