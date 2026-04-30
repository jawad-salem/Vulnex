import os
import sys
from datetime import timedelta
from pathlib import Path
from csp.constants import NONCE
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
    'csp',
    'rest_framework',
    'drf_spectacular',
    # Local apps
    'accounts',
    'dashboard',
    'engagements',
    'vulns',
    'recon',
    'methodology',
    'reports',
    'credentials',
    'api',
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
    'vulnex.showcase.ShowcaseModeMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'accounts.middleware.PermissionsPolicyMiddleware',
    'csp.middleware.CSPMiddleware',
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
                'vulnex.showcase.showcase_context',
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

# Files served only through authenticated views (Evidence uploads). Never
# exposed via MEDIA_URL or staticfiles — vulns.views.evidence_download streams
# them after gating on engagement membership.
PROTECTED_MEDIA_ROOT = BASE_DIR / 'protected_media'

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
# Leak as little URL info as possible to third parties.
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
# Disable browser APIs we never use.
PERMISSIONS_POLICY = {
    'camera': [],
    'microphone': [],
    'geolocation': [],
}
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'

# Cookies stay on-site only — blocks CSRF-via-top-level-nav and cross-site
# session reuse. SameSite=Strict is safe here because Vulnex has no
# third-party embed / cross-site flows.
SESSION_COOKIE_SAMESITE = 'Strict'
CSRF_COOKIE_SAMESITE = 'Strict'

# ── Content-Security-Policy (django-csp 4.x dict format) ──
# Lock scripts to self + the jsdelivr CDN Chart.js is loaded from; everything
# else is same-origin. Inline styles are permitted because templates still
# carry style="..." attributes.
CONTENT_SECURITY_POLICY = {
    # Inline <script> blocks in templates are allowed via a per-request nonce
    # (django-csp 4.x substitutes NONCE for 'nonce-<random>' and sets
    # request.csp_nonce for template use). No 'unsafe-inline' needed.
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src': ("'self'", NONCE, 'https://cdn.jsdelivr.net'),
        'style-src': ("'self'", "'unsafe-inline'"),
        'img-src': ("'self'", 'data:'),
        'connect-src': ("'self'",),
        'frame-ancestors': ("'none'",),
        'base-uri': ("'self'",),
        'form-action': ("'self'",),
    },
}

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

# ── REST API (DRF + SimpleJWT + drf-spectacular) ──
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'api.authentication.APIKeyAuthentication',
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'user': '1000/hour',
    },
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
    # Browsable HTML renderer is a debugging aid that enumerates the API surface
    # to anyone who lands on a JSON endpoint with a browser. Keep it for local
    # development; ship JSON-only in any deployment.
    'DEFAULT_RENDERER_CLASSES': (
        ['rest_framework.renderers.JSONRenderer', 'rest_framework.renderers.BrowsableAPIRenderer']
        if DEBUG else
        ['rest_framework.renderers.JSONRenderer']
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=30),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': False,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'Vulnex API',
    'DESCRIPTION': 'Read/write REST API for Vulnex engagements, findings, hosts, credentials, and reports.',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    # Collapse confidentiality/integrity/availability impact (all share H/L/N)
    # into a single CvssImpactEnum component instead of three identical copies.
    'ENUM_NAME_OVERRIDES': {
        'CvssImpactEnum': [
            ('H', 'High'),
            ('L', 'Low'),
            ('N', 'None'),
        ],
    },
}

# CVSS severity thresholds
SEVERITY_THRESHOLDS = {
    'critical': 9.0,
    'high': 7.0,
    'medium': 4.0,
    'low': 0.1,
    'info': 0.0,
}

# ── Showcase mode (public live demo) ──
# When SHOWCASE_MODE=True:
#  * the database is wiped and re-seeded hourly via Celery beat
#    (vulnex.showcase_tasks.reset_showcase_database),
#  * outbound email is silenced (locmem backend),
#  * a banner is rendered on every page,
#  * new admin user creation and new API key issuance are blocked at the
#    middleware layer.
SHOWCASE_MODE = os.environ.get('SHOWCASE_MODE', 'False').lower() == 'true'

if SHOWCASE_MODE:
    # Force outbound email into a memory queue so demo invitations / password
    # resets never reach a real inbox.
    EMAIL_BACKEND = 'django.core.mail.backends.locmem.EmailBackend'

    # Hourly reset job. The DatabaseScheduler in INSTALLED_APPS picks this up
    # via django-celery-beat on first boot.
    from celery.schedules import crontab as _crontab
    CELERY_BEAT_SCHEDULE = {
        **(globals().get('CELERY_BEAT_SCHEDULE') or {}),
        'showcase-hourly-reset': {
            'task': 'vulnex.showcase.reset_showcase_database',
            'schedule': _crontab(minute=0),  # top of every hour
        },
    }
