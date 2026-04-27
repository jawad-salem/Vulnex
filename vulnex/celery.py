import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vulnex.settings')
app = Celery('vulnex')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()

# Project-level tasks (not in any INSTALLED_APP) need explicit registration.
import vulnex.showcase_tasks  # noqa: E402,F401
