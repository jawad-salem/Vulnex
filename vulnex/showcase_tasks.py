"""Celery beat task that wipes and re-seeds the showcase database.

Scheduled hourly when ``SHOWCASE_MODE=True`` (see ``CELERY_BEAT_SCHEDULE`` in
``vulnex.settings``). Uses ``manage.py flush`` to keep the schema and just
delete row data, then re-runs the seed commands so the demo client / users /
findings / attack path / report all reappear.
"""

import logging

from celery import shared_task
from django.contrib.auth import get_user_model
from django.core.management import call_command

logger = logging.getLogger(__name__)


@shared_task(name='vulnex.showcase.reset_showcase_database')
def reset_showcase_database():
    """Wipe data and re-seed the demo. Safe to run repeatedly."""
    logger.warning('Showcase reset starting — flushing all data.')

    call_command('flush', '--noinput')

    # `flush` removes the bootstrap superuser too — recreate it so the demo
    # is reachable on the very next request without waiting for the entrypoint
    # to re-run.
    User = get_user_model()
    if not User.objects.filter(is_superuser=True).exists():
        user = User.objects.create_superuser(
            username='admin', email='admin@example.com', password='admin1',
        )
        if hasattr(user, 'role'):
            user.role = 'admin'
            user.save(update_fields=['role'])

    call_command('seed_templates')
    call_command('seed_methodologies')
    call_command('seed_demo', '--force')

    logger.warning('Showcase reset complete.')
    return {'status': 'reset'}
