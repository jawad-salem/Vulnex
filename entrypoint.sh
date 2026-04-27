#!/bin/sh
set -e

echo "[entrypoint] waiting for postgres..."
python <<'PYEOF'
import os, time, sys, urllib.parse as u
import psycopg2
url = u.urlparse(os.environ.get("DATABASE_URL", ""))
if not url.scheme.startswith("postgres"):
    sys.exit(0)
deadline = time.time() + 60
while time.time() < deadline:
    try:
        psycopg2.connect(
            host=url.hostname, port=url.port or 5432,
            user=url.username, password=url.password,
            dbname=url.path.lstrip("/"),
        ).close()
        sys.exit(0)
    except Exception:
        time.sleep(1)
sys.exit("[entrypoint] postgres not reachable after 60s")
PYEOF

echo "[entrypoint] running migrations..."
python manage.py migrate --noinput

echo "[entrypoint] collecting static files..."
python manage.py collectstatic --noinput

echo "[entrypoint] seeding finding templates and methodologies (idempotent)..."
python manage.py seed_templates || true
python manage.py seed_methodologies || true

echo "[entrypoint] ensuring a superuser exists..."
python manage.py shell <<'PYEOF'
import os
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    username = os.environ.get("DJANGO_BOOTSTRAP_USERNAME", "admin")
    password = os.environ.get("DJANGO_BOOTSTRAP_PASSWORD", "admin1")
    email = os.environ.get("DJANGO_BOOTSTRAP_EMAIL", "admin@example.com")
    user = User.objects.create_superuser(username=username, email=email, password=password)
    if hasattr(user, "role"):
        user.role = "admin"
        user.save(update_fields=["role"])
    print(f"[entrypoint] created default superuser '{username}' (CHANGE THE PASSWORD)")
else:
    print("[entrypoint] superuser already exists, skipping bootstrap")
PYEOF

echo "[entrypoint] starting: $@"
exec "$@"
