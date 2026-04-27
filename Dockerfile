# syntax=docker/dockerfile:1.6

# ── Builder: compile Python deps into a self-contained venv ─────────────
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r /tmp/requirements.txt


# ── Runtime: slim image, non-root user, venv copied from builder ────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=vulnex.settings

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 1000 vulnex \
    && useradd --system --uid 1000 --gid vulnex --home-dir /app --shell /usr/sbin/nologin vulnex

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=vulnex:vulnex . /app

RUN sed -i 's/\r$//' /app/entrypoint.sh \
    && chmod +x /app/entrypoint.sh \
    && mkdir -p /app/staticfiles /app/media /app/protected_media \
    && chown -R vulnex:vulnex /app/staticfiles /app/media /app/protected_media

USER vulnex

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/accounts/login/ >/dev/null || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["gunicorn", "vulnex.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--access-logfile", "-"]
