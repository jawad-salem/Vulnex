"""Showcase-mode glue.

When ``SHOWCASE_MODE=True``, Vulnex runs as a public demo:

* a banner reminds visitors not to enter real data,
* outbound email is forced to the locmem backend (configured in ``settings``),
* the database is wiped and re-seeded hourly by a Celery beat job
  (``vulnex.showcase_tasks.reset_showcase_database``),
* destructive or write-amplifying actions are blocked at the URL level —
  new admin user creation and new API key issuance.

The blocked-URL list is intentionally short. We do NOT block engagement /
finding / comment edits because those *are* the demo experience; the hourly
reset cleans them up.
"""

from django.http import HttpResponseForbidden


# (namespace, url_name) pairs that 403 in showcase mode.
SHOWCASE_BLOCKED_VIEWS = frozenset({
    ('accounts', 'user_create'),
    ('accounts', 'api_key_create'),
})

SHOWCASE_BANNER_TEXT = (
    'Public demo · resets hourly · do not enter real data'
)


class ShowcaseModeMiddleware:
    """Block destructive actions and surface a banner when SHOWCASE_MODE is on.

    Sits *after* AuthenticationMiddleware so we can identify the actor in any
    audit log entry and *after* CsrfViewMiddleware so the 403 we return for
    blocked POSTs still has gone through CSRF validation.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from django.conf import settings

        request.showcase_mode = bool(getattr(settings, 'SHOWCASE_MODE', False))
        request.showcase_banner = SHOWCASE_BANNER_TEXT if request.showcase_mode else ''
        return self.get_response(request)

    def process_view(self, request, view_func, view_args, view_kwargs):
        from django.conf import settings

        if not getattr(settings, 'SHOWCASE_MODE', False):
            return None
        match = getattr(request, 'resolver_match', None)
        if match is None:
            return None
        if (match.namespace, match.url_name) in SHOWCASE_BLOCKED_VIEWS:
            if request.method == 'POST':
                return HttpResponseForbidden(
                    'This action is disabled in the public demo. '
                    'Self-host Vulnex to manage users and API keys.'
                )
        return None


def showcase_context(request):
    """Template context processor — exposes `showcase_mode` and `showcase_banner`."""
    return {
        'showcase_mode': getattr(request, 'showcase_mode', False),
        'showcase_banner': getattr(request, 'showcase_banner', ''),
    }
