"""Sidebar navigation helpers.

``nav_active`` centralises the "is this nav item the current page?" decision
that used to live as multi-clause ``and``/``or`` conditionals inline in
base.html — those relied on Django template operator precedence
(``and`` binds tighter than ``or``) and were a bug waiting to happen. Here the
matching is explicit and tested in one place.
"""
from django import template

register = template.Library()


def _split(csv: str | None) -> set[str]:
    return {part.strip() for part in csv.split(',') if part.strip()} if csv else set()


@register.simple_tag(takes_context=True)
def nav_active(context, app=None, urls=None, contains=None, exclude=None, css='active'):
    """Return ``css`` (default ``"active"``) when the current request matches,
    else ``""``.

    All provided criteria must match (logical AND):
      - ``app``      — ``resolver_match.app_name`` equals this value
      - ``urls``     — comma list; ``resolver_match.url_name`` is one of them
      - ``contains`` — substring of ``resolver_match.url_name``
      - ``exclude``  — comma list; vetoes the match if url_name is in it

    Example:
        class="nav-item {% nav_active app='engagements' exclude='client_list,client_detail' %}"
    """
    rm = getattr(context.get('request'), 'resolver_match', None)
    if rm is None:
        return ''

    url_name = rm.url_name or ''
    if url_name in _split(exclude):
        return ''

    if app is not None and rm.app_name != app:
        return ''
    if urls is not None and url_name not in _split(urls):
        return ''
    if contains is not None and contains not in url_name:
        return ''

    # At least one positive criterion must have been supplied to count as a match.
    if app is None and urls is None and contains is None:
        return ''

    return css
