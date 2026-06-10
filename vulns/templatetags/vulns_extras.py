"""Markdown rendering for user-authored text (comments, finding bodies).

Pipeline: raw → markdown → bleach allowlist → safe HTML. The allowlist is
intentionally minimal — basic inline formatting, code blocks, tables, no
scripts/styles/iframes.

The PDF generator reuses ``render_markdown`` and lowers the resulting HTML into
ReportLab flowables in ``reports.markdown`` (kept out of this template layer).
"""
import bleach
import markdown as md
from django import template
from django.utils.safestring import mark_safe


register = template.Library()


ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'code', 'pre', 'a',
    'ul', 'ol', 'li', 'blockquote',
    'table', 'thead', 'tbody', 'tr', 'td', 'th',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'hr',
]
ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'rel'],
    'code': ['class'],
    'pre': ['class'],
}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

MARKDOWN_EXTENSIONS = ['fenced_code', 'tables', 'sane_lists', 'nl2br', 'toc']


def render_markdown(raw: str) -> str:
    """Render Markdown → sanitized HTML. Returns empty string on falsy input."""
    if not raw:
        return ''
    html = md.markdown(
        raw,
        extensions=MARKDOWN_EXTENSIONS,
        output_format='html',
    )
    clean = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
    clean = bleach.linkify(clean, parse_email=True)
    return clean


@register.filter(name='markdown')
def markdown_filter(value):
    return mark_safe(render_markdown(value or ''))
