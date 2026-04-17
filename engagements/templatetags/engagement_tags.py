from django import template

register = template.Library()


_POSITIVE = ('approved', 'completed', 'joined', 'created', 'added', 'invited', 'imported')
_DANGER = ('deleted', 'removed')
_WARN = ('revealed', 'requested changes', 'changed status', 'retested')


@register.filter
def activity_tone(action):
    """Classify a free-text activity action string into a tone class.

    Returns one of: 'positive', 'danger', 'warn', or '' (neutral).
    Used by the activity log to color the leading dot.
    """
    if not action:
        return ''
    low = action.lower()
    for kw in _DANGER:
        if kw in low:
            return 'danger'
    for kw in _WARN:
        if kw in low:
            return 'warn'
    for kw in _POSITIVE:
        if low.startswith(kw) or f' {kw}' in low:
            return 'positive'
    return ''
