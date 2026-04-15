from django import template

register = template.Library()

STEP_LABELS = {
    'port_scan': 'Port Scan',
    'subdomain': 'Subdomain Enumeration',
    'tech_detect': 'Technology Detection',
    'dir_brute': 'Directory Bruteforce',
    'dns_enum': 'DNS Enumeration',
    'whois': 'WHOIS Lookup',
}


@register.filter
def dictget(d, key):
    """Access a dict value by variable key: {{ mydict|dictget:var }}"""
    if isinstance(d, dict):
        return d.get(key)
    return None


@register.filter
def step_label(step_code):
    """Convert scan step code to human-readable label."""
    return STEP_LABELS.get(step_code, step_code)
