"""Fail-closed scope policy for the current host-wide scanner engines.

Host rules are exact; *.example.com includes descendants, not the apex.
CIDRs authorize individual IPv4 targets. URL rules cannot grant host-wide access;
a URL exclusion conservatively excludes its entire host. No implicit DNS-based
expansion of an IP allowlist to arbitrary hostnames is performed.
"""
from ipaddress import ip_address, ip_network
from urllib.parse import urlsplit
import re
from engagements.models import Engagement


class ScopeViolation(ValueError):
    pass


def hostname(value):
    value = value.lower().rstrip('.')
    try:
        return str(ip_address(value))
    except ValueError:
        pass
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise ScopeViolation('Invalid hostname.')
    if len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
        raise ScopeViolation('Use one hostname or IPv4 address, without ports, paths or command options.')
    return value


def scan_target(value):
    value = value.strip()
    # Do not silently discard port/path restrictions in target input.
    if '://' in value or '/' in value or ':' in value or '*' in value:
        raise ScopeViolation('These scanners require one hostname or IPv4 address; URL, port, IPv6 and CIDR scan targets are not supported.')
    return hostname(value)


def parse_rule(value):
    value = value.strip()
    if '://' in value:
        try:
            url = urlsplit(value)
            if url.scheme not in ('http', 'https') or not url.hostname or url.username or url.password:
                raise ValueError()
            url.port  # validate malformed port syntax
            return ('url', hostname(url.hostname))
        except ValueError:
            raise ScopeViolation('Invalid URL scope rule.')
    if '/' in value:
        try:
            return ('network', ip_network(value, strict=True))
        except ValueError:
            raise ScopeViolation('Use a canonical IP/CIDR, hostname, wildcard domain, or HTTP(S) URL in scope.')
    if value.startswith('*.'):
        return ('wildcard', hostname(value[2:]))
    if ':' in value:
        try:
            return ('network', ip_network(value))
        except ValueError:
            raise ScopeViolation('Host:port scope is unsupported; use an HTTP(S) URL for restricted web scope.')
    try:
        return ('network', ip_network(value))
    except ValueError:
        return ('host', hostname(value))


def matches(rule, host, exclude=False):
    kind, value = rule
    if kind == 'host' or (kind == 'url' and exclude):
        return host == value
    if kind == 'wildcard':
        return host.endswith('.' + value)
    if kind == 'network':
        try:
            address = ip_address(host)
            return address.version == value.version and address in value
        except ValueError:
            return False
    return False


class ScanScope:
    def __init__(self, engagement):
        if not engagement.roe_signed_off:
            raise ScopeViolation('Confirm and lock the engagement scope before running scans.')
        if engagement.status in ('completed', 'cancelled'):
            raise ScopeViolation('Scans are disabled for completed or cancelled engagements.')
        def rules(text):
            return [parse_rule(line) for line in text.splitlines() if line.strip() and not line.strip().startswith('#')]
        self.allowed = rules(engagement.in_scope)
        self.excluded = rules(engagement.out_of_scope)
        if not self.allowed:
            raise ScopeViolation('No scan targets are in scope.')

    def check(self, target):
        host = scan_target(target)
        if any(matches(rule, host, exclude=True) for rule in self.excluded):
            raise ScopeViolation(f'Target is excluded from scope: {host}')
        if not any(matches(rule, host) for rule in self.allowed):
            raise ScopeViolation(f'Target is not authorized for host-wide scanning: {host}. URL-only scope does not authorize all ports and paths.')
        return host

    def check_address(self, host, address):
        self.check(host)
        if any(matches(rule, address, exclude=True) for rule in self.excluded):
            raise ScopeViolation(f'Resolved address is excluded from scope: {host} ({address})')


def current_scope(engagement_id):
    # Re-read at execution time: queued jobs must not trust the enqueue-time state.
    return ScanScope(Engagement.objects.get(pk=engagement_id))


def validate_scan(engagement_id, target):
    return current_scope(engagement_id).check(target)
