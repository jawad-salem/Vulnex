"""
Real scanning engines using Python stdlib.
No external tools required — works on Windows, Linux, and macOS.
"""
import socket
import struct
import ssl
import json
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Common ports to scan ──
COMMON_PORTS = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
    139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
    993: 'imaps', 995: 'pop3s', 1433: 'ms-sql', 1521: 'oracle',
    3306: 'mysql', 3389: 'ms-wbt-server', 5432: 'postgresql',
    5900: 'vnc', 6379: 'redis', 8080: 'http-proxy', 8443: 'https-alt',
    8888: 'http-alt', 27017: 'mongodb',
}

# ── Subdomain wordlist ──
SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'api', 'dev', 'staging', 'test', 'admin',
    'portal', 'blog', 'shop', 'store', 'app', 'secure', 'vpn',
    'remote', 'ns1', 'ns2', 'mx', 'smtp', 'pop', 'imap', 'webmail',
    'cpanel', 'whm', 'autodiscover', 'autoconfig', 'cdn', 'media',
    'static', 'assets', 'img', 'images', 'docs', 'wiki', 'git',
    'gitlab', 'jenkins', 'ci', 'jira', 'confluence', 'grafana',
    'monitor', 'status', 'dashboard', 'sso', 'auth', 'login',
    'register', 'beta', 'demo', 'sandbox', 'internal', 'intranet',
    'backup', 'db', 'database', 'redis', 'elastic', 'kibana',
    'm', 'mobile', 'ws', 'socket', 'proxy', 'gateway', 'edge',
]

# ── Common directories ──
COMMON_DIRS = [
    '/', '/robots.txt', '/sitemap.xml', '/.env', '/.git/HEAD',
    '/admin/', '/login/', '/wp-admin/', '/wp-login.php',
    '/administrator/', '/phpmyadmin/', '/cpanel/', '/webmail/',
    '/.htaccess', '/.htpasswd', '/server-status', '/server-info',
    '/api/', '/api/v1/', '/graphql', '/swagger/', '/docs/',
    '/backup/', '/backups/', '/dump/', '/config/', '/conf/',
    '/.well-known/security.txt', '/security.txt',
    '/info.php', '/phpinfo.php', '/test/', '/debug/',
    '/uploads/', '/upload/', '/files/', '/tmp/',
    '/console/', '/shell/', '/cmd/', '/exec/',
    '/wp-content/', '/wp-includes/', '/wp-json/',
    '/.svn/', '/.git/', '/.hg/', '/.bzr/',
    '/elmah.axd', '/trace.axd', '/web.config',
]


import ipaddress


def _is_internal_ip(ip_str: str) -> bool:
    """Check if an IP address is internal/private/reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip_str.startswith('169.254.')  # AWS metadata, link-local
        )
    except ValueError:
        return False


def _validate_target(target: str) -> tuple[str, str]:
    """Extract hostname from target, validate it's not internal.

    Returns (hostname, ip) tuple. Callers MUST use the returned IP for
    subsequent connections — re-resolving the hostname would re-introduce
    a DNS rebinding TOCTOU window where an attacker-controlled DNS server
    could return a public IP during validation and an internal IP at
    connection time.
    """
    target = target.strip().rstrip('/')
    if target.startswith(('http://', 'https://')):
        target = target.split('://')[1].split('/')[0]
    if ':' in target and not target.startswith('['):
        target = target.split(':')[0]

    # Block obvious internal targets
    if target in ('localhost', '127.0.0.1', '0.0.0.0', '::1'):
        raise ValueError(f'Scanning internal targets is not allowed: {target}')

    # Resolve and check IP
    try:
        resolved_ip = socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f'Could not resolve hostname: {target}')

    if _is_internal_ip(resolved_ip):
        raise ValueError(f'Scanning internal/private IPs is not allowed: {target} ({resolved_ip})')

    return target, resolved_ip


def _pinned_http_get(hostname: str, ip: str, path: str, use_https: bool, timeout: int = 8):
    """HTTP GET that connects directly to a pre-validated IP.

    This prevents DNS rebinding: the IP was validated by `_validate_target`
    and is passed in here, so no additional name resolution happens between
    the safety check and the actual connection.

    The original `hostname` is sent in the Host header so virtual-hosted
    sites still route correctly.

    Returns (status, headers dict, body bytes). Body is capped at 50 KB.
    """
    port = 443 if use_https else 80
    if use_https:
        ctx = ssl._create_unverified_context()
        conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        conn.request('GET', path or '/', headers={
            'Host': hostname,
            'User-Agent': 'Mozilla/5.0 (compatible; Vulnex/1.0)',
            'Accept': '*/*',
            'Connection': 'close',
        })
        resp = conn.getresponse()
        headers = {k: v for k, v in resp.getheaders()}
        body = resp.read(50000)
        return resp.status, headers, body
    finally:
        conn.close()


def _sanitize_banner(raw: str) -> str:
    """Remove null bytes and control chars that break PostgreSQL jsonb."""
    return raw.replace('\x00', '').replace('\u0000', '')[:200]


def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab service banner from an open port."""
    try:
        if port in (443, 993, 995, 8443):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw) as s:
                    s.settimeout(timeout)
                    try:
                        # Send HTTP request for web ports
                        if port in (443, 8443):
                            s.sendall(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                        banner = s.recv(512).decode('utf-8', errors='replace').strip()
                        return _sanitize_banner(banner)
                    except (socket.timeout, OSError):
                        return ''
        else:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                if port in (80, 8080, 8888):
                    s.sendall(b'HEAD / HTTP/1.0\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                try:
                    banner = s.recv(512).decode('utf-8', errors='replace').strip()
                    return _sanitize_banner(banner)
                except (socket.timeout, OSError):
                    return ''
    except Exception:
        return ''


def _check_port(ip: str, port: int, timeout: float = 1.5) -> dict | None:
    """Check if a single port is open."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            service = COMMON_PORTS.get(port, 'unknown')
            result = {
                'port': port,
                'protocol': 'tcp',
                'state': 'open',
                'service': service,
            }
            # Try banner grab for interesting ports
            banner = _grab_banner(ip, port, timeout=2.0)
            if banner:
                # Extract server info from HTTP response
                for line in banner.split('\n'):
                    line = line.strip()
                    if line.lower().startswith('server:'):
                        result['product'] = line.split(':', 1)[1].strip()
                        break
                    elif not line.startswith('HTTP') and line and 'port' not in result.get('product', ''):
                        if len(line) < 100:
                            result['product'] = line
                            break
            return result
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def scan_ports(target: str) -> list[dict]:
    """TCP connect scan on common ports using thread pool."""
    # Validate and resolve in one step. We use the returned IP directly for
    # the scan — never re-resolve, or DNS rebinding could redirect the scan
    # to an internal target.
    clean_target, ip = _validate_target(target)

    hostname = clean_target if clean_target != ip else ''
    open_ports = []

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(_check_port, ip, port): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x['port'])

    return [{
        'host': clean_target,
        'hostname': hostname,
        'ip': ip,
        'ports': open_ports,
    }]


def scan_subdomains(target: str) -> list[dict]:
    """Enumerate subdomains by DNS resolution."""
    # Clean the target to base domain
    target = target.strip().rstrip('/')
    if target.startswith(('http://', 'https://')):
        target = target.split('://')[1].split('/')[0]
    if ':' in target:
        target = target.split(':')[0]
    # Remove any leading subdomain to get base domain
    parts = target.split('.')
    if len(parts) > 2:
        target = '.'.join(parts[-2:])

    # SSRF guard: refuse to enumerate when the base domain resolves to
    # an internal/private IP. Raises ValueError for internal targets.
    _validate_target(target)

    found = []

    def _try_resolve(sub):
        fqdn = f'{sub}.{target}'
        try:
            ip = socket.gethostbyname(fqdn)
        except socket.gaierror:
            return None
        # Drop subdomains that resolve to internal IPs (split-horizon DNS).
        if _is_internal_ip(ip):
            return None
        return {'hostname': fqdn, 'ip': ip}

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(_try_resolve, sub): sub
            for sub in SUBDOMAIN_WORDLIST
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    # Also check the base domain itself
    try:
        base_ip = socket.gethostbyname(target)
        if not _is_internal_ip(base_ip):
            found.insert(0, {'hostname': target, 'ip': base_ip})
    except socket.gaierror:
        pass

    found.sort(key=lambda x: x['hostname'])
    return found


def detect_technologies(target: str) -> list[dict]:
    """Detect web technologies via HTTP headers and response content."""
    target = target.strip().rstrip('/')
    if not target.startswith(('http://', 'https://')):
        target = f'http://{target}'

    hostname = target.split('://')[1].split('/')[0]
    # SSRF + DNS-rebinding protection: validate and pin to the resolved IP
    host_only, validated_ip = _validate_target(hostname)
    technologies = []
    security_notes = []

    for use_https in (False, True):
        try:
            status, headers, body_bytes = _pinned_http_get(
                host_only, validated_ip, '/', use_https=use_https, timeout=8,
            )
            body = body_bytes.decode('utf-8', errors='replace')

            # Server header
            server = headers.get('Server', '')
            if server:
                technologies.append(server)

            # X-Powered-By
            powered = headers.get('X-Powered-By', '')
            if powered:
                technologies.append(powered)

            # X-AspNet-Version
            aspnet = headers.get('X-AspNet-Version', '')
            if aspnet:
                technologies.append(f'ASP.NET {aspnet}')

            # X-Generator
            generator = headers.get('X-Generator', '')
            if generator:
                technologies.append(generator)

            # Cookie-based detection
            set_cookie = headers.get('Set-Cookie', '')
            if 'PHPSESSID' in set_cookie:
                technologies.append('PHP')
            if 'JSESSIONID' in set_cookie:
                technologies.append('Java')
            if 'ASP.NET' in set_cookie:
                technologies.append('ASP.NET')
            if 'laravel_session' in set_cookie:
                technologies.append('Laravel')
            if 'csrftoken' in set_cookie.lower() and 'django' not in [t.lower() for t in technologies]:
                technologies.append('Django (likely)')
            if 'express.sid' in set_cookie or 'connect.sid' in set_cookie:
                technologies.append('Node.js/Express')

            # Body-based detection
            body_lower = body.lower()
            if 'wp-content' in body_lower or 'wp-includes' in body_lower:
                technologies.append('WordPress')
            if 'joomla' in body_lower:
                technologies.append('Joomla')
            if 'drupal' in body_lower:
                technologies.append('Drupal')
            if 'shopify' in body_lower:
                technologies.append('Shopify')

            # Meta generator tag
            import re
            gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\'](.*?)["\']', body, re.I)
            if gen_match:
                gen_val = gen_match.group(1)
                if gen_val not in technologies:
                    technologies.append(gen_val)

            # JavaScript frameworks
            if 'react' in body_lower and ('reactdom' in body_lower or 'react-dom' in body_lower or '_react' in body_lower):
                technologies.append('React')
            if 'vue' in body_lower and ('vue.js' in body_lower or 'vue.min' in body_lower or '__vue__' in body_lower):
                technologies.append('Vue.js')
            if 'angular' in body_lower and ('ng-version' in body_lower or 'angular.js' in body_lower):
                technologies.append('Angular')
            if 'jquery' in body_lower:
                # Try to get version
                jq_match = re.search(r'jquery[/-](\d+\.\d+[\.\d]*)', body_lower)
                technologies.append(f'jQuery {jq_match.group(1)}' if jq_match else 'jQuery')
            if 'bootstrap' in body_lower:
                technologies.append('Bootstrap')

            # Security headers check
            if not headers.get('X-Frame-Options'):
                security_notes.append('Missing X-Frame-Options')
            if not headers.get('X-Content-Type-Options'):
                security_notes.append('Missing X-Content-Type-Options')
            if use_https and not headers.get('Strict-Transport-Security'):
                security_notes.append('Missing HSTS')
            if not headers.get('Content-Security-Policy'):
                security_notes.append('Missing CSP')

            break  # Got a response, no need to try the other protocol

        except Exception:
            continue

    # Deduplicate
    seen = set()
    unique_techs = []
    for t in technologies:
        if t.lower() not in seen:
            seen.add(t.lower())
            unique_techs.append(t)

    result = {'hostname': hostname, 'technologies': unique_techs}
    if security_notes:
        result['security_notes'] = security_notes
    return [result] if unique_techs or security_notes else [{'hostname': hostname, 'technologies': [], 'note': 'No technologies detected'}]


def enum_dns(target: str) -> list[dict]:
    """DNS enumeration — resolve various record types."""
    target = target.strip().rstrip('/')
    if target.startswith(('http://', 'https://')):
        target = target.split('://')[1].split('/')[0]
    if ':' in target:
        target = target.split(':')[0]

    results = []

    # A record
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET)
        a_records = list(set(ip[4][0] for ip in ips))
        for ip in a_records:
            results.append({'type': 'A', 'hostname': target, 'value': ip})
    except socket.gaierror:
        pass

    # AAAA record
    try:
        ips = socket.getaddrinfo(target, None, socket.AF_INET6)
        aaaa_records = list(set(ip[4][0] for ip in ips))
        for ip in aaaa_records:
            results.append({'type': 'AAAA', 'hostname': target, 'value': ip})
    except socket.gaierror:
        pass

    # Reverse DNS for A records
    for r in [r for r in results if r['type'] == 'A']:
        try:
            reverse = socket.gethostbyaddr(r['value'])
            results.append({'type': 'PTR', 'hostname': r['value'], 'value': reverse[0]})
        except (socket.herror, socket.gaierror, OSError):
            pass

    # MX records via common mail subdomains
    mail_prefixes = ['mail', 'mx', 'mx1', 'mx2', 'smtp']
    for prefix in mail_prefixes:
        try:
            fqdn = f'{prefix}.{target}'
            ip = socket.gethostbyname(fqdn)
            results.append({'type': 'MX (inferred)', 'hostname': fqdn, 'value': ip})
        except socket.gaierror:
            pass

    # NS records via common ns subdomains
    ns_prefixes = ['ns1', 'ns2', 'ns3', 'dns1', 'dns2']
    for prefix in ns_prefixes:
        try:
            fqdn = f'{prefix}.{target}'
            ip = socket.gethostbyname(fqdn)
            results.append({'type': 'NS (inferred)', 'hostname': fqdn, 'value': ip})
        except socket.gaierror:
            pass

    if not results:
        results.append({'type': 'INFO', 'hostname': target, 'value': 'No DNS records resolved'})

    return results


def lookup_whois(target: str) -> list[dict]:
    """WHOIS lookup using raw socket connection to whois servers."""
    target = target.strip().rstrip('/')
    if target.startswith(('http://', 'https://')):
        target = target.split('://')[1].split('/')[0]
    if ':' in target:
        target = target.split(':')[0]

    # Get base domain
    parts = target.split('.')
    if len(parts) > 2:
        target = '.'.join(parts[-2:])

    whois_servers = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'info': 'whois.afilias.net',
        'me': 'whois.nic.me',
        'dev': 'whois.nic.google',
    }

    tld = target.split('.')[-1].lower()
    whois_server = whois_servers.get(tld, f'whois.nic.{tld}')

    raw_output = ''
    try:
        with socket.create_connection((whois_server, 43), timeout=10) as s:
            s.sendall((target + '\r\n').encode())
            response = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            raw_output = response.decode('utf-8', errors='replace')
    except Exception as e:
        return [{'hostname': target, 'note': f'WHOIS lookup failed: {str(e)}'}]

    # Parse key fields
    info = {'hostname': target}
    fields = {}
    for line in raw_output.splitlines():
        line = line.strip()
        if ':' in line and not line.startswith('%') and not line.startswith('#'):
            key, _, value = line.partition(':')
            key = key.strip().lower()
            value = value.strip()
            if value and key not in fields:
                fields[key] = value

    # Extract common fields
    for key_name, display_name in [
        ('registrar', 'registrar'),
        ('registrant organization', 'organization'),
        ('registrant country', 'country'),
        ('creation date', 'created'),
        ('registry expiry date', 'expires'),
        ('updated date', 'updated'),
        ('name server', 'nameserver'),
        ('registrant name', 'registrant'),
        ('domain name', 'domain'),
        ('dnssec', 'dnssec'),
    ]:
        if key_name in fields:
            info[display_name] = fields[key_name]

    # Also get all name servers
    nameservers = []
    for line in raw_output.splitlines():
        line = line.strip()
        if line.lower().startswith('name server:'):
            ns = line.split(':', 1)[1].strip()
            if ns and ns not in nameservers:
                nameservers.append(ns)
    if nameservers:
        info['nameservers'] = nameservers

    info['raw_length'] = len(raw_output)

    return [info]


def bruteforce_dirs(target: str) -> list[dict]:
    """Directory/file bruteforce via HTTP requests."""
    target = target.strip().rstrip('/')
    if not target.startswith(('http://', 'https://')):
        target = f'http://{target}'

    hostname = target.split('://')[1].split('/')[0]
    use_https = target.startswith('https://')
    # SSRF + DNS-rebinding protection: validate and pin to the resolved IP
    host_only, validated_ip = _validate_target(hostname)
    found = []

    def _check_path(path):
        try:
            status, headers, body = _pinned_http_get(
                host_only, validated_ip, path, use_https=use_https, timeout=6,
            )
            if status in (200, 301, 302, 403):
                return {
                    'path': path,
                    'status': status,
                    'size': len(body),
                    'redirect': headers.get('Location') if status in (301, 302) else None,
                }
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(_check_path, path): path
            for path in COMMON_DIRS
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda x: x['path'])
    return [{'hostname': hostname, 'url': target, 'directories': found}]


# ── Main dispatcher ──
SCANNERS = {
    'port_scan': scan_ports,
    'subdomain': scan_subdomains,
    'tech_detect': detect_technologies,
    'dns_enum': enum_dns,
    'whois': lookup_whois,
    'dir_brute': bruteforce_dirs,
}


def run_scan(scan_type: str, target: str) -> list[dict]:
    """Run the appropriate scanner and return results."""
    scanner = SCANNERS.get(scan_type)
    if not scanner:
        return [{'error': f'Unknown scan type: {scan_type}'}]
    return scanner(target)
