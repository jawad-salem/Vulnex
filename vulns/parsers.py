"""
Parsers for common pentest tool outputs.
Each parser takes raw file content (bytes) and returns a list of dicts
suitable for creating Finding objects.
"""
import json
import re
# Use defusedxml to protect against XXE, billion laughs, and quadratic blowup attacks
import defusedxml.ElementTree as ET
from urllib.parse import urlparse


# Shared severity ladder — every parser normalises its native label down to
# one of these five values before returning a finding dict.
VALID_SEVERITIES = {'critical', 'high', 'medium', 'low', 'info'}


def _normalize_severity(raw, fallback='info'):
    """Coerce an arbitrary tool severity label to our 5-tier ladder."""
    if raw is None:
        return fallback
    s = str(raw).strip().lower()
    if not s:
        return fallback
    if s in VALID_SEVERITIES:
        return s
    # Common aliases from Burp / Nessus / ZAP / Semgrep.
    mapping = {
        'informational': 'info',
        'information': 'info',
        'none': 'info',
        'note': 'info',
        'warning': 'medium',
        'error': 'high',
        'severe': 'high',
        'moderate': 'medium',
    }
    return mapping.get(s, fallback)


_CVSS_IMPACTS = {
    'critical': {'c': 'H', 'i': 'H', 'a': 'H'},
    'high': {'c': 'H', 'i': 'L', 'a': 'N'},
    'medium': {'c': 'L', 'i': 'L', 'a': 'N'},
    'low': {'c': 'L', 'i': 'N', 'a': 'N'},
    'info': {'c': 'N', 'i': 'N', 'a': 'N'},
}


def _cvss_defaults(sev):
    """Sensible CVSS v3.1 defaults when the tool itself doesn't emit vectors."""
    imp = _CVSS_IMPACTS.get(sev, _CVSS_IMPACTS['info'])
    return {
        'attack_vector': 'N',
        'attack_complexity': 'L',
        'privileges_required': 'N',
        'user_interaction': 'N',
        'confidentiality_impact': imp['c'],
        'integrity_impact': imp['i'],
        'availability_impact': imp['a'],
    }


_CWE_RE = re.compile(r'CWE[-\s]?(\d+)', re.IGNORECASE)


def _first_cwe(*sources):
    """Scan input strings/lists and return the first ``CWE-NNN`` found, or ''."""
    for src in sources:
        if not src:
            continue
        values = src if isinstance(src, list) else [src]
        for v in values:
            m = _CWE_RE.search(str(v))
            if m:
                return f'CWE-{m.group(1)}'
    return ''


def parse_nmap_xml(content: bytes) -> list[dict]:
    """Parse Nmap XML output into findings."""
    findings = []
    root = ET.fromstring(content)

    for host in root.findall('.//host'):
        addr_el = host.find('address')
        if addr_el is None:
            continue
        addr = addr_el.get('addr', 'unknown')
        hostname = ''
        hostnames_el = host.find('hostnames/hostname')
        if hostnames_el is not None:
            hostname = hostnames_el.get('name', '')

        host_label = hostname or addr

        for port in host.findall('.//port'):
            portid = port.get('portid', '')
            protocol = port.get('protocol', 'tcp')
            state_el = port.find('state')
            state = state_el.get('state', '') if state_el is not None else ''

            if state != 'open':
                continue

            service_el = port.find('service')
            service_name = service_el.get('name', 'unknown') if service_el is not None else 'unknown'
            product = service_el.get('product', '') if service_el is not None else ''
            version = service_el.get('version', '') if service_el is not None else ''

            svc_detail = f"{product} {version}".strip() or service_name

            findings.append({
                'title': f'Open port {portid}/{protocol} ({service_name}) on {host_label}',
                'description': (
                    f'Port {portid}/{protocol} is open on {host_label} ({addr}).\n'
                    f'Service: {svc_detail}'
                ),
                'affected_hosts': addr,
                'severity': 'info',
                'attack_vector': 'N',
                'attack_complexity': 'L',
                'privileges_required': 'N',
                'user_interaction': 'N',
                'confidentiality_impact': 'N',
                'integrity_impact': 'N',
                'availability_impact': 'N',
            })

        # Script results (e.g., vulners, vuln)
        for script in host.findall('.//script'):
            script_id = script.get('id', '')
            output = script.get('output', '')
            if 'vuln' in script_id.lower() and output:
                findings.append({
                    'title': f'Nmap script finding: {script_id} on {host_label}',
                    'description': output[:2000],
                    'affected_hosts': addr,
                    'severity': 'medium',
                    'attack_vector': 'N',
                    'attack_complexity': 'L',
                    'privileges_required': 'N',
                    'user_interaction': 'N',
                    'confidentiality_impact': 'L',
                    'integrity_impact': 'N',
                    'availability_impact': 'N',
                })

    return findings


def parse_nuclei_json(content: bytes) -> list[dict]:
    """Parse Nuclei JSONL output into findings."""
    findings = []
    text = content.decode('utf-8', errors='replace')

    severity_map = {
        'critical': {'c': 'H', 'i': 'H', 'a': 'H'},
        'high': {'c': 'H', 'i': 'L', 'a': 'N'},
        'medium': {'c': 'L', 'i': 'L', 'a': 'N'},
        'low': {'c': 'L', 'i': 'N', 'a': 'N'},
        'info': {'c': 'N', 'i': 'N', 'a': 'N'},
    }

    # Support both JSON array and JSONL (one object per line)
    items = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            items = parsed
        elif isinstance(parsed, dict):
            items = [parsed]
    except json.JSONDecodeError:
        # Fall back to JSONL (one JSON object per line)
        for line in text.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    for item in items:
        if not isinstance(item, dict):
            continue

        info = item.get('info', {})
        sev = info.get('severity', 'info').lower()
        if sev not in severity_map:
            sev = 'info'

        impacts = severity_map[sev]
        refs = info.get('reference', [])
        if isinstance(refs, list):
            refs = '\n'.join(refs)

        cwe_ids = info.get('classification', {}).get('cwe-id', [])
        cwe = cwe_ids[0] if cwe_ids else ''

        # Extract host/url from matched-at
        matched_at = item.get('matched-at', '')
        host_val = item.get('host', '')
        url_val = ''
        endpoint_val = ''
        port_val = None

        if matched_at.startswith(('http://', 'https://')):
            url_val = matched_at
            try:
                from urllib.parse import urlparse
                parsed = urlparse(matched_at)
                host_val = host_val or parsed.hostname or ''
                endpoint_val = parsed.path or ''
                if parsed.port:
                    port_val = parsed.port
                elif parsed.scheme == 'https':
                    port_val = 443
                elif parsed.scheme == 'http':
                    port_val = 80
            except Exception:
                pass
        elif not host_val:
            host_val = matched_at

        finding_data = {
            'title': info.get('name', item.get('template-id', 'Unknown')),
            'description': info.get('description', '') or f"Matched: {matched_at}",
            'host': host_val,
            'url': url_val,
            'endpoint': endpoint_val,
            'references': refs,
            'cwe_id': str(cwe),
            'severity': sev,
            'attack_vector': 'N',
            'attack_complexity': 'L',
            'privileges_required': 'N',
            'user_interaction': 'N',
            'confidentiality_impact': impacts['c'],
            'integrity_impact': impacts['i'],
            'availability_impact': impacts['a'],
        }
        if port_val:
            finding_data['port'] = port_val

        findings.append(finding_data)

    return findings


def parse_nikto_json(content: bytes) -> list[dict]:
    """Parse Nikto JSON output into findings."""
    findings = []
    text = content.decode('utf-8', errors='replace')

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return findings

    # Nikto JSON can be a list or object
    if isinstance(data, dict):
        data = [data]

    for host_result in data:
        ip = host_result.get('ip', 'unknown')
        port = host_result.get('port', '')
        host_label = f"{ip}:{port}" if port else ip

        vulnerabilities = host_result.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            osvdb = vuln.get('OSVDB', '')
            msg = vuln.get('msg', vuln.get('message', 'No description'))
            method = vuln.get('method', 'GET')
            url = vuln.get('url', '/')

            refs = f"OSVDB-{osvdb}" if osvdb and osvdb != '0' else ''

            findings.append({
                'title': f'Nikto: {msg[:120]}',
                'description': f'{method} {url}\n\n{msg}',
                'host': ip,
                'port': int(port) if port else None,
                'endpoint': url,
                'http_method': method if method in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD') else '',
                'references': refs,
                'severity': 'low',
                'attack_vector': 'N',
                'attack_complexity': 'L',
                'privileges_required': 'N',
                'user_interaction': 'N',
                'confidentiality_impact': 'L',
                'integrity_impact': 'N',
                'availability_impact': 'N',
            })

    return findings


# ─── Burp Suite XML ──────────────────────────────────────────────────────────

_BURP_SEVERITY_MAP = {
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'information': 'info',
    'info': 'info',
    'false positive': 'info',
}


def _text(node, tag, default=''):
    el = node.find(tag)
    if el is None or el.text is None:
        return default
    return el.text.strip()


def parse_burp_xml(content: bytes) -> list[dict]:
    """Parse a Burp Suite issues export (``<issues><issue>…``) into findings."""
    findings = []
    root = ET.fromstring(content)
    for issue in root.findall('.//issue'):
        name = _text(issue, 'name') or 'Burp issue'
        raw_sev = _text(issue, 'severity', 'Information')
        sev = _BURP_SEVERITY_MAP.get(raw_sev.strip().lower(), 'info')

        host_url = _text(issue, 'host')
        host_ip = ''
        host_node = issue.find('host')
        if host_node is not None:
            host_ip = host_node.get('ip', '')

        host = host_ip or ''
        port = None
        endpoint = _text(issue, 'path') or _text(issue, 'location')
        url_val = host_url.strip()
        if host_url:
            try:
                parsed = urlparse(host_url)
                if not host:
                    host = parsed.hostname or ''
                if parsed.port:
                    port = parsed.port
                elif parsed.scheme == 'https':
                    port = 443
                elif parsed.scheme == 'http':
                    port = 80
                if endpoint:
                    url_val = f'{parsed.scheme}://{parsed.netloc}{endpoint}'
            except ValueError:
                pass

        parameter = ''
        location = _text(issue, 'location')
        if location:
            m = re.search(r'\[([^\]]+) parameter\]', location)
            if m:
                parameter = m.group(1)

        detail = _text(issue, 'issueDetail') or _text(issue, 'issueBackground')
        remediation = _text(issue, 'remediationDetail') or _text(issue, 'remediationBackground')
        cwe = _first_cwe(_text(issue, 'vulnerabilityClassifications'))

        data = {
            'title': name,
            'description': detail or name,
            'remediation': remediation,
            'host': host,
            'url': url_val,
            'endpoint': endpoint,
            'parameter': parameter,
            'confidence': _text(issue, 'confidence'),
            'severity': sev,
            'cwe_id': cwe,
            **_cvss_defaults(sev),
        }
        if port:
            data['port'] = port
        findings.append(data)
    return findings


# ─── Nessus .nessus XML ──────────────────────────────────────────────────────

_NESSUS_RISK_MAP = {
    'critical': 'critical',
    'high': 'high',
    'medium': 'medium',
    'low': 'low',
    'none': 'info',
    'info': 'info',
    'informational': 'info',
}

_NESSUS_INT_MAP = {'0': 'info', '1': 'low', '2': 'medium', '3': 'high', '4': 'critical'}


def parse_nessus_xml(content: bytes) -> list[dict]:
    """Parse a Nessus ``.nessus`` v2 scan export, one finding per ReportItem."""
    findings = []
    root = ET.fromstring(content)
    for host in root.findall('.//ReportHost'):
        host_name = host.get('name', '') or ''
        host_ip = host_name
        host_fqdn = ''
        for tag in host.findall('.//HostProperties/tag'):
            tag_name = tag.get('name', '')
            if tag_name == 'host-ip' and tag.text:
                host_ip = tag.text.strip()
            elif tag_name == 'host-fqdn' and tag.text:
                host_fqdn = tag.text.strip()

        for item in host.findall('ReportItem'):
            plugin_name = item.get('pluginName', '') or 'Nessus finding'
            port_attr = item.get('port', '0')
            try:
                port = int(port_attr) or None
            except ValueError:
                port = None
            service = item.get('svc_name', '') or ''

            raw_int = item.get('severity', '0')
            raw_factor = _text(item, 'risk_factor') or _NESSUS_INT_MAP.get(raw_int, 'info')
            sev = _NESSUS_RISK_MAP.get(raw_factor.strip().lower(), 'info')

            synopsis = _text(item, 'synopsis')
            description = _text(item, 'description') or synopsis or plugin_name
            solution = _text(item, 'solution')
            plugin_output = _text(item, 'plugin_output')
            if plugin_output:
                description = f'{description}\n\nPlugin output:\n{plugin_output[:2000]}'

            refs = []
            for t in ('see_also', 'cve', 'bid', 'xref'):
                for el in item.findall(t):
                    if el.text:
                        refs.append(el.text.strip())

            cvss_score = None
            for tag in ('cvss3_base_score', 'cvss_base_score'):
                val = _text(item, tag)
                if val:
                    try:
                        cvss_score = float(val)
                        break
                    except ValueError:
                        pass

            # Nessus emits the CWE as a bare number (e.g. <cwe>327</cwe>), so
            # pre-pend "CWE-" before passing through the generic matcher.
            cwe_texts = [
                f'CWE-{el.text.strip()}' for el in item.findall('cwe')
                if el.text and el.text.strip().isdigit()
            ]
            cwe = _first_cwe(*cwe_texts) if cwe_texts else ''

            data = {
                'title': plugin_name,
                'description': description,
                'remediation': solution,
                'host': host_fqdn or host_ip,
                'service': service,
                'references': '\n'.join(refs),
                'severity': sev,
                'cwe_id': cwe,
                **_cvss_defaults(sev),
            }
            if port:
                data['port'] = port
            if cvss_score is not None:
                data['cvss_score'] = cvss_score
            findings.append(data)
    return findings


# ─── OWASP ZAP JSON ──────────────────────────────────────────────────────────

_ZAP_RISK_MAP = {
    '0': 'info', '1': 'low', '2': 'medium', '3': 'high',
    'informational': 'info', 'low': 'low', 'medium': 'medium', 'high': 'high',
}


def parse_zap_json(content: bytes) -> list[dict]:
    """Parse an OWASP ZAP JSON report (``owasp_zap_scanner`` output shape)."""
    findings = []
    try:
        data = json.loads(content.decode('utf-8', errors='replace'))
    except json.JSONDecodeError:
        return findings

    sites = data.get('site', [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        site_host = site.get('@host', '') or site.get('host', '')
        site_port_raw = site.get('@port', '') or site.get('port', '')
        try:
            site_port = int(site_port_raw) if site_port_raw else None
        except (TypeError, ValueError):
            site_port = None

        for alert in site.get('alerts', []) or []:
            name = alert.get('alert') or alert.get('name') or 'ZAP alert'
            risk = alert.get('riskcode') or alert.get('riskdesc', '').split(' ', 1)[0]
            sev = _ZAP_RISK_MAP.get(str(risk).strip().lower(), 'info')
            description = alert.get('desc') or alert.get('description') or name
            solution = alert.get('solution', '')
            references = alert.get('reference', '')
            cwe = alert.get('cweid', '')
            cwe_id = f'CWE-{cwe}' if cwe and str(cwe).strip().isdigit() else ''

            instances = alert.get('instances') or [{}]
            for inst in instances:
                uri = inst.get('uri', '')
                endpoint = ''
                url_val = uri
                host_val = site_host
                port_val = site_port
                if uri:
                    try:
                        parsed = urlparse(uri)
                        endpoint = parsed.path or ''
                        host_val = parsed.hostname or site_host
                        if parsed.port:
                            port_val = parsed.port
                        elif parsed.scheme == 'https':
                            port_val = port_val or 443
                        elif parsed.scheme == 'http':
                            port_val = port_val or 80
                    except ValueError:
                        pass

                data_entry = {
                    'title': name,
                    'description': description,
                    'remediation': solution,
                    'references': references,
                    'host': host_val,
                    'url': url_val,
                    'endpoint': endpoint,
                    'parameter': inst.get('param', ''),
                    'http_method': (inst.get('method') or '').upper()
                    if inst.get('method', '').upper() in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD')
                    else '',
                    'severity': sev,
                    'cwe_id': cwe_id,
                    **_cvss_defaults(sev),
                }
                if port_val:
                    data_entry['port'] = port_val
                findings.append(data_entry)
    return findings


# ─── Semgrep JSON (SAST) ─────────────────────────────────────────────────────

_SEMGREP_SEVERITY_MAP = {
    'error': 'high',
    'warning': 'medium',
    'info': 'info',
    'inventory': 'info',
}


def parse_semgrep_json(content: bytes) -> list[dict]:
    """Parse a Semgrep ``--json`` SAST report into findings."""
    findings = []
    try:
        data = json.loads(content.decode('utf-8', errors='replace'))
    except json.JSONDecodeError:
        return findings

    for result in data.get('results', []) or []:
        if not isinstance(result, dict):
            continue
        check_id = result.get('check_id', 'semgrep')
        extra = result.get('extra', {}) or {}
        raw_sev = extra.get('severity', 'INFO')
        sev = _SEMGREP_SEVERITY_MAP.get(str(raw_sev).strip().lower(), 'info')
        message = extra.get('message', '') or check_id
        path = result.get('path', '')
        start = result.get('start') or {}
        end = result.get('end') or {}
        start_line = start.get('line', '')
        end_line = end.get('line', '')
        location = f'{path}:{start_line}' if path else ''
        if end_line and end_line != start_line:
            location = f'{path}:{start_line}-{end_line}'

        metadata = extra.get('metadata', {}) or {}
        cwe = _first_cwe(metadata.get('cwe'), metadata.get('cwe_id'))
        refs = []
        for ref_key in ('references', 'owasp'):
            val = metadata.get(ref_key)
            if isinstance(val, list):
                refs.extend(str(v) for v in val)
            elif val:
                refs.append(str(val))
        snippet = extra.get('lines', '')

        data_entry = {
            'title': f'{check_id.rsplit(".", 1)[-1]}',
            'description': (
                f'{message}\n\nLocation: {location}\n\n{snippet}'.strip()
                if message else message
            ),
            'endpoint': location,
            'references': '\n'.join(refs),
            'severity': sev,
            'cwe_id': cwe,
            **_cvss_defaults(sev),
        }
        findings.append(data_entry)
    return findings

