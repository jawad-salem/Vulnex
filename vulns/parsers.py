"""
Parsers for common pentest tool outputs.
Each parser takes raw file content (bytes) and returns a list of dicts
suitable for creating Finding objects.
"""
import json
# Use defusedxml to protect against XXE, billion laughs, and quadratic blowup attacks
import defusedxml.ElementTree as ET


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

