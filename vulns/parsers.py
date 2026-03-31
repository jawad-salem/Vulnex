"""
Parsers for common pentest tool outputs.
Each parser takes raw file content (bytes) and returns a list of dicts
suitable for creating Finding objects.
"""
import json
import xml.etree.ElementTree as ET


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

    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
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

        findings.append({
            'title': info.get('name', item.get('template-id', 'Unknown')),
            'description': info.get('description', '') or f"Matched: {item.get('matched-at', '')}",
            'affected_hosts': item.get('host', item.get('matched-at', '')),
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
        })

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
                'affected_hosts': host_label,
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

