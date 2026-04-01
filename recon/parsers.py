"""
Parsers for recon tool outputs.
Each parser returns a list of dicts suitable for creating DiscoveredHost records.
"""
import xml.etree.ElementTree as ET


def parse_nmap_xml_to_hosts(content: bytes) -> list[dict]:
    """Parse Nmap XML output into discovered host records with ports."""
    hosts = []
    root = ET.fromstring(content)

    for host_el in root.findall('.//host'):
        # Skip hosts that are down
        status_el = host_el.find('status')
        if status_el is not None and status_el.get('state') != 'up':
            continue

        addr_el = host_el.find('address')
        if addr_el is None:
            continue
        ip = addr_el.get('addr', '')

        hostname = ''
        hostname_el = host_el.find('hostnames/hostname')
        if hostname_el is not None:
            hostname = hostname_el.get('name', '')

        # Parse open ports
        ports = []
        for port_el in host_el.findall('.//port'):
            state_el = port_el.find('state')
            if state_el is None or state_el.get('state') != 'open':
                continue

            service_el = port_el.find('service')
            port_info = {
                'port': int(port_el.get('portid', 0)),
                'protocol': port_el.get('protocol', 'tcp'),
                'state': 'open',
                'service': service_el.get('name', 'unknown') if service_el is not None else 'unknown',
            }
            if service_el is not None:
                product = service_el.get('product', '')
                version = service_el.get('version', '')
                if product:
                    port_info['product'] = f"{product} {version}".strip()
            ports.append(port_info)

        hosts.append({
            'hostname': hostname or ip,
            'ip': ip,
            'ports': ports,
        })

    return hosts
