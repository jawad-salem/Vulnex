"""Recon result persistence shared by requests and workers."""
from .models import DiscoveredHost


def merge_host(engagement, scan, result):
    """Merge scan result into DiscoveredHost without overwriting other scan data."""
    hostname = result.get('hostname', result.get('host', ''))
    if not hostname:
        return

    host, created = DiscoveredHost.objects.get_or_create(
        engagement=engagement,
        hostname=hostname,
        defaults={
            'scan': scan,
            'ip_address': result.get('ip') or None,
            'ports': result.get('ports', []),
            'technologies': result.get('technologies', []),
        }
    )

    if not created:
        # Merge rather than replace
        changed = False

        # Update IP if we got one and existing is empty
        new_ip = result.get('ip')
        if new_ip and not host.ip_address:
            host.ip_address = new_ip
            changed = True

        # Merge ports (deduplicate by port number)
        new_ports = result.get('ports', [])
        if new_ports:
            existing_port_nums = set()
            for p in host.ports:
                if isinstance(p, dict):
                    existing_port_nums.add(p.get('port'))
                else:
                    existing_port_nums.add(p)
            for p in new_ports:
                port_num = p.get('port') if isinstance(p, dict) else p
                if port_num not in existing_port_nums:
                    host.ports.append(p)
                    existing_port_nums.add(port_num)
                    changed = True

        # Merge technologies (deduplicate)
        new_techs = result.get('technologies', [])
        if new_techs:
            existing_techs = set(host.technologies)
            for t in new_techs:
                if t not in existing_techs:
                    host.technologies.append(t)
                    existing_techs.add(t)
                    changed = True

        if changed:
            host.save()
