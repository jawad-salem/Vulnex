from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from .models import ReconScan, DiscoveredHost
from .forms import ReconScanForm, NmapImportForm
from .parsers import parse_nmap_xml_to_hosts
from .scanners import run_scan
from accounts.decorators import engagement_access, engagement_edit_required


@login_required
@engagement_access(allow_client=False)
def recon_dashboard(request, engagement_pk):
    engagement = request.engagement
    scans = engagement.scans.all()
    hosts = engagement.discovered_hosts.all()
    scan_form = ReconScanForm()
    import_form = NmapImportForm()

    context = {
        'engagement': engagement,
        'scans': scans,
        'hosts': hosts,
        'scan_form': scan_form,
        'import_form': import_form,
    }
    return render(request, 'recon/dashboard.html', context)


def _merge_host(engagement, scan, result):
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


@login_required
@engagement_edit_required
def start_scan(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = ReconScanForm(request.POST)
        if form.is_valid():
            scan_type = form.cleaned_data['scan_type']
            target = form.cleaned_data['target']

            # Prevent duplicate: same type + target already completed
            existing = engagement.scans.filter(
                scan_type=scan_type, target__iexact=target, status='completed'
            ).first()
            if existing:
                messages.warning(
                    request,
                    f'A {existing.get_scan_type_display()} on "{target}" already exists. '
                    f'Delete the old scan first if you want to re-run it.'
                )
                return redirect('recon:dashboard', engagement_pk=engagement_pk)

            scan = form.save(commit=False)
            scan.engagement = engagement
            scan.started_by = request.user
            scan.status = 'pending'
            scan.save()

            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Started {scan.get_scan_type_display()} on {scan.target}'
            )

            scan.status = 'running'
            scan.started_at = timezone.now()
            scan.save()

            try:
                results = run_scan(scan.scan_type, scan.target)
                scan.parsed_results = results
                scan.status = 'completed'
                scan.completed_at = timezone.now()
                scan.save()

                # Merge results into discovered hosts
                for result in results:
                    _merge_host(engagement, scan, result)

                messages.success(request, f'Scan completed: {scan.result_count} results found.')
            except Exception as e:
                scan.status = 'failed'
                scan.error_message = str(e)
                scan.completed_at = timezone.now()
                scan.save()
                messages.error(request, f'Scan failed: {str(e)}')

            return redirect('recon:dashboard', engagement_pk=engagement_pk)
    return redirect('recon:dashboard', engagement_pk=engagement_pk)


@login_required
def scan_detail(request, pk):
    scan = get_object_or_404(ReconScan.objects.select_related('engagement'), pk=pk)
    if not scan.engagement.user_can_access(request.user) or scan.engagement.user_is_client(request.user):
        messages.error(request, 'You do not have access to this section.')
        return redirect('engagements:list')
    return render(request, 'recon/scan_detail.html', {'scan': scan})


@login_required
def scan_delete(request, pk):
    scan = get_object_or_404(ReconScan.objects.select_related('engagement'), pk=pk)
    engagement = scan.engagement
    if not engagement.user_can_edit(request.user):
        messages.error(request, 'You do not have permission to delete scans.')
        return redirect('recon:scan_detail', pk=pk)
    if request.method == 'POST':
        scan_type = scan.get_scan_type_display()  # type: ignore
        target = scan.target
        scan.delete()
        ActivityLog.objects.create(
            engagement=engagement,
            user=request.user,
            action=f'Deleted {scan_type} scan on {target}'
        )
        messages.success(request, 'Scan deleted.')
        return redirect('recon:dashboard', engagement_pk=engagement.pk)
    return render(request, 'recon/confirm_delete.html', {'scan': scan, 'engagement': engagement})


@login_required
@engagement_edit_required
def import_nmap(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = NmapImportForm(request.POST, request.FILES)
        if form.is_valid():
            content = request.FILES['file'].read()
            try:
                hosts_data = parse_nmap_xml_to_hosts(content)
                count = 0
                for hd in hosts_data:
                    _merge_host(engagement, None, hd)
                    count += 1
                ActivityLog.objects.create(
                    engagement=engagement, user=request.user,
                    action=f'Imported {count} hosts from Nmap XML'
                )
                messages.success(request, f'Imported {count} hosts from Nmap scan.')
            except Exception as e:
                messages.error(request, f'Nmap import failed: {str(e)}')
        return redirect('recon:dashboard', engagement_pk=engagement_pk)
    return redirect('recon:dashboard', engagement_pk=engagement_pk)
