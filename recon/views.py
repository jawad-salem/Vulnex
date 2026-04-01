from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from .models import ReconScan, DiscoveredHost
from .forms import ReconScanForm, NmapImportForm
from .parsers import parse_nmap_xml_to_hosts
from .scanners import run_scan
from accounts.decorators import role_required


@login_required
def recon_dashboard(request, engagement_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
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


@login_required
@role_required('admin', 'pentester')
def start_scan(request, engagement_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
    if request.method == 'POST':
        form = ReconScanForm(request.POST)
        if form.is_valid():
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

                # Create discovered hosts from results
                for result in results:
                    hostname = result.get('hostname', result.get('host', ''))
                    if not hostname:
                        continue
                    DiscoveredHost.objects.update_or_create(
                        engagement=engagement,
                        hostname=hostname,
                        defaults={
                            'scan': scan,
                            'ip_address': result.get('ip') or None,
                            'ports': result.get('ports', []),
                            'technologies': result.get('technologies', []),
                        }
                    )

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
    return render(request, 'recon/scan_detail.html', {'scan': scan})


@login_required
@role_required('admin', 'pentester')
def scan_delete(request, pk):
    scan = get_object_or_404(ReconScan.objects.select_related('engagement'), pk=pk)
    engagement = scan.engagement
    if request.method == 'POST':
        scan_type = scan.get_scan_type_display()
        target = scan.target
        scan.delete()
        ActivityLog.objects.create(
            engagement=engagement,
            user=request.user,
            action=f'Deleted {scan_type} scan on {target}'
        )
        messages.success(request, f'Scan deleted.')
        return redirect('recon:dashboard', engagement_pk=engagement.pk)
    return render(request, 'recon/confirm_delete.html', {'scan': scan, 'engagement': engagement})


@login_required
@role_required('admin', 'pentester')
def import_nmap(request, engagement_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
    if request.method == 'POST':
        form = NmapImportForm(request.POST, request.FILES)
        if form.is_valid():
            content = request.FILES['file'].read()
            try:
                hosts_data = parse_nmap_xml_to_hosts(content)
                count = 0
                for hd in hosts_data:
                    DiscoveredHost.objects.update_or_create(
                        engagement=engagement,
                        hostname=hd['hostname'],
                        defaults={
                            'ip_address': hd.get('ip') or None,
                            'ports': hd.get('ports', []),
                        }
                    )
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



