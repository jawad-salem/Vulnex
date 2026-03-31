from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from .models import ReconScan, DiscoveredHost
from .forms import ReconScanForm
from accounts.decorators import role_required


@login_required
def recon_dashboard(request, engagement_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
    scans = engagement.scans.all()
    hosts = engagement.discovered_hosts.all()
    scan_form = ReconScanForm()

    context = {
        'engagement': engagement,
        'scans': scans,
        'hosts': hosts,
        'scan_form': scan_form,
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

            # In production, this would dispatch to Celery:
            # from .tasks import run_scan
            # run_scan.delay(str(scan.pk))

            # For demo, simulate completion
            scan.status = 'completed'
            scan.started_at = timezone.now()
            scan.completed_at = timezone.now()
            scan.parsed_results = _simulate_scan_results(scan)
            scan.save()

            # Create discovered hosts from results
            for result in scan.parsed_results:
                DiscoveredHost.objects.update_or_create(
                    engagement=engagement,
                    hostname=result.get('hostname', result.get('host', '')),
                    defaults={
                        'scan': scan,
                        'ip_address': result.get('ip'),
                        'ports': result.get('ports', []),
                        'technologies': result.get('technologies', []),
                    }
                )

            messages.success(request, f'Scan completed: {scan.result_count} results found.')
            return redirect('recon:dashboard', engagement_pk=engagement_pk)
    return redirect('recon:dashboard', engagement_pk=engagement_pk)


@login_required
def scan_detail(request, pk):
    scan = get_object_or_404(ReconScan.objects.select_related('engagement'), pk=pk)
    return render(request, 'recon/scan_detail.html', {'scan': scan})


def _simulate_scan_results(scan):
    """Generate demo results for the scan. Replace with real tool integration."""
    target = scan.target
    if scan.scan_type == 'port_scan':
        return [
            {'host': target, 'ip': '93.184.216.34', 'hostname': target,
             'ports': [
                 {'port': 22, 'protocol': 'tcp', 'service': 'ssh', 'state': 'open'},
                 {'port': 80, 'protocol': 'tcp', 'service': 'http', 'state': 'open'},
                 {'port': 443, 'protocol': 'tcp', 'service': 'https', 'state': 'open'},
             ]},
        ]
    elif scan.scan_type == 'subdomain':
        return [
            {'hostname': f'www.{target}', 'ip': '93.184.216.34'},
            {'hostname': f'api.{target}', 'ip': '93.184.216.35'},
            {'hostname': f'mail.{target}', 'ip': '93.184.216.36'},
            {'hostname': f'dev.{target}', 'ip': '93.184.216.37'},
        ]
    elif scan.scan_type == 'tech_detect':
        return [
            {'hostname': target, 'technologies': ['nginx/1.21', 'PHP/8.1', 'WordPress 6.4', 'jQuery 3.6']},
        ]
    return [{'hostname': target, 'note': 'Scan completed — no notable results'}]

