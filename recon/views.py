from .services import merge_host as _merge_host
import json

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from engagements.models import ActivityLog
from .models import ReconScan, DiscoveredHost, ScheduledScan, ScanPipeline
from .forms import ReconScanForm, NmapImportForm, DiscoveredHostForm, ScheduledScanForm, ScanPipelineForm
from .parsers import parse_nmap_xml_to_hosts
from .scanners import run_scan
from .scope import validate_scan, ScopeViolation
from accounts.decorators import engagement_access, engagement_edit_required


@login_required
@engagement_access(allow_client=False)
def recon_dashboard(request, engagement_pk):
    engagement = request.engagement
    scans = engagement.scans.all().select_related('pipeline')
    hosts = engagement.discovered_hosts.all()

    # Aggregate stats for the recon header strip.
    open_ports = 0
    services = set()
    for h in hosts:
        for p in (h.ports or []):
            open_ports += 1
            if isinstance(p, dict):
                svc = p.get('service')
                if svc:
                    services.add(svc)
    recon_stats = {
        'hosts': hosts.count(),
        'open_ports': open_ports,
        'services': len(services),
        'scans_run': scans.count(),
        'running': scans.filter(status='running').count(),
    }

    scan_form = ReconScanForm()
    import_form = NmapImportForm()
    scheduled_form = ScheduledScanForm()
    pipeline_form = ScanPipelineForm()
    scheduled_scans = engagement.scheduled_scans.all()
    pipelines = engagement.scan_pipelines.all()[:10]
    pipeline_count = engagement.scan_pipelines.count()

    # Build grouped "recent scans" list — scans born from the same pipeline
    # collapse into a single parent row; standalone scans render as-is.
    # We walk the ordered scan list and group consecutive rows with matching
    # pipeline to preserve the "most recent first" flow.
    recent_scan_groups: list[dict] = []
    for scan in scans[:30]:
        if scan.pipeline_id:
            last = recent_scan_groups[-1] if recent_scan_groups else None
            if last and last.get('pipeline_id') == scan.pipeline_id:
                last['scans'].append(scan)
                continue
            recent_scan_groups.append({
                'kind': 'pipeline',
                'pipeline': scan.pipeline,
                'pipeline_id': scan.pipeline_id,
                'scans': [scan],
            })
        else:
            recent_scan_groups.append({'kind': 'scan', 'scan': scan})
        if len(recent_scan_groups) >= 10:
            break

    context = {
        'engagement': engagement,
        'scans': scans,
        'recent_scan_groups': recent_scan_groups,
        'hosts': hosts,
        'scan_form': scan_form,
        'import_form': import_form,
        'scheduled_form': scheduled_form,
        'pipeline_form': pipeline_form,
        'scheduled_scans': scheduled_scans,
        'pipelines': pipelines,
        'pipeline_count': pipeline_count,
        'pipeline_presets': ScanPipeline.PIPELINE_PRESETS,
        'recon_stats': recon_stats,
    }
    return render(request, 'recon/dashboard.html', context)


@login_required
@engagement_edit_required
def start_scan(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = ReconScanForm(request.POST)
        if form.is_valid():
            scan_type = form.cleaned_data['scan_type']
            target = form.cleaned_data['target']
            try:
                target = validate_scan(engagement.pk, target)
            except ScopeViolation as exc:
                messages.error(request, str(exc))
                return redirect('recon:dashboard', engagement_pk=engagement_pk)

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
                results = run_scan(scan.scan_type, scan.target, engagement_id=engagement.pk)
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


# ── Scheduled scans ──

@login_required
@engagement_edit_required
def create_scheduled_scan(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = ScheduledScanForm(request.POST)
        if form.is_valid():
            try:
                validate_scan(engagement.pk, form.cleaned_data['target'])
            except ScopeViolation as exc:
                messages.error(request, str(exc))
                return redirect('recon:dashboard', engagement_pk=engagement_pk)
            ss = form.save(commit=False)
            ss.engagement = engagement
            ss.created_by = request.user
            ss.save()

            # Create the django-celery-beat PeriodicTask
            _sync_periodic_task(ss)

            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Scheduled {ss.get_scan_type_display()} on {ss.target} ({ss.get_frequency_display()})',
            )
            messages.success(request, f'Scheduled scan created: {ss.get_frequency_display()}.')
            return redirect('recon:dashboard', engagement_pk=engagement_pk)
    return redirect('recon:dashboard', engagement_pk=engagement_pk)


@login_required
@engagement_edit_required
def toggle_scheduled_scan(request, engagement_pk, pk):
    engagement = request.engagement
    ss = get_object_or_404(ScheduledScan, pk=pk, engagement=engagement)
    if request.method == 'POST':
        if not ss.is_active:
            try:
                validate_scan(engagement.pk, ss.target)
            except ScopeViolation as exc:
                messages.error(request, str(exc))
                return redirect('recon:dashboard', engagement_pk=engagement_pk)
        ss.is_active = not ss.is_active
        ss.save(update_fields=['is_active'])
        _sync_periodic_task(ss)
        state = 'enabled' if ss.is_active else 'paused'
        messages.success(request, f'Scheduled scan {state}.')
    return redirect('recon:dashboard', engagement_pk=engagement_pk)


@login_required
@engagement_edit_required
def delete_scheduled_scan(request, engagement_pk, pk):
    engagement = request.engagement
    ss = get_object_or_404(ScheduledScan, pk=pk, engagement=engagement)
    if request.method == 'POST':
        _delete_periodic_task(ss)
        ss.delete()
        messages.success(request, 'Scheduled scan deleted.')
    return redirect('recon:dashboard', engagement_pk=engagement_pk)


def _sync_periodic_task(scheduled_scan):
    """Create or update the django-celery-beat PeriodicTask for a ScheduledScan."""
    from django_celery_beat.models import PeriodicTask, IntervalSchedule

    intervals = {
        'hourly': (1, IntervalSchedule.HOURS),
        'daily': (1, IntervalSchedule.DAYS),
        'weekly': (7, IntervalSchedule.DAYS),
        'monthly': (30, IntervalSchedule.DAYS),
    }
    every, period = intervals[scheduled_scan.frequency]

    schedule, _ = IntervalSchedule.objects.get_or_create(every=every, period=period)

    task_name = f'scheduled-scan-{scheduled_scan.pk}'

    if scheduled_scan.periodic_task_name:
        PeriodicTask.objects.filter(name=scheduled_scan.periodic_task_name).delete()

    if scheduled_scan.is_active:
        pt = PeriodicTask.objects.create(
            name=task_name,
            task='recon.tasks.run_scheduled_scan',
            interval=schedule,
            args=json.dumps([str(scheduled_scan.pk)]),
            enabled=True,
        )
        scheduled_scan.periodic_task_name = task_name
        scheduled_scan.save(update_fields=['periodic_task_name'])
    else:
        scheduled_scan.periodic_task_name = ''
        scheduled_scan.save(update_fields=['periodic_task_name'])


def _delete_periodic_task(scheduled_scan):
    """Remove the django-celery-beat PeriodicTask."""
    if scheduled_scan.periodic_task_name:
        from django_celery_beat.models import PeriodicTask
        PeriodicTask.objects.filter(name=scheduled_scan.periodic_task_name).delete()


# ── Scan pipelines ──

@login_required
@engagement_edit_required
def start_pipeline(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = ScanPipelineForm(request.POST)
        if form.is_valid():
            preset_key = form.cleaned_data['preset']
            target = form.cleaned_data['target']
            try:
                target = validate_scan(engagement.pk, target)
            except ScopeViolation as exc:
                messages.error(request, str(exc))
                return redirect('recon:dashboard', engagement_pk=engagement_pk)
            preset = ScanPipeline.PIPELINE_PRESETS[preset_key]

            pipeline = ScanPipeline.objects.create(
                engagement=engagement,
                name=preset['name'],
                target=target,
                steps=preset['steps'],
                started_by=request.user,
            )

            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Started pipeline "{preset["name"]}" on {target}',
            )

            # Try to run via Celery, fall back to synchronous
            try:
                from .tasks import run_pipeline as run_pipeline_task
                run_pipeline_task.delay(str(pipeline.pk))
                messages.success(
                    request,
                    f'Pipeline "{preset["name"]}" started in background. '
                    f'Steps: {" → ".join(preset["steps"])}',
                )
            except Exception:
                # Celery not available — run synchronously
                _run_pipeline_sync(pipeline)
                if pipeline.status == 'completed':
                    messages.success(request, f'Pipeline completed: {pipeline.total_results} results.')
                else:
                    messages.error(request, f'Pipeline failed: {pipeline.error_message}')

            return redirect('recon:dashboard', engagement_pk=engagement_pk)
    return redirect('recon:dashboard', engagement_pk=engagement_pk)


@login_required
@engagement_access(allow_client=False)
def pipeline_detail(request, engagement_pk, pk):
    engagement = request.engagement
    pipeline = get_object_or_404(ScanPipeline, pk=pk, engagement=engagement)
    related_scans = engagement.scans.filter(pipeline=pipeline)

    context = {
        'engagement': engagement,
        'pipeline': pipeline,
        'related_scans': related_scans,
    }
    return render(request, 'recon/pipeline_detail.html', context)


def _run_pipeline_sync(pipeline):
    """Use the exact worker execution path when no broker is available."""
    from .tasks import run_pipeline
    result = run_pipeline(str(pipeline.pk))
    pipeline.refresh_from_db()
    return result


@login_required
@engagement_access(allow_client=False)
def host_detail(request, engagement_pk, host_pk):
    engagement = request.engagement
    host = get_object_or_404(DiscoveredHost, pk=host_pk, engagement=engagement)
    related_scans = engagement.scans.filter(
        target__iexact=host.hostname
    ) | engagement.scans.filter(target__iexact=host.ip_address or '')
    context = {
        'engagement': engagement,
        'host': host,
        'related_scans': related_scans.distinct(),
        'can_edit': engagement.user_can_edit(request.user),
    }
    return render(request, 'recon/host_detail.html', context)


@login_required
@engagement_edit_required
def host_add(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = DiscoveredHostForm(request.POST)
        if form.is_valid():
            host = form.save(commit=False)
            host.engagement = engagement
            try:
                host.save()
                ActivityLog.objects.create(
                    engagement=engagement, user=request.user,
                    action=f'Added host: {host.hostname}'
                )
                messages.success(request, f'Host "{host.hostname}" added.')
                return redirect('recon:host_detail', engagement_pk=engagement_pk, host_pk=host.pk)
            except Exception:
                messages.error(request, f'Host "{host.hostname}" already exists in this engagement.')
                return redirect('recon:dashboard', engagement_pk=engagement_pk)
    else:
        form = DiscoveredHostForm()
    return render(request, 'recon/host_form.html', {
        'form': form, 'engagement': engagement, 'title': 'Add host',
    })


@login_required
@engagement_edit_required
def host_edit(request, engagement_pk, host_pk):
    engagement = request.engagement
    host = get_object_or_404(DiscoveredHost, pk=host_pk, engagement=engagement)
    if request.method == 'POST':
        form = DiscoveredHostForm(request.POST, instance=host)
        if form.is_valid():
            form.save()
            messages.success(request, f'Host "{host.hostname}" updated.')
            return redirect('recon:host_detail', engagement_pk=engagement_pk, host_pk=host.pk)
    else:
        form = DiscoveredHostForm(instance=host)
    return render(request, 'recon/host_form.html', {
        'form': form, 'engagement': engagement, 'title': f'Edit {host.hostname}', 'host': host,
    })


@login_required
@engagement_edit_required
def host_delete(request, engagement_pk, host_pk):
    engagement = request.engagement
    host = get_object_or_404(DiscoveredHost, pk=host_pk, engagement=engagement)
    if request.method == 'POST':
        hostname = host.hostname
        host.delete()
        ActivityLog.objects.create(
            engagement=engagement, user=request.user,
            action=f'Deleted host: {hostname}'
        )
        messages.success(request, f'Host "{hostname}" deleted.')
        return redirect('recon:dashboard', engagement_pk=engagement_pk)
    return render(request, 'recon/host_confirm_delete.html', {
        'host': host, 'engagement': engagement,
    })
