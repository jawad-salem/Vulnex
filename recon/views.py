import json

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from .models import ReconScan, DiscoveredHost, ScheduledScan, ScanPipeline
from .forms import ReconScanForm, NmapImportForm, DiscoveredHostForm, ScheduledScanForm, ScanPipelineForm
from .parsers import parse_nmap_xml_to_hosts
from .scanners import run_scan
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


# ── Scheduled scans ──

@login_required
@engagement_edit_required
def create_scheduled_scan(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = ScheduledScanForm(request.POST)
        if form.is_valid():
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
                messages.success(
                    request,
                    f'Pipeline "{preset["name"]}" completed: {pipeline.total_results} results.',
                )

            return redirect('recon:dashboard', engagement_pk=engagement_pk)
    return redirect('recon:dashboard', engagement_pk=engagement_pk)


@login_required
@engagement_access(allow_client=False)
def pipeline_detail(request, engagement_pk, pk):
    engagement = request.engagement
    pipeline = get_object_or_404(ScanPipeline, pk=pk, engagement=engagement)
    # Get scans that were created by this pipeline (matched by time window)
    related_scans = engagement.scans.filter(
        started_by=pipeline.started_by,
        created_at__gte=pipeline.created_at,
    )
    if pipeline.completed_at:
        related_scans = related_scans.filter(created_at__lte=pipeline.completed_at)

    context = {
        'engagement': engagement,
        'pipeline': pipeline,
        'related_scans': related_scans,
    }
    return render(request, 'recon/pipeline_detail.html', context)


def _run_pipeline_sync(pipeline):
    """Run a pipeline synchronously (fallback when Celery is unavailable)."""
    from .scanners import run_scan as scanner_run

    pipeline.status = 'running'
    pipeline.started_at = timezone.now()
    pipeline.save(update_fields=['status', 'started_at'])

    targets = [pipeline.target]
    results_summary = {}

    try:
        for i, step in enumerate(pipeline.steps):
            pipeline.current_step = i
            pipeline.save(update_fields=['current_step'])

            step_results = []
            step_targets = list(targets)

            # Deduplicate by IP — skip scanning the same server multiple times
            if step in ('port_scan', 'tech_detect', 'dir_brute'):
                from .tasks import _dedupe_targets_by_ip
                step_targets = _dedupe_targets_by_ip(step_targets)

            for target in step_targets:
                scan = ReconScan.objects.create(
                    engagement=pipeline.engagement,
                    scan_type=step,
                    target=target,
                    started_by=pipeline.started_by,
                    status='running',
                    started_at=timezone.now(),
                )
                try:
                    results = scanner_run(step, target)
                    scan.parsed_results = results
                    scan.status = 'completed'
                    scan.completed_at = timezone.now()
                    scan.save(update_fields=['parsed_results', 'status', 'completed_at'])
                    for result in results:
                        _merge_host(pipeline.engagement, scan, result)
                    step_results.extend(results)
                except Exception as e:
                    scan.status = 'failed'
                    scan.error_message = str(e)
                    scan.completed_at = timezone.now()
                    scan.save(update_fields=['status', 'error_message', 'completed_at'])

            if step == 'subdomain':
                for result in step_results:
                    hostname = result.get('hostname', '')
                    if hostname and hostname not in targets:
                        targets.append(hostname)

            if step == 'port_scan':
                for result in step_results:
                    host = result.get('host') or result.get('hostname', '')
                    if host and host not in targets:
                        targets.append(host)

            results_summary[step] = {
                'count': len(step_results),
                'targets_scanned': len(step_targets),
            }
            # Save incremental results so the detail page shows progress mid-run
            pipeline.results_summary = results_summary
            pipeline.save(update_fields=['results_summary'])

        pipeline.current_step = len(pipeline.steps)
        pipeline.status = 'completed'
        pipeline.completed_at = timezone.now()
        pipeline.save(update_fields=['current_step', 'status', 'completed_at'])

    except Exception as e:
        pipeline.status = 'failed'
        pipeline.error_message = str(e)
        pipeline.completed_at = timezone.now()
        pipeline.results_summary = results_summary
        pipeline.save(update_fields=['status', 'error_message', 'completed_at', 'results_summary'])


# ── Host management ──

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
