"""
Celery tasks for asynchronous recon scanning, scheduling, and pipelines.
"""
import json
import logging

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=2, default_retry_delay=30)
def run_scan_async(self, scan_id):
    """Run a single ReconScan asynchronously."""
    from .models import ReconScan, DiscoveredHost
    from .scanners import run_scan
    from .views import _merge_host

    try:
        scan = ReconScan.objects.get(pk=scan_id)
    except ReconScan.DoesNotExist:
        logger.error(f'Scan {scan_id} not found')
        return

    scan.status = 'running'
    scan.started_at = timezone.now()
    scan.save(update_fields=['status', 'started_at'])

    try:
        results = run_scan(scan.scan_type, scan.target)
        scan.parsed_results = results
        scan.status = 'completed'
        scan.completed_at = timezone.now()
        scan.save(update_fields=['parsed_results', 'status', 'completed_at'])

        for result in results:
            _merge_host(scan.engagement, scan, result)

        return {'status': 'completed', 'result_count': len(results)}
    except Exception as e:
        scan.status = 'failed'
        scan.error_message = str(e)
        scan.completed_at = timezone.now()
        scan.save(update_fields=['status', 'error_message', 'completed_at'])
        logger.error(f'Scan {scan_id} failed: {e}')
        return {'status': 'failed', 'error': str(e)}


@shared_task(bind=True)
def run_scheduled_scan(self, scheduled_scan_id):
    """Execute a scheduled (recurring) scan and create a new ReconScan record."""
    from .models import ScheduledScan, ReconScan

    try:
        ss = ScheduledScan.objects.get(pk=scheduled_scan_id)
    except ScheduledScan.DoesNotExist:
        logger.error(f'ScheduledScan {scheduled_scan_id} not found')
        return

    if not ss.is_active:
        return

    # Create a new ReconScan record
    scan = ReconScan.objects.create(
        engagement=ss.engagement,
        scan_type=ss.scan_type,
        target=ss.target,
        started_by=ss.created_by,
        status='pending',
    )

    # Update tracking
    ss.last_run = timezone.now()
    ss.run_count += 1
    ss.save(update_fields=['last_run', 'run_count'])

    # Run the actual scan
    return run_scan_async(str(scan.pk))


@shared_task(bind=True)
def run_pipeline(self, pipeline_id):
    """Execute a scan pipeline — runs steps sequentially, chaining results."""
    from .models import ScanPipeline, ReconScan
    from .scanners import run_scan
    from .views import _merge_host
    from engagements.models import ActivityLog

    try:
        pipeline = ScanPipeline.objects.get(pk=pipeline_id)
    except ScanPipeline.DoesNotExist:
        logger.error(f'Pipeline {pipeline_id} not found')
        return

    pipeline.status = 'running'
    pipeline.started_at = timezone.now()
    pipeline.save(update_fields=['status', 'started_at'])

    # Targets expand as we discover subdomains/hosts
    targets = [pipeline.target]
    results_summary = {}

    try:
        for i, step in enumerate(pipeline.steps):
            pipeline.current_step = i
            pipeline.save(update_fields=['current_step'])

            step_results = []
            step_targets = list(targets)  # snapshot current targets

            for target in step_targets:
                # Create a ReconScan record for each step+target
                scan = ReconScan.objects.create(
                    engagement=pipeline.engagement,
                    scan_type=step,
                    target=target,
                    started_by=pipeline.started_by,
                    status='running',
                    started_at=timezone.now(),
                )

                try:
                    results = run_scan(step, target)
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
                    logger.warning(f'Pipeline step {step} failed for {target}: {e}')

            # Expand targets from subdomain results for subsequent steps
            if step == 'subdomain':
                for result in step_results:
                    hostname = result.get('hostname', '')
                    if hostname and hostname not in targets:
                        targets.append(hostname)

            # Expand targets from port scan results (hosts with open ports)
            if step == 'port_scan':
                for result in step_results:
                    host = result.get('host') or result.get('hostname', '')
                    if host and host not in targets:
                        targets.append(host)

            results_summary[step] = {
                'count': len(step_results),
                'targets_scanned': len(step_targets),
            }

        pipeline.current_step = len(pipeline.steps)
        pipeline.status = 'completed'
        pipeline.completed_at = timezone.now()
        pipeline.results_summary = results_summary
        pipeline.save(update_fields=[
            'current_step', 'status', 'completed_at', 'results_summary',
        ])

        # Log activity
        total = sum(s['count'] for s in results_summary.values())
        ActivityLog.objects.create(
            engagement=pipeline.engagement,
            user=pipeline.started_by,
            action=f'Pipeline "{pipeline.name}" completed: {total} results across {len(pipeline.steps)} steps',
        )

        return {'status': 'completed', 'results_summary': results_summary}

    except Exception as e:
        pipeline.status = 'failed'
        pipeline.error_message = str(e)
        pipeline.completed_at = timezone.now()
        pipeline.results_summary = results_summary
        pipeline.save(update_fields=[
            'status', 'error_message', 'completed_at', 'results_summary',
        ])
        logger.error(f'Pipeline {pipeline_id} failed: {e}')
        return {'status': 'failed', 'error': str(e)}
