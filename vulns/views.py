import csv
import json
from datetime import timedelta
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponse, FileResponse, HttpResponseForbidden
from django.db.models import Q
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from .models import Finding, Evidence, FindingTemplate
from .forms import FindingForm, EvidenceForm, ToolImportForm, RetestForm
from .parsers import parse_nuclei_json, parse_nikto_json
from accounts.decorators import engagement_access, engagement_edit_required
from accounts.models import AuditLog
from recon.models import DiscoveredHost


@login_required
@engagement_access(allow_client=True)
def finding_list(request, engagement_pk):
    engagement = request.engagement
    findings = engagement.findings.all()

    is_client = request.eng_role == 'client'
    if is_client:
        findings = findings.filter(review_state=Finding.ReviewState.APPROVED)

    severity_filter = request.GET.get('severity')
    status_filter = request.GET.get('status')
    sla_filter = request.GET.get('sla')
    assigned_filter = request.GET.get('assigned')
    review_filter = request.GET.get('review')
    search = request.GET.get('q')

    if review_filter and not is_client:
        findings = findings.filter(review_state=review_filter)

    if severity_filter:
        findings = findings.filter(severity=severity_filter)
    if status_filter:
        findings = findings.filter(status=status_filter)
    if assigned_filter == 'me':
        findings = findings.filter(assigned_to=request.user)
    elif assigned_filter == 'unassigned':
        findings = findings.filter(assigned_to__isnull=True)
    elif assigned_filter:
        findings = findings.filter(assigned_to_id=assigned_filter)
    if sla_filter:
        today = timezone.now().date()
        open_statuses = ~Q(status__in=Finding.SLA_CLOSED_STATUSES)
        if sla_filter == 'overdue':
            findings = findings.filter(open_statuses, due_date__lt=today)
        elif sla_filter == 'due_soon':
            findings = findings.filter(
                open_statuses, due_date__gte=today, due_date__lte=today + timedelta(days=3),
            )
        elif sla_filter == 'on_track':
            findings = findings.filter(open_statuses, due_date__gt=today + timedelta(days=3))
    if search:
        findings = findings.filter(Q(title__icontains=search) | Q(description__icontains=search))

    paginator = Paginator(findings, 20)
    page = paginator.get_page(request.GET.get('page'))

    qs_parts = []
    if severity_filter:
        qs_parts.append(f'severity={severity_filter}')
    if status_filter:
        qs_parts.append(f'status={status_filter}')
    if sla_filter:
        qs_parts.append(f'sla={sla_filter}')
    if assigned_filter:
        qs_parts.append(f'assigned={assigned_filter}')
    if review_filter:
        qs_parts.append(f'review={review_filter}')
    if search:
        qs_parts.append(f'q={search}')
    query_string = '&'.join(qs_parts) + ('&' if qs_parts else '')

    # Assignable members for the filter dropdown — non-clients only
    assignable_members = [
        m for m in engagement.members.exclude(role='client').select_related('user')
    ]

    context = {
        'engagement': engagement,
        'findings': page,
        'page_obj': page,
        'query_string': query_string,
        'severity_choices': Finding.Severity.choices,
        'status_choices': Finding.Status.choices,
        'review_choices': Finding.ReviewState.choices,
        'sla_filter': sla_filter,
        'assigned_filter': assigned_filter,
        'review_filter': review_filter,
        'assignable_members': assignable_members,
        'can_edit': request.eng_role in ('admin', 'lead', 'pentester'),
        'is_client': is_client,
    }
    return render(request, 'vulns/list.html', context)


@login_required
def finding_detail(request, pk):
    finding = get_object_or_404(Finding.objects.select_related('engagement', 'found_by', 'retested_by'), pk=pk)
    if not finding.engagement.user_can_access(request.user):
        messages.error(request, 'You are not a member of this engagement.')
        return redirect('engagements:list')
    evidence_form = EvidenceForm()
    retest_form = RetestForm(instance=finding)
    is_client = finding.engagement.user_is_client(request.user)
    can_edit = finding.engagement.user_can_edit(request.user)
    can_review = finding.engagement.user_can_review(request.user)

    if is_client and finding.review_state != Finding.ReviewState.APPROVED:
        messages.error(request, 'This finding is not yet available.')
        return redirect('vulns:list', engagement_pk=finding.engagement.pk)

    if request.method == 'POST' and 'upload_evidence' in request.POST and not is_client:
        evidence_form = EvidenceForm(request.POST, request.FILES)
        if evidence_form.is_valid():
            ev = evidence_form.save(commit=False)
            ev.finding = finding
            ev.uploaded_by = request.user
            ev.save()
            messages.success(request, 'Evidence uploaded.')
            return redirect('vulns:detail', pk=pk)

    if request.method == 'POST' and 'record_retest' in request.POST and can_edit:
        retest_form = RetestForm(request.POST, instance=finding)
        if retest_form.is_valid():
            f = retest_form.save(commit=False)
            f.retested_by = request.user
            if f.retest_status == Finding.RetestStatus.FIXED:
                f.status = Finding.Status.REMEDIATED
            f.save()
            ActivityLog.objects.create(
                engagement=finding.engagement, user=request.user,
                action=f'Retested finding: {finding.title} → {f.get_retest_status_display()}',
            )
            messages.success(request, 'Retest recorded.')
            return redirect('vulns:detail', pk=pk)

    context = {
        'finding': finding,
        'evidence': finding.evidence.all(),
        'evidence_form': evidence_form,
        'retest_form': retest_form,
        'is_client': is_client,
        'can_edit': can_edit,
        'can_review': can_review,
    }
    return render(request, 'vulns/detail.html', context)


@login_required
@engagement_edit_required
def finding_create(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = FindingForm(request.POST, engagement=engagement)
        if form.is_valid():
            finding = form.save(commit=False)
            finding.engagement = engagement
            finding.found_by = request.user
            # Auto-fill host/IP from linked recon host if not manually set
            if finding.discovered_host:
                if not finding.host:
                    finding.host = finding.discovered_host.hostname
                if not finding.port and finding.discovered_host.ports:
                    first_port = finding.discovered_host.ports[0]
                    if isinstance(first_port, dict):
                        finding.port = first_port.get('port')
            finding.save()
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Added finding: {finding.title}'
            )
            if finding.assigned_to:
                ActivityLog.objects.create(
                    engagement=engagement, user=request.user,
                    action=f'Assigned finding "{finding.title}" to {finding.assigned_to}',
                )
            messages.success(request, 'Finding created.')
            return redirect('vulns:detail', pk=finding.pk)
    else:
        form = FindingForm(engagement=engagement)
    templates = FindingTemplate.objects.all()
    return render(request, 'vulns/form.html', {
        'form': form, 'engagement': engagement, 'title': 'New finding',
        'finding_templates': templates,
    })


@login_required
def finding_edit(request, pk):
    finding = get_object_or_404(Finding, pk=pk)
    engagement = finding.engagement
    if not engagement.user_can_edit(request.user):
        messages.error(request, 'You do not have edit permissions.')
        return redirect('vulns:detail', pk=pk)
    if request.method == 'POST':
        previous_assignee = finding.assigned_to
        form = FindingForm(request.POST, instance=finding, engagement=engagement)
        if form.is_valid():
            updated = form.save()
            if updated.assigned_to != previous_assignee:
                ActivityLog.objects.create(
                    engagement=engagement, user=request.user,
                    action=(
                        f'Reassigned finding "{updated.title}" '
                        f'from {previous_assignee or "unassigned"} '
                        f'to {updated.assigned_to or "unassigned"}'
                    ),
                )
            messages.success(request, 'Finding updated.')
            return redirect('vulns:detail', pk=pk)
    else:
        form = FindingForm(instance=finding, engagement=engagement)
    templates = FindingTemplate.objects.all()
    return render(request, 'vulns/form.html', {
        'form': form, 'engagement': engagement,
        'title': 'Edit finding', 'finding': finding,
        'finding_templates': templates,
    })


@login_required
def finding_delete(request, pk):
    finding = get_object_or_404(Finding, pk=pk)
    if not finding.engagement.user_can_edit(request.user):
        messages.error(request, 'You do not have permission to delete findings.')
        return redirect('vulns:detail', pk=pk)
    engagement = finding.engagement
    if request.method == 'POST':
        title = finding.title
        finding.delete()
        ActivityLog.objects.create(
            engagement=engagement,
            user=request.user,
            action=f'Deleted finding: {title}'
        )
        messages.success(request, f'Finding "{title}" deleted.')
        return redirect('vulns:list', engagement_pk=engagement.pk)
    return render(request, 'vulns/confirm_delete.html', {
        'finding': finding, 'engagement': engagement,
    })


@login_required
def submit_for_review(request, pk):
    """Pentester moves finding DRAFT (or CHANGES_REQUESTED) → IN_REVIEW."""
    finding = get_object_or_404(Finding, pk=pk)
    engagement = finding.engagement
    if not engagement.user_can_edit(request.user):
        messages.error(request, 'You do not have permission to submit findings for review.')
        return redirect('vulns:detail', pk=pk)
    if request.method != 'POST':
        return redirect('vulns:detail', pk=pk)
    if finding.review_state not in (Finding.ReviewState.DRAFT, Finding.ReviewState.CHANGES_REQUESTED):
        messages.error(request, 'This finding is not in a state that can be submitted for review.')
        return redirect('vulns:detail', pk=pk)
    finding.review_state = Finding.ReviewState.IN_REVIEW
    finding.review_notes = ''
    finding.save(update_fields=['review_state', 'review_notes', 'updated_at'])
    ActivityLog.objects.create(
        engagement=engagement, user=request.user,
        action=f'Submitted finding for review: {finding.title}',
    )
    messages.success(request, 'Finding submitted for review.')
    return redirect('vulns:detail', pk=pk)


@login_required
def approve_finding(request, pk):
    """Lead / reviewer moves IN_REVIEW → APPROVED. Approved findings become client-visible."""
    finding = get_object_or_404(Finding, pk=pk)
    engagement = finding.engagement
    if not engagement.user_can_review(request.user):
        messages.error(request, 'Only leads and reviewers can approve findings.')
        return redirect('vulns:detail', pk=pk)
    if request.method != 'POST':
        return redirect('vulns:detail', pk=pk)
    if finding.review_state != Finding.ReviewState.IN_REVIEW:
        messages.error(request, 'Only findings in review can be approved.')
        return redirect('vulns:detail', pk=pk)
    finding.review_state = Finding.ReviewState.APPROVED
    finding.reviewed_by = request.user
    finding.reviewed_at = timezone.now()
    finding.review_notes = ''
    finding.save(update_fields=[
        'review_state', 'reviewed_by', 'reviewed_at', 'review_notes', 'updated_at',
    ])
    ActivityLog.objects.create(
        engagement=engagement, user=request.user,
        action=f'Approved finding: {finding.title}',
    )
    messages.success(request, 'Finding approved — now visible to clients.')
    return redirect('vulns:detail', pk=pk)


@login_required
def request_changes(request, pk):
    """Lead / reviewer moves IN_REVIEW → CHANGES_REQUESTED with feedback notes."""
    finding = get_object_or_404(Finding, pk=pk)
    engagement = finding.engagement
    if not engagement.user_can_review(request.user):
        messages.error(request, 'Only leads and reviewers can request changes.')
        return redirect('vulns:detail', pk=pk)
    if request.method != 'POST':
        return redirect('vulns:detail', pk=pk)
    if finding.review_state != Finding.ReviewState.IN_REVIEW:
        messages.error(request, 'Only findings in review can have changes requested.')
        return redirect('vulns:detail', pk=pk)
    notes = (request.POST.get('review_notes') or '').strip()
    if not notes:
        messages.error(request, 'Please explain what needs to change.')
        return redirect('vulns:detail', pk=pk)
    finding.review_state = Finding.ReviewState.CHANGES_REQUESTED
    finding.reviewed_by = request.user
    finding.reviewed_at = timezone.now()
    finding.review_notes = notes
    finding.save(update_fields=[
        'review_state', 'reviewed_by', 'reviewed_at', 'review_notes', 'updated_at',
    ])
    ActivityLog.objects.create(
        engagement=engagement, user=request.user,
        action=f'Requested changes on finding: {finding.title}',
    )
    messages.success(request, 'Changes requested — author has been notified.')
    return redirect('vulns:detail', pk=pk)


@login_required
@engagement_edit_required
def tool_import(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = ToolImportForm(request.POST, request.FILES)
        if form.is_valid():
            tool = form.cleaned_data['tool']
            uploaded = request.FILES['file']
            content = uploaded.read()

            parsers = {
                'nuclei': parse_nuclei_json,
                'nikto': parse_nikto_json,
            }
            try:
                findings_data = parsers[tool](content)
                created = 0
                skipped = 0
                # Build set of (title, host, endpoint) from existing findings
                existing_keys = set(
                    engagement.findings.values_list('title', 'host', 'endpoint')
                )
                for fd in findings_data:
                    dedup_key = (fd.get('title', ''), fd.get('host', ''), fd.get('endpoint', ''))
                    if dedup_key in existing_keys:
                        skipped += 1
                        continue
                    existing_keys.add(dedup_key)
                    Finding.objects.create(
                        engagement=engagement,
                        found_by=request.user,
                        tool_source=tool.capitalize(),
                        **fd
                    )
                    created += 1
                ActivityLog.objects.create(
                    engagement=engagement, user=request.user,
                    action=f'Imported {created} findings from {tool.capitalize()}'
                )
                msg = f'Imported {created} findings from {tool.capitalize()}.'
                if skipped:
                    msg += f' {skipped} duplicate(s) skipped.'
                messages.success(request, msg)
            except Exception as e:
                messages.error(request, f'Import failed: {str(e)}')
            return redirect('vulns:list', engagement_pk=engagement_pk)
    else:
        form = ToolImportForm()
    return render(request, 'vulns/import.html', {
        'form': form, 'engagement': engagement,
    })


EXPORT_FIELDS = [
    'title', 'severity', 'cvss_score', 'status', 'host', 'port', 'url',
    'endpoint', 'http_method', 'parameter', 'description',
    'proof_of_concept', 'remediation', 'cwe_id', 'tool_source',
    'affected_hosts', 'references', 'cvss_vector_string', 'created_at',
    'due_date', 'sla_status',
]


@login_required
@engagement_access(allow_client=True)
def export_csv(request, engagement_pk):
    engagement = request.engagement
    findings = engagement.findings.all()
    if request.eng_role == 'client':
        findings = findings.filter(review_state=Finding.ReviewState.APPROVED)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{engagement.name}_findings.csv"'

    writer = csv.writer(response)
    writer.writerow(EXPORT_FIELDS)
    for f in findings:
        writer.writerow([
            getattr(f, field) if field != 'cvss_vector_string'
            else f.cvss_vector_string
            for field in EXPORT_FIELDS
        ])
    return response


@login_required
@engagement_access(allow_client=True)
def export_json(request, engagement_pk):
    engagement = request.engagement
    findings = engagement.findings.all()
    if request.eng_role == 'client':
        findings = findings.filter(review_state=Finding.ReviewState.APPROVED)

    data = []
    for f in findings:
        row = {}
        for field in EXPORT_FIELDS:
            val = getattr(f, field) if field != 'cvss_vector_string' else f.cvss_vector_string
            if hasattr(val, 'isoformat'):
                val = val.isoformat()
            row[field] = val
        data.append(row)

    response = HttpResponse(
        json.dumps(data, indent=2),
        content_type='application/json',
    )
    response['Content-Disposition'] = f'attachment; filename="{engagement.name}_findings.json"'
    return response


@login_required
def evidence_download(request, pk):
    """Stream an evidence file after verifying the user can access its
    engagement. Files live under PROTECTED_MEDIA_ROOT so this view is the
    only path to them."""
    evidence = get_object_or_404(
        Evidence.objects.select_related('finding__engagement'),
        pk=pk,
    )
    engagement = evidence.finding.engagement
    if not engagement.user_can_access(request.user):
        return HttpResponseForbidden('You do not have access to this evidence.')
    if engagement.user_is_client(request.user) and \
            evidence.finding.review_state != Finding.ReviewState.APPROVED:
        return HttpResponseForbidden('This evidence is not yet available.')
    filename = evidence.file.name.rsplit('/', 1)[-1]
    AuditLog.record(
        actor=request.user,
        action=AuditLog.Action.EVIDENCE_DOWNLOAD,
        target=str(evidence.pk),
        details={
            'engagement': engagement.name,
            'finding': str(evidence.finding.pk),
            'filename': filename,
        },
        request=request,
    )
    return FileResponse(evidence.file.open('rb'), filename=filename)


@login_required
def api_template_detail(request, pk):
    """Return finding template data as JSON for form auto-fill."""
    tpl = get_object_or_404(FindingTemplate, pk=pk)
    data = {
        'title': tpl.title,
        'description': tpl.description,
        'remediation': tpl.remediation,
        'references': tpl.references,
        'cwe_id': tpl.cwe_id,
        'attack_vector': tpl.attack_vector,
        'attack_complexity': tpl.attack_complexity,
        'privileges_required': tpl.privileges_required,
        'user_interaction': tpl.user_interaction,
        'scope': tpl.scope,
        'confidentiality_impact': tpl.confidentiality_impact,
        'integrity_impact': tpl.integrity_impact,
        'availability_impact': tpl.availability_impact,
    }
    return HttpResponse(json.dumps(data), content_type='application/json')


@login_required
def api_host_detail(request, pk):
    """Return discovered host data as JSON for form auto-fill."""
    host = get_object_or_404(DiscoveredHost, pk=pk)
    # Verify user has access to the engagement
    if not host.engagement.user_can_access(request.user):
        return HttpResponse('{}', content_type='application/json', status=403)
    ports = []
    for p in host.ports:
        if isinstance(p, dict):
            ports.append(p)
        else:
            ports.append({'port': p, 'protocol': 'tcp'})
    data = {
        'hostname': host.hostname,
        'ip_address': host.ip_address or '',
        'ports': ports,
        'technologies': host.technologies,
    }
    return HttpResponse(json.dumps(data), content_type='application/json')

