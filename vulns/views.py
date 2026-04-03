import csv
import json
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.db.models import Q
from engagements.models import Engagement, ActivityLog
from .models import Finding, Evidence, FindingTemplate
from .forms import FindingForm, EvidenceForm, ToolImportForm
from .parsers import parse_nuclei_json, parse_nikto_json
from accounts.decorators import engagement_access, engagement_edit_required
from recon.models import DiscoveredHost


@login_required
@engagement_access(allow_client=True)
def finding_list(request, engagement_pk):
    engagement = request.engagement
    findings = engagement.findings.all()

    severity_filter = request.GET.get('severity')
    status_filter = request.GET.get('status')
    search = request.GET.get('q')

    if severity_filter:
        findings = findings.filter(severity=severity_filter)
    if status_filter:
        findings = findings.filter(status=status_filter)
    if search:
        findings = findings.filter(Q(title__icontains=search) | Q(description__icontains=search))

    paginator = Paginator(findings, 20)
    page = paginator.get_page(request.GET.get('page'))

    qs_parts = []
    if severity_filter:
        qs_parts.append(f'severity={severity_filter}')
    if status_filter:
        qs_parts.append(f'status={status_filter}')
    if search:
        qs_parts.append(f'q={search}')
    query_string = '&'.join(qs_parts) + ('&' if qs_parts else '')

    context = {
        'engagement': engagement,
        'findings': page,
        'page_obj': page,
        'query_string': query_string,
        'severity_choices': Finding.Severity.choices,
        'status_choices': Finding.Status.choices,
        'can_edit': request.eng_role in ('admin', 'lead', 'pentester'),
    }
    return render(request, 'vulns/list.html', context)


@login_required
def finding_detail(request, pk):
    finding = get_object_or_404(Finding.objects.select_related('engagement', 'found_by'), pk=pk)
    if not finding.engagement.user_can_access(request.user):
        messages.error(request, 'You are not a member of this engagement.')
        return redirect('engagements:list')
    evidence_form = EvidenceForm()
    is_client = finding.engagement.user_is_client(request.user)

    if request.method == 'POST' and 'upload_evidence' in request.POST and not is_client:
        evidence_form = EvidenceForm(request.POST, request.FILES)
        if evidence_form.is_valid():
            ev = evidence_form.save(commit=False)
            ev.finding = finding
            ev.uploaded_by = request.user
            ev.save()
            messages.success(request, 'Evidence uploaded.')
            return redirect('vulns:detail', pk=pk)

    context = {
        'finding': finding,
        'evidence': finding.evidence.all(),
        'evidence_form': evidence_form,
        'is_client': is_client,
        'can_edit': finding.engagement.user_can_edit(request.user),
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
        form = FindingForm(request.POST, instance=finding, engagement=engagement)
        if form.is_valid():
            form.save()
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
]


@login_required
@engagement_access(allow_client=True)
def export_csv(request, engagement_pk):
    engagement = request.engagement
    findings = engagement.findings.all()

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

