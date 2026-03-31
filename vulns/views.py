from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from engagements.models import Engagement, ActivityLog
from .models import Finding, Evidence
from .forms import FindingForm, EvidenceForm, ToolImportForm
from .parsers import parse_nmap_xml, parse_nuclei_json, parse_nikto_json
from accounts.decorators import role_required


@login_required
def finding_list(request, engagement_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
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

    context = {
        'engagement': engagement,
        'findings': findings,
        'severity_choices': Finding.Severity.choices,
        'status_choices': Finding.Status.choices,
    }
    return render(request, 'vulns/list.html', context)


@login_required
def finding_detail(request, pk):
    finding = get_object_or_404(Finding.objects.select_related('engagement', 'found_by'), pk=pk)
    evidence_form = EvidenceForm()

    if request.method == 'POST' and 'upload_evidence' in request.POST:
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
    }
    return render(request, 'vulns/detail.html', context)


@login_required
@role_required('admin', 'pentester')
def finding_create(request, engagement_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
    if request.method == 'POST':
        form = FindingForm(request.POST)
        if form.is_valid():
            finding = form.save(commit=False)
            finding.engagement = engagement
            finding.found_by = request.user
            finding.save()
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Added finding: {finding.title}'
            )
            messages.success(request, 'Finding created.')
            return redirect('vulns:detail', pk=finding.pk)
    else:
        form = FindingForm()
    return render(request, 'vulns/form.html', {
        'form': form, 'engagement': engagement, 'title': 'New finding'
    })


@login_required
@role_required('admin', 'pentester')
def finding_edit(request, pk):
    finding = get_object_or_404(Finding, pk=pk)
    if request.method == 'POST':
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            form.save()
            messages.success(request, 'Finding updated.')
            return redirect('vulns:detail', pk=pk)
    else:
        form = FindingForm(instance=finding)
    return render(request, 'vulns/form.html', {
        'form': form, 'engagement': finding.engagement,
        'title': 'Edit finding', 'finding': finding,
    })


@login_required
@role_required('admin', 'pentester')
def tool_import(request, engagement_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
    if request.method == 'POST':
        form = ToolImportForm(request.POST, request.FILES)
        if form.is_valid():
            tool = form.cleaned_data['tool']
            uploaded = request.FILES['file']
            content = uploaded.read()

            parsers = {
                'nmap': parse_nmap_xml,
                'nuclei': parse_nuclei_json,
                'nikto': parse_nikto_json,
            }
            try:
                findings_data = parsers[tool](content)
                count = 0
                for fd in findings_data:
                    Finding.objects.create(
                        engagement=engagement,
                        found_by=request.user,
                        tool_source=tool.capitalize(),
                        **fd
                    )
                    count += 1
                ActivityLog.objects.create(
                    engagement=engagement, user=request.user,
                    action=f'Imported {count} findings from {tool.capitalize()}'
                )
                messages.success(request, f'Imported {count} findings from {tool.capitalize()}.')
            except Exception as e:
                messages.error(request, f'Import failed: {str(e)}')
            return redirect('vulns:list', engagement_pk=engagement_pk)
    else:
        form = ToolImportForm()
    return render(request, 'vulns/import.html', {
        'form': form, 'engagement': engagement,
    })

