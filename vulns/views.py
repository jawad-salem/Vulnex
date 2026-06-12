import csv
import json
from datetime import datetime, time, timedelta
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.http import HttpResponse, FileResponse, HttpResponseForbidden
from django.db.models import Q
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from .models import Finding, Evidence, FindingTemplate, FindingComment
from .forms import (
    FindingForm, EvidenceForm, ToolImportForm, RetestForm,
    FindingCommentForm, FindingMergeForm, CsvImportForm,
)
from .services.imports import (
    PARSERS,
    IMPORT_PREVIEW_LIMIT,
    CSV_IMPORT_COLUMNS,
    CSV_IMPORT_REQUIRED,
    classify_import,
    commit_import,
    parse_csv_findings,
)
from .services.merge import merge_findings
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
    can_mark_internal = not is_client
    comment_form = FindingCommentForm(
        can_mark_internal=can_mark_internal, can_mark_review=can_review,
    )

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

    if request.method == 'POST' and 'post_comment' in request.POST:
        comment_form = FindingCommentForm(
            request.POST,
            can_mark_internal=can_mark_internal, can_mark_review=can_review,
        )
        if comment_form.is_valid():
            comment = comment_form.save(commit=False)
            comment.finding = finding
            comment.author = request.user
            if is_client:
                comment.internal_only = False
                comment.is_review_feedback = False
            # Only reviewers/leads can mark as review feedback
            if not can_review:
                comment.is_review_feedback = False
            # Validate parent belongs to this finding
            if comment.parent and comment.parent.finding_id != finding.pk:
                comment.parent = None
            comment.save()
            AuditLog.record(
                actor=request.user,
                action=AuditLog.Action.COMMENT_POST,
                target=str(comment.pk),
                details={
                    'finding': finding.title,
                    'engagement': finding.engagement.name,
                    'internal_only': comment.internal_only,
                    'is_review_feedback': comment.is_review_feedback,
                },
                request=request,
            )
            ActivityLog.objects.create(
                engagement=finding.engagement, user=request.user,
                action=f'Commented on finding: {finding.title}',
            )
            messages.success(request, 'Comment posted.')
            return redirect('vulns:detail', pk=pk)

    comments_qs = finding.comments.select_related('author', 'parent').all()
    if is_client:
        comments_qs = comments_qs.filter(internal_only=False)
    comments = list(comments_qs)
    # Tag each with per-user edit permission for template.
    for c in comments:
        c.user_can_edit = c.can_edit(request.user)
        c.user_can_delete = c.can_delete(request.user)

    evidence = list(finding.evidence.select_related('uploaded_by').all())

    # ── Attack paths this finding is referenced in (via AttackPathEdge.finding) ──
    attack_paths = []
    _seen_paths = set()
    for edge in finding.attack_path_edges.select_related('path').all():
        if edge.path_id not in _seen_paths:
            _seen_paths.add(edge.path_id)
            attack_paths.append(edge.path)

    # ── Synthesised activity timeline (oldest → newest) ──
    # Built from existing timestamps; no event table needed. Clients only see
    # public comments (internal ones are already filtered out of `comments`).
    timeline = [{
        'ts': finding.created_at,
        'kind': 'create',
        'title': 'Finding created',
        'who': finding.found_by,
        'meta': finding.tool_source or 'Manual entry',
    }]
    for ev in evidence:
        timeline.append({
            'ts': ev.uploaded_at,
            'kind': 'evidence',
            'title': 'Evidence uploaded',
            'who': ev.uploaded_by,
            'meta': ev.caption or ev.file.name.rsplit('/', 1)[-1],
        })
    for c in comments:
        timeline.append({
            'ts': c.created_at,
            'kind': 'review' if c.is_review_feedback else 'comment',
            'title': 'Review feedback' if c.is_review_feedback else 'Comment added',
            'who': c.author,
            'meta': 'Internal' if c.internal_only else '',
        })
    if finding.reviewed_at and (not is_client or finding.review_state == Finding.ReviewState.APPROVED):
        timeline.append({
            'ts': finding.reviewed_at,
            'kind': 'review',
            'title': f'Review · {finding.get_review_state_display()}',
            'who': finding.reviewed_by,
            'meta': '',
        })
    if finding.retest_date:
        retest_ts = timezone.make_aware(datetime.combine(finding.retest_date, time.min))
        timeline.append({
            'ts': retest_ts,
            'kind': 'retest',
            'title': f'Retest · {finding.get_retest_status_display()}',
            'who': finding.retested_by,
            'meta': '',
        })
    timeline.sort(key=lambda e: e['ts'])

    context = {
        'finding': finding,
        'evidence': evidence,
        'evidence_form': evidence_form,
        'retest_form': retest_form,
        'comment_form': comment_form,
        'comments': comments,
        'timeline': timeline,
        'attack_paths': attack_paths,
        'is_client': is_client,
        'can_edit': can_edit,
        'can_review': can_review,
    }
    return render(request, 'vulns/detail.html', context)


@login_required
def finding_merge(request, pk):
    """Lead/Reviewer-only action: merge ``pk`` (source) into a chosen target.

    GET renders a confirmation page with the side-by-side preview; POST with
    a valid target performs the merge.
    """
    source = get_object_or_404(Finding.objects.select_related('engagement'), pk=pk)
    engagement = source.engagement
    if not engagement.user_can_review(request.user):
        messages.error(request, 'Only leads and reviewers can merge findings.')
        return redirect('vulns:detail', pk=pk)

    if request.method == 'POST':
        form = FindingMergeForm(request.POST, source=source)
        if form.is_valid():
            target = form.cleaned_data['target']
            if target.engagement_id != source.engagement_id:
                # ModelChoiceField queryset already enforces this, but
                # belt-and-braces in case of a tampered request.
                return HttpResponseForbidden('Cross-engagement merge denied.')
            details = merge_findings(source, target, request.user)
            AuditLog.record(
                actor=request.user,
                action=AuditLog.Action.FINDING_MERGE,
                target=details['target_id'],
                details={**details, 'engagement': engagement.name},
                request=request,
            )
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=(
                    f'Merged finding "{details["source_title"]}" '
                    f'into "{details["target_title"]}"'
                ),
            )
            messages.success(
                request,
                f'Merged into "{details["target_title"]}". '
                f'{details["moved_evidence"]} evidence item(s) and '
                f'{details["moved_comments"]} comment(s) moved.',
            )
            return redirect('vulns:detail', pk=target.pk)
    else:
        form = FindingMergeForm(source=source)

    target_id = request.GET.get('target')
    target_preview = None
    if target_id:
        try:
            target_preview = Finding.objects.get(
                pk=target_id, engagement_id=source.engagement_id,
            )
        except (Finding.DoesNotExist, ValueError):
            target_preview = None

    return render(request, 'vulns/merge_confirm.html', {
        'source': source,
        'engagement': engagement,
        'form': form,
        'target_preview': target_preview,
    })


@login_required
def comment_edit(request, pk):
    comment = get_object_or_404(
        FindingComment.objects.select_related('finding__engagement', 'author'),
        pk=pk,
    )
    finding = comment.finding
    if not finding.engagement.user_can_access(request.user):
        return HttpResponseForbidden('Not a member of this engagement.')
    if not comment.can_edit(request.user):
        messages.error(request, 'This comment can no longer be edited.')
        return redirect('vulns:detail', pk=finding.pk)

    is_client = finding.engagement.user_is_client(request.user)
    can_review = finding.engagement.user_can_review(request.user)
    can_mark_internal = not is_client

    if request.method == 'POST':
        form = FindingCommentForm(
            request.POST, instance=comment,
            can_mark_internal=can_mark_internal, can_mark_review=can_review,
        )
        if form.is_valid():
            updated = form.save(commit=False)
            updated.edited_at = timezone.now()
            if is_client:
                updated.internal_only = False
                updated.is_review_feedback = False
            if not can_review:
                updated.is_review_feedback = False
            updated.save()
            AuditLog.record(
                actor=request.user,
                action=AuditLog.Action.COMMENT_EDIT,
                target=str(updated.pk),
                details={'finding': finding.title},
                request=request,
            )
            messages.success(request, 'Comment updated.')
            return redirect('vulns:detail', pk=finding.pk)
    else:
        form = FindingCommentForm(
            instance=comment,
            can_mark_internal=can_mark_internal, can_mark_review=can_review,
        )
    return render(request, 'vulns/comment_edit.html', {
        'form': form, 'comment': comment, 'finding': finding,
    })


@login_required
def comment_delete(request, pk):
    comment = get_object_or_404(
        FindingComment.objects.select_related('finding__engagement', 'author'),
        pk=pk,
    )
    finding = comment.finding
    if not finding.engagement.user_can_access(request.user):
        return HttpResponseForbidden('Not a member of this engagement.')
    if not comment.can_delete(request.user):
        messages.error(request, 'You cannot delete this comment.')
        return redirect('vulns:detail', pk=finding.pk)
    if request.method == 'POST':
        target_id = str(comment.pk)
        comment.delete()
        AuditLog.record(
            actor=request.user,
            action=AuditLog.Action.COMMENT_DELETE,
            target=target_id,
            details={'finding': finding.title},
            request=request,
        )
        messages.success(request, 'Comment deleted.')
        return redirect('vulns:detail', pk=finding.pk)
    return render(request, 'vulns/comment_confirm_delete.html', {
        'comment': comment, 'finding': finding,
    })


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

    # ── Step 2 of preview flow: confirm and commit pre-parsed payload ──
    if request.method == 'POST' and 'confirm_import' in request.POST:
        pending = request.session.pop('import_pending', None)
        if not pending or pending.get('engagement') != str(engagement.pk):
            messages.error(request, 'Import preview expired. Please re-upload.')
            return redirect('vulns:import', engagement_pk=engagement.pk)
        tool = pending['tool']
        new_items = pending['new']
        created = commit_import(engagement, request.user,tool, new_items)
        ActivityLog.objects.create(
            engagement=engagement, user=request.user,
            action=f'Imported {created} findings from {tool.capitalize()}',
        )
        messages.success(
            request,
            f'Imported {created} findings from {tool.capitalize()}. '
            f'{pending["skipped"]} duplicate(s) skipped.',
        )
        return redirect('vulns:list', engagement_pk=engagement_pk)

    # ── Step 1: upload + parse ──
    if request.method == 'POST':
        form = ToolImportForm(request.POST, request.FILES)
        if form.is_valid():
            tool = form.cleaned_data['tool']
            preview = form.cleaned_data.get('preview', False)
            content = request.FILES['file'].read()
            try:
                findings_data = PARSERS[tool](content)
            except Exception as e:
                messages.error(request, f'Import failed: {str(e)}')
                return redirect('vulns:import', engagement_pk=engagement_pk)

            new_items, dup_items = classify_import(engagement,findings_data)

            if preview:
                if len(new_items) + len(dup_items) > IMPORT_PREVIEW_LIMIT:
                    messages.error(
                        request,
                        f'Preview supports up to {IMPORT_PREVIEW_LIMIT} entries. '
                        f'Re-run without preview, or split the file.',
                    )
                    return redirect('vulns:import', engagement_pk=engagement_pk)
                request.session['import_pending'] = {
                    'engagement': str(engagement.pk),
                    'tool': tool,
                    'new': new_items,
                    'skipped': len(dup_items),
                }
                return render(request, 'vulns/import_preview.html', {
                    'engagement': engagement,
                    'tool': tool,
                    'new_items': new_items,
                    'dup_items': dup_items,
                })

            created = commit_import(engagement, request.user,tool, new_items)
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Imported {created} findings from {tool.capitalize()}',
            )
            msg = f'Imported {created} findings from {tool.capitalize()}.'
            if dup_items:
                msg += f' {len(dup_items)} duplicate(s) skipped.'
            messages.success(request, msg)
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
@engagement_edit_required
def finding_import_csv(request, engagement_pk):
    """Bulk CSV import. Two-step preview flow mirrors ``tool_import``.

    Header validation is strict; per-row errors are surfaced in the preview
    and those rows are skipped on commit. Dedup against existing engagement
    findings reuses ``classify_import``.
    """
    engagement = request.engagement

    # Step 2: confirm and commit pre-parsed payload.
    if request.method == 'POST' and 'confirm_import' in request.POST:
        pending = request.session.pop('csv_import_pending', None)
        if not pending or pending.get('engagement') != str(engagement.pk):
            messages.error(request, 'CSV import preview expired. Please re-upload.')
            return redirect('vulns:import_csv', engagement_pk=engagement.pk)
        new_items = pending['new']
        created = commit_import(engagement, request.user,'csv', new_items)
        ActivityLog.objects.create(
            engagement=engagement, user=request.user,
            action=f'Imported {created} findings from CSV',
        )
        messages.success(
            request,
            f'Imported {created} findings from CSV. '
            f'{pending["skipped"]} duplicate(s) skipped, '
            f'{pending["errored"]} row(s) had errors and were skipped.',
        )
        return redirect('vulns:list', engagement_pk=engagement_pk)

    # Step 1: upload + parse.
    if request.method == 'POST':
        form = CsvImportForm(request.POST, request.FILES)
        if form.is_valid():
            preview = form.cleaned_data.get('preview', True)
            content = request.FILES['file'].read()
            rows, row_errors, header_errors = parse_csv_findings(content)

            if header_errors:
                for err in header_errors:
                    messages.error(request, err)
                return render(request, 'vulns/import_csv.html', {
                    'form': form, 'engagement': engagement,
                    'columns': sorted(CSV_IMPORT_COLUMNS),
                    'required': sorted(CSV_IMPORT_REQUIRED),
                })

            new_items, dup_items = classify_import(engagement,rows)

            if preview:
                if len(new_items) + len(dup_items) > IMPORT_PREVIEW_LIMIT:
                    messages.error(
                        request,
                        f'Preview supports up to {IMPORT_PREVIEW_LIMIT} rows. '
                        f'Re-run without preview, or split the file.',
                    )
                    return redirect('vulns:import_csv', engagement_pk=engagement.pk)
                request.session['csv_import_pending'] = {
                    'engagement': str(engagement.pk),
                    'new': new_items,
                    'skipped': len(dup_items),
                    'errored': len(row_errors),
                }
                return render(request, 'vulns/import_csv_preview.html', {
                    'engagement': engagement,
                    'new_items': new_items,
                    'dup_items': dup_items,
                    'row_errors': row_errors,
                })

            if row_errors:
                for err in row_errors[:10]:
                    messages.warning(
                        request, f'Row {err["row"]}: {err["error"]} (skipped)',
                    )
                if len(row_errors) > 10:
                    messages.warning(
                        request,
                        f'… and {len(row_errors) - 10} more row error(s) skipped.',
                    )

            created = commit_import(engagement, request.user,'csv', new_items)
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Imported {created} findings from CSV',
            )
            msg = f'Imported {created} findings from CSV.'
            if dup_items:
                msg += f' {len(dup_items)} duplicate(s) skipped.'
            if row_errors:
                msg += f' {len(row_errors)} row(s) had errors.'
            messages.success(request, msg)
            return redirect('vulns:list', engagement_pk=engagement_pk)
    else:
        form = CsvImportForm()

    return render(request, 'vulns/import_csv.html', {
        'form': form, 'engagement': engagement,
        'columns': sorted(CSV_IMPORT_COLUMNS),
        'required': sorted(CSV_IMPORT_REQUIRED),
    })


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
def markdown_preview(request):
    """Render raw Markdown to sanitized HTML using the same pipeline as the
    finding/comment views. POST-only so request bodies don't end up in logs.
    """
    if request.method != 'POST':
        return HttpResponse(status=405)
    raw = request.POST.get('text', '')[:20000]
    from .templatetags.vulns_extras import render_markdown
    return HttpResponse(render_markdown(raw), content_type='text/html; charset=utf-8')


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

