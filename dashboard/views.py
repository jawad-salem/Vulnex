from datetime import timedelta
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from vulns.models import Finding
from recon.models import DiscoveredHost
from reports.generator import calculate_engagement_risk_score, _risk_label


@login_required
def home(request):
    # Scope data to user's engagements (admins see all)
    if request.user.role == 'admin':
        engagements = Engagement.objects.all()
        findings = Finding.objects.all()
        recent_activity = ActivityLog.objects.select_related('engagement', 'user')[:20]
    else:
        user_engagement_ids = request.user.memberships.values_list('engagement_id', flat=True)
        engagements = Engagement.objects.filter(pk__in=user_engagement_ids)
        findings = Finding.objects.filter(engagement_id__in=user_engagement_ids)
        recent_activity = ActivityLog.objects.filter(
            engagement_id__in=user_engagement_ids
        ).select_related('engagement', 'user')[:20]

    # Clients only see approved findings in their dashboard stats
    if request.user.is_client:
        findings = findings.filter(review_state=Finding.ReviewState.APPROVED)

    # Stats
    active_engagements = engagements.exclude(
        status__in=['completed', 'cancelled']
    ).count()
    total_findings = findings.count()

    severity_counts = {
        'critical': findings.filter(severity='critical').count(),
        'high': findings.filter(severity='high').count(),
        'medium': findings.filter(severity='medium').count(),
        'low': findings.filter(severity='low').count(),
        'info': findings.filter(severity='info').count(),
    }

    # Status distribution for chart
    status_counts = {
        'open': findings.filter(status='open').count(),
        'confirmed': findings.filter(status='confirmed').count(),
        'remediated': findings.filter(status='remediated').count(),
        'false_positive': findings.filter(status='false_positive').count(),
        'accepted': findings.filter(status='accepted').count(),
    }

    # Findings over time (last 30 days, grouped by date)
    findings_over_time = list(
        findings.annotate(date=TruncDate('created_at'))
        .values('date')
        .annotate(count=Count('id'))
        .order_by('date')
    )
    timeline_labels = [entry['date'].strftime('%b %d') for entry in findings_over_time]
    timeline_data = [entry['count'] for entry in findings_over_time]

    # Top engagements by finding count
    top_engagements = list(
        engagements.annotate(fcount=Count('findings'))
        .filter(fcount__gt=0)
        .order_by('-fcount')[:6]
    )
    top_eng_labels = [e.name[:20] for e in top_engagements]
    top_eng_data = [e.fcount for e in top_engagements]

    recent_engagements = engagements[:5]

    urgent_findings = findings.filter(
        severity__in=['critical', 'high'], status__in=['open', 'confirmed']
    ).select_related('engagement')[:10]

    # SLA tracking — overdue + due-soon findings
    today = timezone.now().date()
    open_findings = findings.exclude(status__in=Finding.SLA_CLOSED_STATUSES)
    overdue_findings = list(
        open_findings.filter(due_date__lt=today)
        .select_related('engagement')
        .order_by('due_date')[:10]
    )
    overdue_count = open_findings.filter(due_date__lt=today).count()
    due_soon_count = open_findings.filter(
        due_date__gte=today, due_date__lte=today + timedelta(days=3),
    ).count()

    # Findings currently assigned to the logged-in user
    my_open_findings = open_findings.filter(assigned_to=request.user)
    my_assigned_count = my_open_findings.count()
    my_assigned_overdue = my_open_findings.filter(due_date__lt=today).count()

    # Overall risk score
    overall_risk_score = calculate_engagement_risk_score(findings)
    risk_label, risk_color = _risk_label(overall_risk_score)

    # Per-engagement risk scores (for active engagements)
    active_engs = engagements.exclude(status__in=['completed', 'cancelled'])[:10]
    engagement_risks = []
    for eng in active_engs:
        eng_findings = findings.filter(engagement=eng)
        eng_score = calculate_engagement_risk_score(eng_findings)
        eng_label, eng_color = _risk_label(eng_score)
        engagement_risks.append({
            'engagement': eng,
            'score': eng_score,
            'label': eng_label,
            'color': eng_color,
            'finding_count': eng_findings.count(),
        })
    engagement_risks.sort(key=lambda x: x['score'], reverse=True)

    context = {
        'active_engagements': active_engagements,
        'total_findings': total_findings,
        'severity_counts': severity_counts,
        'status_counts': status_counts,
        'timeline_labels': timeline_labels,
        'timeline_data': timeline_data,
        'top_eng_labels': top_eng_labels,
        'top_eng_data': top_eng_data,
        'recent_engagements': recent_engagements,
        'urgent_findings': urgent_findings,
        'recent_activity': recent_activity,
        'overall_risk_score': overall_risk_score,
        'risk_label': risk_label,
        'risk_color': risk_color,
        'engagement_risks': engagement_risks,
        'overdue_findings': overdue_findings,
        'overdue_count': overdue_count,
        'due_soon_count': due_soon_count,
        'my_assigned_count': my_assigned_count,
        'my_assigned_overdue': my_assigned_overdue,
        'today': today,
    }
    return render(request, 'dashboard/home.html', context)


@login_required
def global_search(request):
    """Search across engagements, findings, and discovered hosts.

    Scopes by engagement membership (admins see everything). Clients get the
    same scope rules as elsewhere — they only see engagements they're part of,
    and are excluded from recon results.
    """
    query = (request.GET.get('q') or '').strip()
    results = {'engagements': [], 'findings': [], 'hosts': [], 'query': query}

    if not query or len(query) < 2:
        return render(request, 'dashboard/search.html', results)

    is_admin = request.user.role == 'admin'
    is_client = request.user.is_client

    if is_admin:
        eng_qs = Engagement.objects.all()
    else:
        eng_ids = request.user.memberships.values_list('engagement_id', flat=True)
        eng_qs = Engagement.objects.filter(pk__in=eng_ids)

    results['engagements'] = list(
        eng_qs.filter(
            Q(name__icontains=query)
            | Q(client_name__icontains=query)
            | Q(description__icontains=query)
        )[:15]
    )

    finding_qs = Finding.objects.filter(engagement__in=eng_qs)
    if is_client:
        finding_qs = finding_qs.filter(review_state=Finding.ReviewState.APPROVED)
    results['findings'] = list(
        finding_qs.filter(
            Q(title__icontains=query)
            | Q(description__icontains=query)
            | Q(host__icontains=query)
            | Q(url__icontains=query)
            | Q(cwe_id__icontains=query)
        )
        .select_related('engagement')[:25]
    )

    # Clients cannot access recon at all — skip hosts entirely
    if not is_client:
        results['hosts'] = list(
            DiscoveredHost.objects.filter(engagement__in=eng_qs)
            .filter(Q(hostname__icontains=query) | Q(ip_address__icontains=query))
            .select_related('engagement')[:15]
        )

    results['total'] = (
        len(results['engagements']) + len(results['findings']) + len(results['hosts'])
    )
    return render(request, 'dashboard/search.html', results)
