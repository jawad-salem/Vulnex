from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from engagements.models import Engagement, ActivityLog
from vulns.models import Finding


@login_required
def home(request):
    engagements = Engagement.objects.all()
    findings = Finding.objects.all()
    recent_activity = ActivityLog.objects.select_related('engagement', 'user')[:20]

    # Stats
    total_engagements = engagements.count()
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

    status_counts = dict(
        findings.values_list('status').annotate(count=Count('status')).values_list('status', 'count')
    )

    # Recent engagements
    recent_engagements = engagements[:5]

    # Top critical/high findings
    urgent_findings = findings.filter(
        severity__in=['critical', 'high'], status__in=['open', 'confirmed']
    ).select_related('engagement')[:10]

    context = {
        'total_engagements': total_engagements,
        'active_engagements': active_engagements,
        'total_findings': total_findings,
        'severity_counts': severity_counts,
        'status_counts': status_counts,
        'recent_engagements': recent_engagements,
        'urgent_findings': urgent_findings,
        'recent_activity': recent_activity,
    }
    return render(request, 'dashboard/home.html', context)

