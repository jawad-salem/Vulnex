from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.db.models.functions import TruncDate
from engagements.models import Engagement, ActivityLog
from vulns.models import Finding


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
    }
    return render(request, 'dashboard/home.html', context)
