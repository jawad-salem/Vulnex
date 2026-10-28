"""Bounded, permission-scoped dashboard queues and summary data."""
from datetime import timedelta
from django.core.paginator import Paginator
from django.db.models import Case, Count, IntegerField, Q, Value, When
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from vulns.models import Finding
from vulns.services.workflow import visible_findings


def workspace_context(user, params):
    engagements = Engagement.objects.all()
    if not user.is_admin:
        engagements = engagements.filter(pk__in=user.memberships.values('engagement_id'))
    findings = visible_findings(user)
    today = timezone.localdate()
    opened = findings.exclude(status__in=Finding.SLA_CLOSED_STATUSES)
    mine = opened.filter(assigned_to=user)
    review = findings.filter(review_state='in_review')
    retest = findings.filter(status='remediated', retest_status='not_retested')
    if not user.is_admin:
        review = review.filter(engagement_id__in=user.memberships.filter(role__in=['lead', 'reviewer']).values('engagement_id'))
        retest = retest.filter(engagement_id__in=user.memberships.filter(role__in=['lead', 'pentester']).values('engagement_id'))
    queues = {'attention': opened}
    if not user.is_client:
        queues.update(mine=mine, review=review, retest=retest)
    selected = params.get('queue', 'attention' if user.is_client else 'mine')
    if selected not in queues:
        selected = 'attention'
    labels = {'attention': 'Open findings', 'mine': 'Assigned to me', 'review': 'Ready for your review', 'retest': 'Ready for retest'}
    queue_links = [{'key': key, 'label': labels[key], 'count': qs.count()} for key, qs in queues.items()]
    ordered = queues[selected].select_related('engagement', 'assigned_to').annotate(
        overdue_rank=Case(When(due_date__lt=today, then=Value(0)), default=Value(1), output_field=IntegerField()),
    ).order_by('overdue_rank', '-cvss_score', '-created_at', '-pk')
    page = Paginator(ordered, 15).get_page(params.get('page'))
    hour = timezone.localtime().hour
    # Counts must use the same visibility rules as finding links, including client memberships.
    recent = engagements.select_related('client').annotate(
        visible_finding_count=Count('findings', filter=Q(findings__in=findings)),
    ).order_by('-updated_at')[:5]
    internal_ids = user.memberships.exclude(role='client').values('engagement_id')
    activity = ActivityLog.objects.filter(engagement__in=engagements)
    if not user.is_admin:
        activity = activity.filter(engagement_id__in=internal_ids)
    return {
        'greeting': 'Good morning' if hour < 12 else 'Good afternoon' if hour < 18 else 'Good evening',
        'active_engagements': engagements.exclude(status__in=['completed', 'cancelled']).count(),
        'in_test_count': engagements.filter(status__in=['recon', 'scanning', 'exploitation', 'post_exploitation']).count(),
        'open_findings_count': opened.count(),
        'critical_open': opened.filter(severity='critical').count(),
        'attention_count': opened.filter(severity__in=['critical', 'high']).count(),
        'awaiting_review': review.count() if not user.is_client else 0,
        'overdue_count': opened.filter(due_date__lt=today).count(),
        'due_soon_count': opened.filter(due_date__gte=today, due_date__lte=today + timedelta(days=3)).count(),
        'my_assigned_count': mine.count(),
        'my_assigned_overdue': mine.filter(due_date__lt=today).count(),
        'recent_engagements': recent,
        'recent_activity': activity.select_related('engagement', 'user')[:12],
        'triage_findings': page, 'page_obj': page,
        'queue_links': queue_links, 'selected_queue': selected, 'queue_label': labels[selected],
        'query_string': 'queue=' + selected + '&',
    }
