from django.db import connection
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from credentials.models import Credential
from engagements.models import Engagement
from vulns.models import Finding
from recon.models import DiscoveredHost
from .selectors import workspace_context


@login_required
def home(request):
    return render(request, 'dashboard/home.html', workspace_context(request.user, request.GET))


def _is_postgres():
    return connection.vendor == 'postgresql'


def _rank_engagements(qs, query):
    """Postgres: weighted FTS over name/client/description with relevance ranking.
    SQLite: icontains across the same fields.
    """
    if _is_postgres():
        from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
        vector = (
            SearchVector('name', weight='A')
            + SearchVector('client__name', weight='B')
            + SearchVector('description', weight='C')
        )
        sq = SearchQuery(query)
        return (
            qs.annotate(rank=SearchRank(vector, sq))
            .filter(rank__gt=0)
            .order_by('-rank')
        )
    return qs.filter(
        Q(name__icontains=query)
        | Q(client__name__icontains=query)
        | Q(description__icontains=query)
    )


def _rank_findings(qs, query):
    if _is_postgres():
        from django.contrib.postgres.search import SearchQuery, SearchRank, SearchVector
        vector = (
            SearchVector('title', weight='A')
            + SearchVector('host', 'url', 'cwe_id', weight='B')
            + SearchVector('description', weight='C')
        )
        sq = SearchQuery(query)
        return (
            qs.annotate(rank=SearchRank(vector, sq))
            .filter(rank__gt=0)
            .order_by('-rank', '-updated_at')
        )
    return qs.filter(
        Q(title__icontains=query)
        | Q(description__icontains=query)
        | Q(host__icontains=query)
        | Q(url__icontains=query)
        | Q(cwe_id__icontains=query)
    )


def _rank_hosts(qs, query):
    # Hostnames and IPs are short structured identifiers — Postgres FTS treats
    # `vault.acme.example.com` as a single token and won't match "vault", so
    # icontains is the right tool here regardless of vendor.
    return qs.filter(
        Q(hostname__icontains=query) | Q(ip_address__icontains=query)
    )


def _rank_credentials(qs, query):
    # Credential fields (usernames, services, hash types) are short identifiers
    # where substring matching is more useful than tokenized FTS.
    return qs.filter(
        Q(username__icontains=query)
        | Q(service__icontains=query)
        | Q(hash_type__icontains=query)
        | Q(source__icontains=query)
        | Q(notes__icontains=query)
    )


@login_required
def global_search(request):
    """Search across engagements, findings, hosts, and credentials.

    On Postgres, uses ``SearchVector`` / ``SearchQuery`` / ``SearchRank`` for
    relevance-weighted full-text search; on SQLite (dev) it falls back to
    ``icontains`` over the same fields. Results are scoped to the viewer's
    engagement memberships (admins see all). Clients never see credentials
    or recon hosts and only see APPROVED findings.
    """
    query = (request.GET.get('q') or '').strip()
    results = {
        'engagements': [], 'findings': [], 'hosts': [], 'credentials': [],
        'query': query,
    }

    if not query or len(query) < 2:
        return render(request, 'dashboard/search.html', results)

    is_admin = request.user.role == 'admin'
    is_client = request.user.is_client

    if is_admin:
        eng_qs = Engagement.objects.all()
    else:
        eng_ids = request.user.memberships.values_list('engagement_id', flat=True)
        eng_qs = Engagement.objects.filter(pk__in=eng_ids)

    results['engagements'] = list(_rank_engagements(eng_qs, query)[:15])

    finding_qs = Finding.objects.filter(engagement__in=eng_qs)
    if is_client:
        finding_qs = finding_qs.filter(review_state=Finding.ReviewState.APPROVED)
    results['findings'] = list(
        _rank_findings(finding_qs, query).select_related('engagement')[:25]
    )

    # Clients cannot access recon or credentials at all.
    if not is_client:
        results['hosts'] = list(
            _rank_hosts(
                DiscoveredHost.objects.filter(engagement__in=eng_qs), query,
            ).select_related('engagement')[:15]
        )
        results['credentials'] = list(
            _rank_credentials(
                Credential.objects.filter(engagement__in=eng_qs), query,
            ).select_related('engagement', 'host')[:15]
        )

    results['total'] = (
        len(results['engagements']) + len(results['findings'])
        + len(results['hosts']) + len(results['credentials'])
    )
    return render(request, 'dashboard/search.html', results)
