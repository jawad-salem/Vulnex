"""Read models for engagement workflow screens."""
from django.db.models import Count, Q
from django.urls import reverse
from vulns.models import Finding
from vulns.services.workflow import visible_findings


def engagement_work_queue(engagement, user):
    if engagement.user_is_client(user) and user.role != 'admin':
        return []
    if not engagement.user_can_access(user):
        return []
    findings = visible_findings(user, engagement.findings.all())
    counts = findings.aggregate(
        review=Count('pk', filter=Q(review_state=Finding.ReviewState.IN_REVIEW)),
        drafts=Count('pk', filter=Q(review_state__in=[Finding.ReviewState.DRAFT, Finding.ReviewState.CHANGES_REQUESTED])),
        retest=Count('pk', filter=Q(status=Finding.Status.REMEDIATED, retest_status=Finding.RetestStatus.NOT_RETESTED)),
    )
    checklist = engagement.checklist_items.aggregate(
        total=Count('pk'), done=Count('pk', filter=Q(status__in=['completed', 'not_applicable']))
    )
    findings_url = reverse('vulns:list', args=[engagement.pk])
    scope_ready = engagement.roe_signed_off
    rows = [
        {'label': 'Scope confirmation', 'value': 'Locked' if scope_ready else 'Confirmation pending',
         'description': 'Approved targets and rules of engagement.' if scope_ready else 'Confirm targets and rules with the engagement lead.',
         'url': reverse('engagements:detail', args=[engagement.pk]) + '#scope',
         'action': 'View scope', 'attention': not scope_ready},
        {'label': 'Testing coverage', 'value': f"{checklist['done']} / {checklist['total']}",
         'description': 'Completed or not applicable checks.' if checklist['total'] else 'Apply a methodology to track testing coverage.',
         'url': reverse('methodology:dashboard', args=[engagement.pk]), 'action': 'Open testing', 'attention': not checklist['total']},
        {'label': 'Review queue', 'value': str(counts['review']),
         'description': f"{counts['drafts']} findings still in draft or requiring changes.",
         'url': findings_url + '?review=in_review', 'action': 'Review findings', 'attention': bool(counts['review'])},
        {'label': 'Retest queue', 'value': str(counts['retest']),
         'description': 'Remediated findings awaiting their first verification.',
         'url': findings_url + '?status=remediated&retest=not_retested', 'action': 'Open retests', 'attention': bool(counts['retest'])},
    ]

    if engagement.engagement_type == 'red_team':
        rows.insert(1, {'label': 'Attack paths & objectives', 'value': str(engagement.attack_paths.count()),
                       'description': 'Connect entry points to objectives and link supporting findings.',
                       'url': reverse('engagements:attack_path_list', args=[engagement.pk]),
                       'action': 'Open attack paths', 'attention': not engagement.attack_paths.exists()})
    return rows


def attack_path_context(path, user):
    """Graph checks and a stable dependency-ordered narrative, including legacy cycles."""
    nodes = list(path.nodes.all())
    edges = list(path.edges.select_related('from_node', 'to_node', 'finding'))
    visible_ids = set(visible_findings(user).filter(pk__in=[e.finding_id for e in edges if e.finding_id]).values_list('pk', flat=True))
    for edge in edges:
        if edge.finding_id not in visible_ids:
            edge.finding = None
    adjacency = {n.pk: [] for n in nodes}
    indegree = {n.pk: 0 for n in nodes}
    for edge in edges:
        adjacency[edge.from_node_id].append(edge.to_node_id)
        indegree[edge.to_node_id] += 1
    pending = [n.pk for n in nodes if not indegree[n.pk]]
    ordered = []
    while pending:
        current = pending.pop(0)
        ordered.append(current)
        for target in adjacency[current]:
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    ranks = {pk: i for i, pk in enumerate(ordered)}
    edges.sort(key=lambda edge: (ranks.get(edge.from_node_id, len(nodes)), ranks.get(edge.to_node_id, len(nodes))))
    entrypoints = [n for n in nodes if n.kind == 'entrypoint']
    objectives = [n for n in nodes if n.kind == 'objective']
    reached = set(n.pk for n in entrypoints)
    pending = list(reached)
    while pending:
        for target in adjacency[pending.pop()]:
            if target not in reached:
                reached.add(target)
                pending.append(target)
    issues = []
    if not entrypoints: issues.append('Add an entry point to show where the path starts.')
    if not objectives: issues.append('Add an objective to explain the intended outcome.')
    if len(ordered) != len(nodes): issues.append('This diagram contains a cycle; remove the return connection to restore a directed path.')
    if objectives and any(n.pk not in reached for n in objectives): issues.append('Connect every objective to an entry point.')
    if nodes and any(n.pk not in reached for n in nodes): issues.append('Some nodes are not reachable from an entry point.')
    return {'path_nodes': nodes, 'path_edges': edges, 'path_issues': issues,
            'path_objectives': objectives, 'path_connected': bool(nodes) and not issues}
