from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import JsonResponse, HttpResponseBadRequest

from accounts.decorators import engagement_access, engagement_edit_required
from engagements.models import ActivityLog
from recon.models import DiscoveredHost
from .models import Credential
from .forms import CredentialForm


@login_required
@engagement_access(allow_client=False)
def credential_list(request, engagement_pk):
    engagement = request.engagement
    credentials = engagement.credentials.select_related('host', 'found_by').all()

    type_filter = request.GET.get('type')
    status_filter = request.GET.get('status')
    host_filter = request.GET.get('host')
    search = request.GET.get('q')

    if type_filter:
        credentials = credentials.filter(credential_type=type_filter)
    if status_filter:
        credentials = credentials.filter(status=status_filter)
    if host_filter:
        credentials = credentials.filter(host_id=host_filter)
    if search:
        credentials = credentials.filter(
            Q(username__icontains=search)
            | Q(service__icontains=search)
            | Q(source__icontains=search)
            | Q(notes__icontains=search)
        )

    paginator = Paginator(credentials, 25)
    page = paginator.get_page(request.GET.get('page'))

    qs_parts = []
    for key, value in (('type', type_filter), ('status', status_filter),
                       ('host', host_filter), ('q', search)):
        if value:
            qs_parts.append(f'{key}={value}')
    query_string = '&'.join(qs_parts) + ('&' if qs_parts else '')

    hosts = DiscoveredHost.objects.filter(engagement=engagement).order_by('hostname')

    context = {
        'engagement': engagement,
        'credentials': page,
        'page_obj': page,
        'query_string': query_string,
        'type_choices': Credential.Type.choices,
        'status_choices': Credential.Status.choices,
        'hosts': hosts,
        'type_filter': type_filter,
        'status_filter': status_filter,
        'host_filter': host_filter,
        'search': search,
        'can_edit': request.eng_role in ('admin', 'lead', 'pentester'),
    }
    return render(request, 'credentials/list.html', context)


@login_required
@engagement_edit_required
def credential_create(request, engagement_pk):
    engagement = request.engagement
    if request.method == 'POST':
        form = CredentialForm(request.POST, engagement=engagement)
        if form.is_valid():
            credential = form.save(commit=False)
            credential.engagement = engagement
            credential.found_by = request.user
            credential.save()

            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Added credential: {credential.get_credential_type_display()} '
                       f'for {credential.username or "(no user)"}'
                       f'{" on " + credential.host.hostname if credential.host else ""}',
            )
            messages.success(request, 'Credential added.')
            return redirect('credentials:list', engagement_pk=engagement.pk)
    else:
        form = CredentialForm(engagement=engagement)

    return render(request, 'credentials/form.html', {
        'form': form, 'engagement': engagement, 'title': 'Add credential',
    })


@login_required
@engagement_edit_required
def credential_edit(request, engagement_pk, pk):
    engagement = request.engagement
    credential = get_object_or_404(Credential, pk=pk, engagement=engagement)
    if request.method == 'POST':
        form = CredentialForm(request.POST, instance=credential, engagement=engagement)
        if form.is_valid():
            form.save()
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Updated credential for {credential.username or "(no user)"}',
            )
            messages.success(request, 'Credential updated.')
            return redirect('credentials:list', engagement_pk=engagement.pk)
    else:
        form = CredentialForm(instance=credential, engagement=engagement)

    return render(request, 'credentials/form.html', {
        'form': form, 'engagement': engagement, 'credential': credential,
        'title': f'Edit credential — {credential.username or "(no user)"}',
    })


@login_required
@engagement_edit_required
def credential_delete(request, engagement_pk, pk):
    engagement = request.engagement
    credential = get_object_or_404(Credential, pk=pk, engagement=engagement)
    if request.method == 'POST':
        label = credential.username or credential.get_credential_type_display()
        credential.delete()
        ActivityLog.objects.create(
            engagement=engagement, user=request.user,
            action=f'Deleted credential: {label}',
        )
        messages.success(request, 'Credential deleted.')
        return redirect('credentials:list', engagement_pk=engagement.pk)
    return render(request, 'credentials/confirm_delete.html', {
        'credential': credential, 'engagement': engagement,
    })


@login_required
@engagement_access(allow_client=False)
def credential_reveal(request, engagement_pk, pk):
    """Return the plaintext secret as JSON. POST-only and logged.

    We record every reveal so a lead can see who pulled a password out of the
    vault — think of it as the audit trail for a KeePass group.
    """
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')

    engagement = request.engagement
    credential = get_object_or_404(Credential, pk=pk, engagement=engagement)

    ActivityLog.objects.create(
        engagement=engagement, user=request.user,
        action=f'Revealed credential for {credential.username or "(no user)"}',
    )

    return JsonResponse({'secret': credential.secret})
