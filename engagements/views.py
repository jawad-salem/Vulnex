from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from .models import Engagement, ActivityLog
from .forms import EngagementForm, EngagementNoteForm
from accounts.decorators import role_required


@login_required
def engagement_list(request):
    engagements = Engagement.objects.all()
    status_filter = request.GET.get('status')
    type_filter = request.GET.get('type')
    search = request.GET.get('q')

    if status_filter:
        engagements = engagements.filter(status=status_filter)
    if type_filter:
        engagements = engagements.filter(engagement_type=type_filter)
    if search:
        engagements = engagements.filter(
            Q(name__icontains=search) | Q(client_name__icontains=search)
        )

    context = {
        'engagements': engagements,
        'status_choices': Engagement.Status.choices,
        'type_choices': Engagement.EngagementType.choices,
        'current_status': status_filter,
        'current_type': type_filter,
        'search_query': search or '',
    }
    return render(request, 'engagements/list.html', context)


@login_required
def engagement_detail(request, pk):
    engagement = get_object_or_404(Engagement, pk=pk)
    note_form = EngagementNoteForm()

    if request.method == 'POST' and 'add_note' in request.POST:
        note_form = EngagementNoteForm(request.POST)
        if note_form.is_valid():
            note = note_form.save(commit=False)
            note.engagement = engagement
            note.author = request.user
            note.save()
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action='Added a note'
            )
            messages.success(request, 'Note added.')
            return redirect('engagements:detail', pk=pk)

    context = {
        'engagement': engagement,
        'note_form': note_form,
        'notes': engagement.notes.select_related('author')[:20],
        'findings': engagement.findings.all()[:10],
        'activity': engagement.activity_logs.select_related('user')[:15],
    }
    return render(request, 'engagements/detail.html', context)


@login_required
@role_required('admin', 'pentester')
def engagement_create(request):
    if request.method == 'POST':
        form = EngagementForm(request.POST)
        if form.is_valid():
            engagement = form.save(commit=False)
            engagement.created_by = request.user
            engagement.save()
            form.save_m2m()
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action='Created engagement'
            )
            messages.success(request, f'Engagement "{engagement.name}" created.')
            return redirect('engagements:detail', pk=engagement.pk)
    else:
        form = EngagementForm()
    return render(request, 'engagements/form.html', {'form': form, 'title': 'New engagement'})


@login_required
@role_required('admin', 'pentester')
def engagement_edit(request, pk):
    engagement = get_object_or_404(Engagement, pk=pk)
    if request.method == 'POST':
        form = EngagementForm(request.POST, instance=engagement)
        if form.is_valid():
            form.save()
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action='Updated engagement'
            )
            messages.success(request, 'Engagement updated.')
            return redirect('engagements:detail', pk=pk)
    else:
        form = EngagementForm(instance=engagement)
    return render(request, 'engagements/form.html', {'form': form, 'title': 'Edit engagement', 'engagement': engagement})


@login_required
@role_required('admin')
def engagement_delete(request, pk):
    engagement = get_object_or_404(Engagement, pk=pk)
    if request.method == 'POST':
        name = engagement.name
        engagement.delete()
        messages.success(request, f'Engagement "{name}" deleted.')
        return redirect('engagements:list')
    return render(request, 'engagements/confirm_delete.html', {'engagement': engagement})


@login_required
@role_required('admin', 'pentester')
def engagement_update_status(request, pk):
    engagement = get_object_or_404(Engagement, pk=pk)
    new_status = request.POST.get('status')
    if new_status and new_status in dict(Engagement.Status.choices):
        old_status = engagement.get_status_display()
        engagement.status = new_status
        engagement.save(update_fields=['status', 'updated_at'])
        ActivityLog.objects.create(
            engagement=engagement, user=request.user,
            action=f'Changed status from {old_status} to {engagement.get_status_display()}'
        )
        messages.success(request, f'Status updated to {engagement.get_status_display()}.')
    return redirect('engagements:detail', pk=pk)

