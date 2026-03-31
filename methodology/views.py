from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from .models import Methodology, EngagementChecklist, ChecklistItem
from accounts.decorators import role_required


@login_required
def methodology_dashboard(request, engagement_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
    methodologies = Methodology.objects.prefetch_related('categories__items').all()

    # Get or create checklist progress for this engagement
    checklist_progress = {}
    for ec in engagement.checklist_items.select_related('checklist_item').all():
        checklist_progress[ec.checklist_item_id] = ec

    context = {
        'engagement': engagement,
        'methodologies': methodologies,
        'checklist_progress': checklist_progress,
    }
    return render(request, 'methodology/dashboard.html', context)


@login_required
@role_required('admin', 'pentester')
def apply_methodology(request, engagement_pk, methodology_pk):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
    methodology = get_object_or_404(Methodology, pk=methodology_pk)

    items = ChecklistItem.objects.filter(category__methodology=methodology)
    created = 0
    for item in items:
        _, was_created = EngagementChecklist.objects.get_or_create(
            engagement=engagement,
            checklist_item=item,
        )
        if was_created:
            created += 1

    ActivityLog.objects.create(
        engagement=engagement, user=request.user,
        action=f'Applied methodology: {methodology.name} ({created} items)'
    )
    messages.success(request, f'Applied "{methodology.name}" — {created} checklist items added.')
    return redirect('methodology:dashboard', engagement_pk=engagement_pk)


@login_required
@role_required('admin', 'pentester')
def update_checklist_item(request, engagement_pk, item_id):
    engagement = get_object_or_404(Engagement, pk=engagement_pk)
    checklist_item = get_object_or_404(ChecklistItem, pk=item_id)

    ec, _ = EngagementChecklist.objects.get_or_create(
        engagement=engagement,
        checklist_item=checklist_item,
    )

    new_status = request.POST.get('status')
    notes = request.POST.get('notes', '')

    if new_status and new_status in dict(EngagementChecklist.ItemStatus.choices):
        ec.status = new_status
        ec.notes = notes
        if new_status == 'completed':
            ec.completed_by = request.user
            ec.completed_at = timezone.now()
        ec.save()

    return redirect('methodology:dashboard', engagement_pk=engagement_pk)

