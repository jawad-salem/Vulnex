from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from engagements.models import Engagement, ActivityLog
from .models import Methodology, EngagementChecklist, ChecklistItem
from accounts.decorators import engagement_access, engagement_edit_required


@login_required
@engagement_access(allow_client=False)
def methodology_dashboard(request, engagement_pk):
    engagement = request.engagement
    methodologies = Methodology.objects.prefetch_related('categories__items').all()

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
@engagement_edit_required
def apply_methodology(request, engagement_pk, methodology_pk):
    engagement = request.engagement
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
@engagement_edit_required
def update_checklist_item(request, engagement_pk, item_id):
    engagement = request.engagement
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
