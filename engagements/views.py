from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.paginator import Paginator
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from .models import Engagement, EngagementMember, Invitation, ActivityLog
from .forms import EngagementForm, EngagementNoteForm
from reports.generator import calculate_engagement_risk_score, _risk_label
from accounts.decorators import role_required, engagement_access, engagement_edit_required
from accounts.models import AuditLog


@login_required
def engagement_list(request):
    if request.user.role == 'admin':
        engagements = Engagement.objects.all()
    else:
        engagements = Engagement.objects.filter(
            members__user=request.user
        ).distinct()

    total_count = engagements.count()
    active_count = engagements.exclude(
        status__in=[Engagement.Status.COMPLETED, Engagement.Status.CANCELLED]
    ).count()
    completed_count = engagements.filter(status=Engagement.Status.COMPLETED).count()

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

    paginator = Paginator(engagements, 15)
    page = paginator.get_page(request.GET.get('page'))

    qs_parts = []
    if status_filter:
        qs_parts.append(f'status={status_filter}')
    if type_filter:
        qs_parts.append(f'type={type_filter}')
    if search:
        qs_parts.append(f'q={search}')
    query_string = '&'.join(qs_parts) + ('&' if qs_parts else '')

    context = {
        'engagements': page,
        'page_obj': page,
        'query_string': query_string,
        'status_choices': Engagement.Status.choices,
        'type_choices': Engagement.EngagementType.choices,
        'current_status': status_filter,
        'current_type': type_filter,
        'search_query': search or '',
        'total_count': total_count,
        'active_count': active_count,
        'completed_count': completed_count,
    }
    return render(request, 'engagements/list.html', context)


@login_required
@engagement_access(allow_client=True)
def engagement_detail(request, pk):
    engagement = request.engagement
    is_client = request.eng_role == 'client'
    note_form = EngagementNoteForm()

    if request.method == 'POST' and 'add_note' in request.POST and not is_client:
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

    # Get team members for display
    members = engagement.members.select_related('user').all()
    pending_invitations = engagement.invitations.filter(status='pending')

    # Risk score — clients only see approved findings everywhere
    all_findings = engagement.findings.all()
    if is_client:
        from vulns.models import Finding
        all_findings = all_findings.filter(review_state=Finding.ReviewState.APPROVED)
    risk_score = calculate_engagement_risk_score(all_findings)
    risk_label_text, risk_color = _risk_label(risk_score)

    context = {
        'engagement': engagement,
        'note_form': note_form,
        'notes': engagement.notes.select_related('author')[:20] if not is_client else [],
        'findings': all_findings[:10],
        'activity': engagement.activity_logs.select_related('user')[:15] if not is_client else [],
        'members': members,
        'pending_invitations': pending_invitations,
        'is_client': is_client,
        'can_edit': request.eng_role in ('admin', 'lead', 'pentester'),
        'can_manage': request.eng_role in ('admin', 'lead'),
        'risk_score': risk_score,
        'risk_label': risk_label_text,
        'risk_color': risk_color,
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
            # Auto-add creator as Lead
            EngagementMember.objects.create(
                engagement=engagement,
                user=request.user,
                role=EngagementMember.Role.LEAD,
            )
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action='Created engagement'
            )
            AuditLog.record(
                actor=request.user,
                action=AuditLog.Action.ENGAGEMENT_CREATE,
                target=engagement.name,
                details={'client': engagement.client_name, 'type': engagement.engagement_type},
                request=request,
            )
            messages.success(request, f'Engagement "{engagement.name}" created.')
            return redirect('engagements:detail', pk=engagement.pk)
    else:
        form = EngagementForm()
    return render(request, 'engagements/form.html', {'form': form, 'title': 'New engagement'})


@login_required
@engagement_edit_required
def engagement_edit(request, pk):
    engagement = request.engagement
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
@engagement_access()
def engagement_delete(request, pk):
    engagement = request.engagement
    # Only lead or global admin can delete
    if not engagement.user_is_lead(request.user):
        messages.error(request, 'Only the engagement lead can delete this.')
        return redirect('engagements:detail', pk=pk)
    if request.method == 'POST':
        name = engagement.name
        client_name = engagement.client_name
        engagement.delete()
        AuditLog.record(
            actor=request.user,
            action=AuditLog.Action.ENGAGEMENT_DELETE,
            target=name,
            details={'client': client_name},
            request=request,
        )
        messages.success(request, f'Engagement "{name}" deleted.')
        return redirect('engagements:list')
    return render(request, 'engagements/confirm_delete.html', {'engagement': engagement})


@login_required
@engagement_edit_required
def engagement_update_status(request, pk):
    engagement = request.engagement
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


# ── Team management ──

@login_required
def invite_member(request, pk):
    engagement = get_object_or_404(Engagement, pk=pk)
    if not engagement.user_is_lead(request.user):
        messages.error(request, 'Only the lead can invite members.')
        return redirect('engagements:detail', pk=pk)

    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        role = request.POST.get('role', 'pentester')

        if not email:
            messages.error(request, 'Email is required.')
            return redirect('engagements:detail', pk=pk)

        if role not in dict(EngagementMember.Role.choices):
            messages.error(request, 'Invalid role.')
            return redirect('engagements:detail', pk=pk)

        # Check if already a member
        from accounts.models import User
        existing_user = User.objects.filter(email=email).first()
        if existing_user and engagement.members.filter(user=existing_user).exists():
            messages.warning(request, f'{email} is already a member.')
            return redirect('engagements:detail', pk=pk)

        # Check for duplicate pending invitation
        if engagement.invitations.filter(email=email, status='pending').exists():
            messages.warning(request, f'An invitation to {email} is already pending.')
            return redirect('engagements:detail', pk=pk)

        invitation = Invitation.objects.create(
            engagement=engagement,
            email=email,
            role=role,
            invited_by=request.user,
        )

        # If user already exists, auto-accept
        if existing_user:
            with transaction.atomic():
                EngagementMember.objects.create(
                    engagement=engagement,
                    user=existing_user,
                    role=role,
                )
                invitation.status = 'accepted'
                invitation.save()
            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Added {existing_user} as {invitation.get_role_display()}'
            )
            AuditLog.record(
                actor=request.user,
                action=AuditLog.Action.INVITATION_ACCEPTED,
                target=email,
                details={
                    'engagement': engagement.name,
                    'role': role,
                    'auto_accepted': True,
                },
                request=request,
            )
            messages.success(request, f'{email} added as {invitation.get_role_display()}.')
        else:
            # Send invitation email
            invite_url = f'{settings.SITE_URL}/engagements/join/{invitation.token}/'
            try:
                send_mail(
                    subject=f'You\'ve been invited to "{engagement.name}" on Vulnex',
                    message=(
                        f'Hi,\n\n'
                        f'{request.user.get_full_name() or request.user.username} has invited you '
                        f'to join the engagement "{engagement.name}" as {invitation.get_role_display()}.\n\n'
                        f'Click the link below to accept:\n'
                        f'{invite_url}\n\n'
                        f'This invitation expires in 7 days.\n\n'
                        f'— Vulnex'
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )
            except Exception:
                pass  # Don't block the flow if email fails

            ActivityLog.objects.create(
                engagement=engagement, user=request.user,
                action=f'Invited {email} as {invitation.get_role_display()}'
            )
            AuditLog.record(
                actor=request.user,
                action=AuditLog.Action.INVITATION_SENT,
                target=email,
                details={'engagement': engagement.name, 'role': role},
                request=request,
            )
            messages.success(request, f'Invitation sent to {email}.')

    return redirect('engagements:detail', pk=pk)


@login_required
def remove_member(request, pk, member_pk):
    engagement = get_object_or_404(Engagement, pk=pk)
    if not engagement.user_is_lead(request.user):
        messages.error(request, 'Only the lead can remove members.')
        return redirect('engagements:detail', pk=pk)

    member = get_object_or_404(EngagementMember, pk=member_pk, engagement=engagement)

    # Can't remove yourself if you're the only lead
    if member.user == request.user and member.role == 'lead':
        other_leads = engagement.members.filter(role='lead').exclude(pk=member.pk).count()
        if other_leads == 0:
            messages.error(request, 'Cannot remove yourself — you are the only lead.')
            return redirect('engagements:detail', pk=pk)

    if request.method == 'POST':
        username = str(member.user)
        member.delete()
        ActivityLog.objects.create(
            engagement=engagement, user=request.user,
            action=f'Removed {username} from team'
        )
        messages.success(request, f'{username} removed from team.')

    return redirect('engagements:detail', pk=pk)


@login_required
def cancel_invitation(request, pk, invitation_pk):
    engagement = get_object_or_404(Engagement, pk=pk)
    if not engagement.user_is_lead(request.user):
        messages.error(request, 'Only the lead can cancel invitations.')
        return redirect('engagements:detail', pk=pk)

    invitation = get_object_or_404(Invitation, pk=invitation_pk, engagement=engagement, status='pending')
    if request.method == 'POST':
        invitation.status = 'expired'
        invitation.save()
        messages.success(request, f'Invitation to {invitation.email} cancelled.')

    return redirect('engagements:detail', pk=pk)


def accept_invitation(request, token):
    """Accept an invitation via token link. Handles three cases:
    1. Logged-in user whose email matches -> accept immediately
    2. Logged-in user whose email doesn't match -> error
    3. Anonymous user with existing account -> redirect to login
    4. Anonymous user, no account -> show registration form
    """
    # IP-based rate limit to blunt token-enumeration attempts.
    ip = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR', '')).split(',')[0].strip()
    if ip:
        key = f'invite_attempts:{ip}'
        attempts = cache.get(key, 0)
        if attempts >= 20:
            return HttpResponse('Too many attempts. Try again later.', status=429)
        cache.set(key, attempts + 1, 300)  # 5-minute window

    invitation = get_object_or_404(Invitation, token=token, status='pending')

    if invitation.is_expired:
        invitation.status = 'expired'
        invitation.save(update_fields=['status'])
        messages.error(request, 'This invitation has expired.')
        if request.user.is_authenticated:
            return redirect('dashboard:home')
        return redirect('accounts:login')

    # ── Case 1 & 2: User is logged in ──
    if request.user.is_authenticated:
        if request.user.email != invitation.email:
            messages.error(request, f'This invitation was sent to {invitation.email}. Please log in with that account.')
            return redirect('dashboard:home')

        # Accept: create membership (atomic to prevent race conditions). The
        # global role on request.user is intentionally left alone — only an
        # admin can change that via accounts.views.user_edit.
        with transaction.atomic():
            EngagementMember.objects.get_or_create(
                engagement=invitation.engagement,
                user=request.user,
                defaults={'role': invitation.role},
            )
            invitation.status = 'accepted'
            invitation.save()

        ActivityLog.objects.create(
            engagement=invitation.engagement, user=request.user,
            action=f'Joined as {invitation.get_role_display()}'
        )
        AuditLog.record(
            actor=request.user,
            action=AuditLog.Action.INVITATION_ACCEPTED,
            target=invitation.email,
            details={
                'engagement': invitation.engagement.name,
                'role': invitation.role,
            },
            request=request,
        )
        messages.success(request, f'You joined "{invitation.engagement.name}" as {invitation.get_role_display()}.')
        return redirect('engagements:detail', pk=invitation.engagement.pk)

    # ── Case 3: Anonymous, but account already exists ──
    from accounts.models import User
    existing_user = User.objects.filter(email=invitation.email).first()
    if existing_user:
        messages.info(request, f'Please log in as "{existing_user.username}" to accept this invitation.')
        from django.urls import reverse
        login_url = reverse('accounts:login') + f'?next=/engagements/join/{token}/'
        return redirect(login_url)

    # ── Case 4: Anonymous, no account — show registration form ──
    from .forms import InviteRegistrationForm

    if request.method == 'POST':
        form = InviteRegistrationForm(request.POST)
        if form.is_valid():
            # Atomic: create user + membership + accept invitation together
            with transaction.atomic():
                # New accounts created via invite always start with the
                # lowest-privilege global role. An admin must promote them via
                # accounts.views.user_edit if platform-wide access is needed.
                user = User.objects.create_user(
                    username=form.cleaned_data['username'],
                    email=invitation.email,
                    password=form.cleaned_data['password1'],
                    first_name=form.cleaned_data.get('first_name', ''),
                    last_name=form.cleaned_data.get('last_name', ''),
                    role='client',
                )

                EngagementMember.objects.create(
                    engagement=invitation.engagement,
                    user=user,
                    role=invitation.role,
                )
                invitation.status = 'accepted'
                invitation.save()

            ActivityLog.objects.create(
                engagement=invitation.engagement, user=user,
                action=f'Joined as {invitation.get_role_display()}'
            )
            AuditLog.record(
                actor=user,
                action=AuditLog.Action.INVITATION_ACCEPTED,
                target=invitation.email,
                details={
                    'engagement': invitation.engagement.name,
                    'role': invitation.role,
                    'new_account': True,
                },
                request=request,
            )

            # Log them in. Specify the backend explicitly because we have
            # multiple AUTHENTICATION_BACKENDS configured (axes + ModelBackend).
            from django.contrib.auth import login
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            messages.success(request, f'Account created! You joined "{invitation.engagement.name}" as {invitation.get_role_display()}.')
            return redirect('engagements:detail', pk=invitation.engagement.pk)
    else:
        form = InviteRegistrationForm()

    return render(request, 'engagements/accept_invitation.html', {
        'form': form,
        'invitation': invitation,
    })
