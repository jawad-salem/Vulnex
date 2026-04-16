from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import CustomAuthenticationForm, UserProfileForm, AdminUserForm
from .decorators import role_required
from .models import User, AuditLog


class CustomLoginView(LoginView):
    form_class = CustomAuthenticationForm
    template_name = 'accounts/login.html'

    def form_invalid(self, form):
        username = self.request.POST.get('username', '')[:150]
        AuditLog.record(
            actor=None,
            action=AuditLog.Action.LOGIN_FAILED,
            target=username,
            request=self.request,
        )
        return super().form_invalid(form)


class CustomLogoutView(LogoutView):
    next_page = '/accounts/login/'


@login_required
def profile(request):
    if request.method == 'POST':
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated.')
            return redirect('accounts:profile')
    else:
        form = UserProfileForm(instance=request.user)
    return render(request, 'accounts/profile.html', {'form': form})


# ── Admin user management ──

@login_required
@role_required('admin')
def user_list(request):
    users = User.objects.all().order_by('role', 'username')
    return render(request, 'accounts/user_list.html', {'users': users})


@login_required
@role_required('admin')
def user_create(request):
    if request.method == 'POST':
        form = AdminUserForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.save()
            AuditLog.record(
                actor=request.user,
                action=AuditLog.Action.USER_CREATE,
                target=user.username,
                details={'role': user.role},
                request=request,
            )
            messages.success(request, f'User "{user.username}" created.')
            return redirect('accounts:user_list')
    else:
        form = AdminUserForm()
    return render(request, 'accounts/user_form.html', {
        'form': form, 'title': 'Create user',
    })


@login_required
@role_required('admin')
def user_edit(request, pk):
    target_user = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        old_role = target_user.role
        form = AdminUserForm(request.POST, instance=target_user)
        if form.is_valid():
            user = form.save(commit=False)
            pwd = form.cleaned_data.get('password1')
            if pwd:
                user.set_password(pwd)
            user.save()
            if old_role != user.role:
                AuditLog.record(
                    actor=request.user,
                    action=AuditLog.Action.USER_ROLE_CHANGE,
                    target=user.username,
                    details={'from': old_role, 'to': user.role},
                    request=request,
                )
            else:
                AuditLog.record(
                    actor=request.user,
                    action=AuditLog.Action.USER_UPDATE,
                    target=user.username,
                    details={'password_changed': bool(pwd)},
                    request=request,
                )
            messages.success(request, f'User "{user.username}" updated.')
            return redirect('accounts:user_list')
    else:
        form = AdminUserForm(instance=target_user)
    return render(request, 'accounts/user_form.html', {
        'form': form, 'title': f'Edit {target_user.username}', 'target_user': target_user,
    })


@login_required
@role_required('admin')
def user_delete(request, pk):
    target_user = get_object_or_404(User, pk=pk)
    if target_user == request.user:
        messages.error(request, 'You cannot delete your own account.')
        return redirect('accounts:user_list')
    if request.method == 'POST':
        username = target_user.username
        target_user.delete()
        AuditLog.record(
            actor=request.user,
            action=AuditLog.Action.USER_DELETE,
            target=username,
            request=request,
        )
        messages.success(request, f'User "{username}" deleted.')
        return redirect('accounts:user_list')
    return render(request, 'accounts/user_confirm_delete.html', {'target_user': target_user})


@login_required
@role_required('admin')
def audit_log(request):
    logs = AuditLog.objects.select_related('actor').all()
    action_filter = request.GET.get('action')
    if action_filter:
        logs = logs.filter(action=action_filter)
    logs = logs[:500]
    return render(request, 'accounts/audit_log.html', {
        'logs': logs,
        'action_choices': AuditLog.Action.choices,
        'action_filter': action_filter,
    })
