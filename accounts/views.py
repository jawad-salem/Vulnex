from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .forms import CustomAuthenticationForm, UserProfileForm, AdminUserForm
from .decorators import role_required
from .models import User


class CustomLoginView(LoginView):
    form_class = CustomAuthenticationForm
    template_name = 'accounts/login.html'


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
        form = AdminUserForm(request.POST, instance=target_user)
        if form.is_valid():
            user = form.save(commit=False)
            pwd = form.cleaned_data.get('password1')
            if pwd:
                user.set_password(pwd)
            user.save()
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
        messages.success(request, f'User "{username}" deleted.')
        return redirect('accounts:user_list')
    return render(request, 'accounts/user_confirm_delete.html', {'target_user': target_user})
