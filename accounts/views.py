import base64
import io

import qrcode
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView
from django.shortcuts import get_object_or_404, redirect, render
from django_otp import devices_for_user, user_has_device
from django_otp.plugins.otp_static.models import StaticDevice, StaticToken
from django_otp.plugins.otp_totp.models import TOTPDevice

from .decorators import role_required
from .forms import (
    AdminUserForm,
    CustomAuthenticationForm,
    MFACodeForm,
    UserPasswordChangeForm,
    UserProfileForm,
)
from .models import AuditLog, User


class CustomLoginView(LoginView):
    form_class = CustomAuthenticationForm
    template_name = 'accounts/login.html'

    def form_valid(self, form):
        user = form.get_user()
        if user_has_device(user, confirmed=True):
            # Defer auth_login() until the second factor is verified.
            self.request.session['mfa_pending_user_id'] = user.pk
            self.request.session['mfa_pending_backend'] = getattr(
                user, 'backend', 'django.contrib.auth.backends.ModelBackend',
            )
            self.request.session['mfa_next'] = self.get_success_url()
            return redirect('accounts:mfa_verify')
        return super().form_valid(form)

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
    form = UserProfileForm(instance=request.user)
    password_form = UserPasswordChangeForm(request.user)
    if request.method == 'POST':
        # Which form was submitted? The password card's button carries
        # `name="change_password"`; the profile card's does not.
        if 'change_password' in request.POST:
            password_form = UserPasswordChangeForm(request.user, request.POST)
            if password_form.is_valid():
                user = password_form.save()
                # Keep the current session alive despite the hash rotation.
                update_session_auth_hash(request, user)
                AuditLog.record(
                    actor=request.user,
                    action=AuditLog.Action.PASSWORD_CHANGE,
                    target=request.user.username,
                    request=request,
                )
                messages.success(request, 'Password changed.')
                return redirect('accounts:profile')
        else:
            form = UserProfileForm(request.POST, instance=request.user)
            if form.is_valid():
                form.save()
                messages.success(request, 'Profile updated.')
                return redirect('accounts:profile')
    return render(request, 'accounts/profile.html', {
        'form': form,
        'password_form': password_form,
        'mfa_enabled': user_has_device(request.user, confirmed=True),
        'mfa_required': request.user.role in getattr(settings, 'MFA_REQUIRED_ROLES', []),
    })


# ── MFA ──

def _qr_png_data_uri(totp_device):
    img = qrcode.make(totp_device.config_url)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return 'data:image/png;base64,' + base64.b64encode(buf.getvalue()).decode()


@login_required
def mfa_setup(request):
    existing = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
    if existing:
        messages.info(request, 'MFA is already enabled.')
        return redirect('accounts:profile')

    device, _ = TOTPDevice.objects.get_or_create(
        user=request.user, confirmed=False,
        defaults={'name': 'default'},
    )

    if request.method == 'POST':
        form = MFACodeForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['code'].strip()
            if device.verify_token(code):
                device.confirmed = True
                device.save()
                static_device, _ = StaticDevice.objects.get_or_create(
                    user=request.user, name='backup',
                )
                static_device.token_set.all().delete()
                backup_tokens = []
                for _ in range(8):
                    t = StaticToken.random_token()
                    static_device.token_set.create(token=t)
                    backup_tokens.append(t)
                static_device.confirmed = True
                static_device.save()
                AuditLog.record(
                    actor=request.user,
                    action=AuditLog.Action.MFA_ENABLED,
                    target=request.user.username,
                    request=request,
                )
                return render(request, 'accounts/mfa_backup_tokens.html', {
                    'tokens': backup_tokens,
                })
            form.add_error('code', 'Invalid code — try again.')
    else:
        form = MFACodeForm()

    return render(request, 'accounts/mfa_setup.html', {
        'form': form,
        'qr_data_uri': _qr_png_data_uri(device),
        'secret': device.key,
    })


def mfa_verify(request):
    pending_pk = request.session.get('mfa_pending_user_id')
    if not pending_pk:
        return redirect('accounts:login')

    try:
        user = User.objects.get(pk=pending_pk, is_active=True)
    except User.DoesNotExist:
        request.session.pop('mfa_pending_user_id', None)
        return redirect('accounts:login')

    if request.method == 'POST':
        form = MFACodeForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['code'].strip()
            matched = any(d.verify_token(code) for d in devices_for_user(user, confirmed=True))
            if matched:
                user.backend = request.session.pop(
                    'mfa_pending_backend', 'django.contrib.auth.backends.ModelBackend',
                )
                auth_login(request, user)
                next_url = request.session.pop('mfa_next', None) or settings.LOGIN_REDIRECT_URL
                request.session.pop('mfa_pending_user_id', None)
                return redirect(next_url)
            AuditLog.record(
                actor=None,
                action=AuditLog.Action.MFA_CHALLENGE_FAILED,
                target=user.username,
                request=request,
            )
            form.add_error('code', 'Invalid code.')
    else:
        form = MFACodeForm()

    return render(request, 'accounts/mfa_verify.html', {'form': form})


@login_required
def mfa_disable(request):
    required = getattr(settings, 'MFA_REQUIRED_ROLES', [])
    if request.user.role in required:
        messages.error(
            request,
            'Your role requires MFA. Ask an admin to reset it if you need to re-enroll.',
        )
        return redirect('accounts:profile')
    if request.method == 'POST':
        TOTPDevice.objects.filter(user=request.user).delete()
        StaticDevice.objects.filter(user=request.user).delete()
        AuditLog.record(
            actor=request.user,
            action=AuditLog.Action.MFA_DISABLED,
            target=request.user.username,
            request=request,
        )
        messages.success(request, 'MFA disabled.')
        return redirect('accounts:profile')
    return render(request, 'accounts/mfa_disable.html')


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
