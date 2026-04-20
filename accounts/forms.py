from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.password_validation import validate_password
from .models import User


class MFACodeForm(forms.Form):
    code = forms.CharField(
        label='Verification code',
        max_length=20,
        widget=forms.TextInput(attrs={
            'class': 'form-input',
            'autocomplete': 'one-time-code',
            'inputmode': 'numeric',
            'autofocus': 'autofocus',
            'placeholder': '123456',
        }),
    )


class CustomAuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-input'


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'bio')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-input'


class AdminUserForm(forms.ModelForm):
    """Form for admins to create/edit users."""
    password1 = forms.CharField(
        label='Password', widget=forms.PasswordInput(attrs={'class': 'form-input'}),
        required=False, help_text='Leave blank to keep the current password.',
    )
    password2 = forms.CharField(
        label='Confirm password', widget=forms.PasswordInput(attrs={'class': 'form-input'}),
        required=False,
    )

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'role', 'is_active')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            if name not in ('password1', 'password2'):
                field.widget.attrs['class'] = 'form-input'
        # Password required on create, optional on edit
        if not self.instance.pk:
            self.fields['password1'].required = True
            self.fields['password2'].required = True
            self.fields['password1'].help_text = ''

    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get('password1')
        p2 = cleaned_data.get('password2')
        if p1 or p2:
            if p1 != p2:
                raise forms.ValidationError('Passwords do not match.')
            try:
                validate_password(p1, self.instance)
            except forms.ValidationError as e:
                self.add_error('password1', e)
        return cleaned_data


class UserPasswordChangeForm(PasswordChangeForm):
    """Self-service password change on the profile page. Runs the same
    AUTH_PASSWORD_VALIDATORS chain as Django's default and adds our form-input
    styling."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-input'
