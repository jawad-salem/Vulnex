from django import forms
from django.contrib.auth.password_validation import validate_password
from accounts.models import User
from .models import Engagement, EngagementNote, Client


class InviteRegistrationForm(forms.Form):
    """Form for new users to create an account via an invitation link."""
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={'class': 'form-input', 'placeholder': 'Choose a username'}),
    )
    first_name = forms.CharField(
        max_length=150, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input'}),
    )
    last_name = forms.CharField(
        max_length=150, required=False,
        widget=forms.TextInput(attrs={'class': 'form-input'}),
    )
    password1 = forms.CharField(
        label='Password',
        widget=forms.PasswordInput(attrs={'class': 'form-input'}),
    )
    password2 = forms.CharField(
        label='Confirm password',
        widget=forms.PasswordInput(attrs={'class': 'form-input'}),
    )

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError('This username is already taken.')
        return username

    def clean(self):
        cleaned_data = super().clean()
        p1 = cleaned_data.get('password1')
        p2 = cleaned_data.get('password2')
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError('Passwords do not match.')
        if p1:
            # Build an unsaved User so UserAttributeSimilarityValidator can
            # compare the password against the username/first/last values
            # being submitted right now.
            candidate = User(
                username=cleaned_data.get('username', '') or '',
                first_name=cleaned_data.get('first_name', '') or '',
                last_name=cleaned_data.get('last_name', '') or '',
            )
            try:
                validate_password(p1, candidate)
            except forms.ValidationError as e:
                self.add_error('password1', e)
        return cleaned_data


class EngagementForm(forms.ModelForm):
    client_name = forms.CharField(
        max_length=200, label='Client',
        help_text='Pick an existing client or type a new name to create one.',
        widget=forms.TextInput(attrs={'list': 'client-suggestions', 'autocomplete': 'off'}),
    )

    class Meta:
        model = Engagement
        fields = [
            'name', 'engagement_type', 'status',
            'description', 'in_scope', 'out_of_scope',
            'rules_of_engagement', 'start_date', 'end_date',
        ]
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date'}),
            'end_date': forms.DateInput(attrs={'type': 'date'}),
            'description': forms.Textarea(attrs={'rows': 3}),
            'in_scope': forms.Textarea(attrs={'rows': 5, 'placeholder': '192.168.1.0/24\nexample.com\nhttps://app.example.com'}),
            'out_of_scope': forms.Textarea(attrs={'rows': 3}),
            'rules_of_engagement': forms.Textarea(attrs={'rows': 4}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk and self.instance.client_id:
            self.fields['client_name'].initial = self.instance.client.name
        for field in self.fields.values():
            if not isinstance(field.widget, (forms.CheckboxInput, forms.RadioSelect)):
                field.widget.attrs.setdefault('class', 'form-input')

    def clean_name(self):
        name = self.cleaned_data['name']
        qs = Engagement.objects.filter(name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('An engagement with this name already exists.')
        return name

    def clean_client_name(self):
        name = (self.cleaned_data.get('client_name') or '').strip()
        if not name:
            raise forms.ValidationError('Client is required.')
        return name

    def save(self, commit=True):
        name = self.cleaned_data['client_name']
        client = Client.objects.filter(name__iexact=name).first()
        if client is None:
            client = Client.objects.create(name=name)
        self.instance.client = client
        return super().save(commit=commit)


class EngagementNoteForm(forms.ModelForm):
    class Meta:
        model = EngagementNote
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Add a note...', 'class': 'form-input'}),
        }

