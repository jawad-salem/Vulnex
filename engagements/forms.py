from django import forms
from django.contrib.auth.password_validation import validate_password
from accounts.models import User
from .models import (
    Engagement, EngagementNote, Client,
    AttackPath, AttackPathNode, AttackPathEdge,
)


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


class ClientForm(forms.ModelForm):
    """Create / edit a Client. Validates the logo by opening it through PIL so
    a renamed `.exe` masquerading as `logo.png` fails before it touches disk."""

    LOGO_MAX_BYTES = 1024 * 1024  # 1 MB
    LOGO_ALLOWED_FORMATS = ('PNG', 'JPEG')

    class Meta:
        model = Client
        fields = [
            'name', 'primary_contact_name', 'primary_contact_email',
            'logo', 'notes',
        ]
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'Acme Corporation'}),
            'primary_contact_name': forms.TextInput(attrs={'placeholder': 'Jane Doe'}),
            'primary_contact_email': forms.EmailInput(attrs={'placeholder': 'jane@acme.test'}),
            'notes': forms.Textarea(attrs={'rows': 4, 'placeholder': 'Optional internal notes (markdown).'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name, field in self.fields.items():
            if not isinstance(field.widget, (forms.CheckboxInput, forms.RadioSelect, forms.FileInput)):
                field.widget.attrs.setdefault('class', 'form-input')

    def clean_name(self):
        name = (self.cleaned_data.get('name') or '').strip()
        if not name:
            raise forms.ValidationError('Name is required.')
        qs = Client.objects.filter(name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError('A client with this name already exists.')
        return name

    def clean_logo(self):
        logo = self.cleaned_data.get('logo')
        if not logo or not hasattr(logo, 'size'):
            return logo
        if logo.size > self.LOGO_MAX_BYTES:
            raise forms.ValidationError('Logo must be 1 MB or smaller.')
        try:
            from PIL import Image
        except ImportError:
            return logo
        try:
            with Image.open(logo) as img:
                fmt = (img.format or '').upper()
                img.verify()
        except Exception:
            raise forms.ValidationError('Logo could not be parsed as a PNG or JPEG image.')
        if fmt not in self.LOGO_ALLOWED_FORMATS:
            raise forms.ValidationError('Logo must be a PNG or JPEG file.')
        # PIL closes the file after verify(); rewind so the storage backend can re-read it.
        if hasattr(logo, 'seek'):
            logo.seek(0)
        return logo


class EngagementNoteForm(forms.ModelForm):
    class Meta:
        model = EngagementNote
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Add a note...', 'class': 'form-input'}),
        }


class AttackPathForm(forms.ModelForm):
    class Meta:
        model = AttackPath
        fields = ['name', 'description']
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'e.g. External → Domain Admin'}),
            'description': forms.Textarea(attrs={'rows': 2}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')


class AttackPathNodeForm(forms.ModelForm):
    class Meta:
        model = AttackPathNode
        fields = ['label', 'kind', 'notes']
        widgets = {
            'label': forms.TextInput(attrs={'placeholder': 'e.g. CONTOSO\\administrator or web01.example.com'}),
            'notes': forms.Textarea(attrs={'rows': 2}),
        }

    def __init__(self, *args, engagement=None, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')


class AttackPathEdgeForm(forms.ModelForm):
    class Meta:
        model = AttackPathEdge
        fields = ['from_node', 'to_node', 'technique', 'mitre_attack_id', 'finding']
        widgets = {
            'technique': forms.TextInput(attrs={'placeholder': 'e.g. Pass-the-Hash, Kerberoast, Phishing'}),
            'mitre_attack_id': forms.TextInput(attrs={'placeholder': 'T1078'}),
        }

    def __init__(self, *args, path=None, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')
        if path is not None:
            node_qs = path.nodes.all()
            self.fields['from_node'].queryset = node_qs
            self.fields['to_node'].queryset = node_qs
            from vulns.models import Finding
            self.fields['finding'].queryset = Finding.objects.filter(
                engagement=path.engagement,
            )
        self.fields['finding'].required = False
        self.fields['finding'].empty_label = '— No linked finding —'

    def clean(self):
        cleaned = super().clean()
        from_node = cleaned.get('from_node')
        to_node = cleaned.get('to_node')
        if from_node and to_node and from_node == to_node:
            raise forms.ValidationError('Edge cannot connect a node to itself.')
        return cleaned

