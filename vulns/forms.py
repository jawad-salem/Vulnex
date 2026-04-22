from django import forms
from django.conf import settings
from .models import Finding, Evidence
from recon.models import DiscoveredHost


class FindingForm(forms.ModelForm):
    class Meta:
        model = Finding
        fields = [
            'title', 'description',
            # Host link
            'discovered_host',
            # Assignment
            'assigned_to',
            # Location
            'host', 'port', 'url', 'endpoint', 'http_method', 'parameter',
            # Additional
            'affected_hosts', 'proof_of_concept',
            'remediation', 'references', 'cwe_id', 'tool_source',
            # CVSS
            'attack_vector', 'attack_complexity', 'privileges_required',
            'user_interaction', 'scope', 'confidentiality_impact',
            'integrity_impact', 'availability_impact', 'status',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
            'affected_hosts': forms.Textarea(attrs={'rows': 2}),
            'proof_of_concept': forms.Textarea(attrs={'rows': 5}),
            'remediation': forms.Textarea(attrs={'rows': 3}),
            'references': forms.Textarea(attrs={'rows': 2}),
            'url': forms.URLInput(attrs={'placeholder': 'https://api.example.com/login'}),
            'host': forms.TextInput(attrs={'placeholder': 'api.example.com'}),
            'port': forms.NumberInput(attrs={'placeholder': '443'}),
            'endpoint': forms.TextInput(attrs={'placeholder': '/api/v1/login'}),
            'parameter': forms.TextInput(attrs={'placeholder': 'username, id'}),
        }

    def __init__(self, *args, engagement=None, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if not isinstance(field.widget, (forms.CheckboxInput, forms.RadioSelect)):
                field.widget.attrs.setdefault('class', 'form-input')

        # Scope host dropdown to this engagement's discovered hosts
        if engagement:
            self.fields['discovered_host'].queryset = DiscoveredHost.objects.filter(
                engagement=engagement
            )
            # Scope assignee to non-client members of this engagement
            User = self.fields['assigned_to'].queryset.model
            member_ids = engagement.members.exclude(role='client').values_list(
                'user_id', flat=True,
            )
            self.fields['assigned_to'].queryset = User.objects.filter(
                pk__in=list(member_ids)
            )
        else:
            self.fields['discovered_host'].queryset = DiscoveredHost.objects.none()
            self.fields['assigned_to'].queryset = self.fields['assigned_to'].queryset.none()

        self.fields['discovered_host'].required = False
        self.fields['discovered_host'].empty_label = '— Select from recon (optional) —'
        self.fields['assigned_to'].required = False
        self.fields['assigned_to'].empty_label = '— Unassigned —'


class EvidenceForm(forms.ModelForm):
    # Whitelist of allowed evidence file extensions. Anything that the browser
    # could execute as script (html, svg, js, xml, etc.) is intentionally excluded
    # to prevent stored XSS via the media folder.
    ALLOWED_EXTENSIONS = {
        'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp',
        'pdf', 'txt', 'log', 'json', 'csv', 'md',
        'zip', 'tar', 'gz',
    }
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

    class Meta:
        model = Evidence
        fields = ['file', 'caption']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')

    def clean_file(self):
        f = self.cleaned_data.get('file')
        if not f:
            return f

        if f.size > self.MAX_FILE_SIZE:
            raise forms.ValidationError(
                f'File too large ({f.size // 1024} KB). Maximum size is '
                f'{self.MAX_FILE_SIZE // (1024 * 1024)} MB.'
            )

        name = f.name or ''
        if '/' in name or '\\' in name or '..' in name or name.startswith('.'):
            raise forms.ValidationError('Invalid filename.')
        if '.' not in name:
            raise forms.ValidationError('File must have an extension.')

        ext = name.rsplit('.', 1)[-1].lower()
        if ext not in self.ALLOWED_EXTENSIONS:
            allowed = ', '.join(sorted(self.ALLOWED_EXTENSIONS))
            raise forms.ValidationError(
                f'File type ".{ext}" is not allowed. Allowed types: {allowed}.'
            )

        return f


class RetestForm(forms.ModelForm):
    class Meta:
        model = Finding
        fields = ['retest_status', 'retest_date', 'retest_notes']
        widgets = {
            'retest_date': forms.DateInput(attrs={'type': 'date'}),
            'retest_notes': forms.Textarea(attrs={'rows': 4, 'placeholder': 'What was verified, commands run, screenshots…'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')


class ToolImportForm(forms.Form):
    TOOL_CHOICES = [
        ('nuclei', 'Nuclei JSON'),
        ('nikto', 'Nikto JSON'),
        ('burp', 'Burp Suite XML (issues export)'),
        ('nessus', 'Nessus XML (.nessus v2)'),
        ('zap', 'OWASP ZAP JSON'),
        ('semgrep', 'Semgrep JSON (SAST)'),
    ]
    tool = forms.ChoiceField(choices=TOOL_CHOICES)
    file = forms.FileField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')

