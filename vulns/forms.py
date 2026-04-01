from django import forms
from .models import Finding, Evidence


class FindingForm(forms.ModelForm):
    class Meta:
        model = Finding
        fields = [
            'title', 'description', 'affected_hosts', 'proof_of_concept',
            'remediation', 'references', 'cwe_id', 'tool_source',
            'attack_vector', 'attack_complexity', 'privileges_required',
            'user_interaction', 'confidentiality_impact', 'integrity_impact',
            'availability_impact', 'status',
        ]
        widgets = {
            'description': forms.Textarea(attrs={'rows': 4}),
            'affected_hosts': forms.Textarea(attrs={'rows': 3}),
            'proof_of_concept': forms.Textarea(attrs={'rows': 5}),
            'remediation': forms.Textarea(attrs={'rows': 3}),
            'references': forms.Textarea(attrs={'rows': 2}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if not isinstance(field.widget, (forms.CheckboxInput, forms.RadioSelect)):
                field.widget.attrs.setdefault('class', 'form-input')


class EvidenceForm(forms.ModelForm):
    class Meta:
        model = Evidence
        fields = ['file', 'caption']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')


class ToolImportForm(forms.Form):
    TOOL_CHOICES = [
        ('nuclei', 'Nuclei JSON'),
        ('nikto', 'Nikto JSON'),
    ]
    tool = forms.ChoiceField(choices=TOOL_CHOICES)
    file = forms.FileField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')

