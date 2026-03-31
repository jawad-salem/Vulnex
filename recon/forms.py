from django import forms
from .models import ReconScan


class ReconScanForm(forms.ModelForm):
    class Meta:
        model = ReconScan
        fields = ['scan_type', 'target']
        widgets = {
            'target': forms.TextInput(attrs={'placeholder': 'e.g. example.com or 192.168.1.0/24'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')

