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


class NmapImportForm(forms.Form):
    file = forms.FileField(label='Nmap XML file')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['file'].widget.attrs['class'] = 'form-input'
        self.fields['file'].widget.attrs['accept'] = '.xml'

