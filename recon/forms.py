from django import forms
from .models import ReconScan, DiscoveredHost, ScheduledScan, ScanPipeline


class ReconScanForm(forms.ModelForm):
    class Meta:
        model = ReconScan
        fields = ['scan_type', 'target']
        widgets = {
            'target': forms.TextInput(attrs={'placeholder': 'e.g. example.com or 192.168.1.0/24'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        scan_type = self.fields.get('scan_type')
        if scan_type is not None:
            choices = list(scan_type.choices)
            if choices and choices[0][0] in ('', None):
                choices[0] = ('', 'Select a scan type…')
            else:
                choices = [('', 'Select a scan type…')] + choices
            scan_type.choices = choices
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')


class NmapImportForm(forms.Form):
    file = forms.FileField(label='Nmap XML file')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['file'].widget.attrs['class'] = 'form-input'
        self.fields['file'].widget.attrs['accept'] = '.xml'


class DiscoveredHostForm(forms.ModelForm):
    ports_text = forms.CharField(
        label='Open ports',
        required=False,
        widget=forms.Textarea(attrs={
            'rows': 3,
            'placeholder': 'One per line: port/protocol service\ne.g. 80/tcp http\n443/tcp https\n22/tcp ssh',
        }),
        help_text='One port per line: port/protocol service (e.g. 443/tcp https)',
    )
    techs_text = forms.CharField(
        label='Technologies',
        required=False,
        widget=forms.TextInput(attrs={
            'placeholder': 'e.g. Apache, PHP, WordPress (comma-separated)',
        }),
        help_text='Comma-separated list of detected technologies.',
    )

    class Meta:
        model = DiscoveredHost
        fields = ['hostname', 'ip_address', 'notes']
        widgets = {
            'hostname': forms.TextInput(attrs={'placeholder': 'e.g. api.example.com'}),
            'ip_address': forms.TextInput(attrs={'placeholder': 'e.g. 192.168.1.10'}),
            'notes': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Additional notes about this host...'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')

        # Pre-populate text fields from JSON on edit
        if self.instance.pk:
            # Ports
            lines = []
            for p in self.instance.ports:
                if isinstance(p, dict):
                    line = f"{p.get('port', '')}/{p.get('protocol', 'tcp')}"
                    svc = p.get('service', '')
                    if svc and svc != 'unknown':
                        line += f" {svc}"
                    lines.append(line)
                else:
                    lines.append(str(p))
            self.fields['ports_text'].initial = '\n'.join(lines)

            # Technologies
            self.fields['techs_text'].initial = ', '.join(self.instance.technologies)

    def save(self, commit=True):
        instance = super().save(commit=False)

        # Parse ports from text
        ports = []
        for line in self.cleaned_data.get('ports_text', '').strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 1)
            port_proto = parts[0]
            service = parts[1] if len(parts) > 1 else 'unknown'

            if '/' in port_proto:
                port_num, proto = port_proto.split('/', 1)
            else:
                port_num, proto = port_proto, 'tcp'

            try:
                ports.append({
                    'port': int(port_num),
                    'protocol': proto,
                    'service': service,
                    'state': 'open',
                })
            except ValueError:
                continue
        instance.ports = ports

        # Parse technologies from text
        techs_raw = self.cleaned_data.get('techs_text', '')
        instance.technologies = [
            t.strip() for t in techs_raw.split(',') if t.strip()
        ]

        if commit:
            instance.save()
        return instance


class ScheduledScanForm(forms.ModelForm):
    class Meta:
        model = ScheduledScan
        fields = ['scan_type', 'target', 'frequency']
        widgets = {
            'target': forms.TextInput(attrs={'placeholder': 'e.g. example.com'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        scan_type = self.fields.get('scan_type')
        if scan_type is not None:
            choices = list(scan_type.choices)
            if choices and choices[0][0] in ('', None):
                choices[0] = ('', 'Select a scan type…')
            else:
                choices = [('', 'Select a scan type…')] + choices
            scan_type.choices = choices
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')


class ScanPipelineForm(forms.Form):
    PRESET_CHOICES = [
        (key, preset['name'])
        for key, preset in ScanPipeline.PIPELINE_PRESETS.items()
    ]

    preset = forms.ChoiceField(choices=PRESET_CHOICES, label='Pipeline type')
    target = forms.CharField(
        max_length=500,
        widget=forms.TextInput(attrs={'placeholder': 'e.g. example.com'}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs.setdefault('class', 'form-input')
