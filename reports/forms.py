from django import forms

from .models import Report, ReportTemplate


MAX_LOGO_BYTES = 1 * 1024 * 1024  # 1 MB
ALLOWED_LOGO_FORMATS = {'PNG', 'JPEG'}


class ReportGenerateForm(forms.Form):
    """Report-type + optional template override, shown on the dashboard."""
    report_type = forms.ChoiceField(
        choices=Report.ReportType.choices,
        initial=Report.ReportType.FULL,
        widget=forms.Select(attrs={'class': 'form-input'}),
    )
    template = forms.ModelChoiceField(
        queryset=ReportTemplate.objects.all(),
        required=False,
        empty_label='— Use default —',
        help_text='Optional. Overrides the client / global default.',
        widget=forms.Select(attrs={'class': 'form-input'}),
    )


class ReportTemplateForm(forms.ModelForm):
    """Admin-only CRUD form; validates cover_logo shape and size."""
    class Meta:
        model = ReportTemplate
        fields = [
            'name', 'cover_logo',
            'primary_color', 'accent_color',
            'preamble_markdown', 'disclaimer_markdown',
            'footer_text', 'is_default',
        ]
        widgets = {
            'primary_color': forms.TextInput(attrs={'type': 'color'}),
            'accent_color': forms.TextInput(attrs={'type': 'color'}),
            'preamble_markdown': forms.Textarea(attrs={'rows': 4}),
            'disclaimer_markdown': forms.Textarea(attrs={'rows': 4}),
        }

    def clean_cover_logo(self):
        logo = self.cleaned_data.get('cover_logo')
        if not logo:
            return logo
        # Only re-validate freshly uploaded files; existing FieldFiles have no size change.
        if not hasattr(logo, 'file') or not hasattr(logo, 'size'):
            return logo
        if logo.size and logo.size > MAX_LOGO_BYTES:
            raise forms.ValidationError('Logo must be 1 MB or smaller.')
        try:
            from PIL import Image
            pos = logo.file.tell() if hasattr(logo.file, 'tell') else None
            logo.file.seek(0)
            with Image.open(logo.file) as img:
                img.verify()
                fmt = img.format
            logo.file.seek(0 if pos is None else pos)
        except Exception:
            raise forms.ValidationError('Logo must be a valid PNG or JPG image.')
        if fmt not in ALLOWED_LOGO_FORMATS:
            raise forms.ValidationError('Logo must be PNG or JPG.')
        return logo
