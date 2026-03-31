from django import forms
from .models import Engagement, EngagementNote


class EngagementForm(forms.ModelForm):
    class Meta:
        model = Engagement
        fields = [
            'name', 'client_name', 'engagement_type', 'status',
            'description', 'in_scope', 'out_of_scope',
            'rules_of_engagement', 'start_date', 'end_date', 'lead',
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
        for field in self.fields.values():
            if not isinstance(field.widget, (forms.CheckboxInput, forms.RadioSelect)):
                field.widget.attrs.setdefault('class', 'form-input')


class EngagementNoteForm(forms.ModelForm):
    class Meta:
        model = EngagementNote
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Add a note...', 'class': 'form-input'}),
        }

