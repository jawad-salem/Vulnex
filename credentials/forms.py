from django import forms
from recon.models import DiscoveredHost
from .models import Credential


class CredentialForm(forms.ModelForm):
    """Credential creation / edit form.

    The plaintext secret is entered into a transient `secret` field; on save we
    push it through `set_secret()` so only the ciphertext ever hits the DB.
    """

    secret = forms.CharField(
        label='Secret',
        required=False,
        widget=forms.Textarea(attrs={
            'rows': 2,
            'placeholder': 'Password, hash, token, or key material',
            'autocomplete': 'new-password',
            'spellcheck': 'false',
        }),
        help_text='Leave blank on edit to keep the existing value.',
    )

    class Meta:
        model = Credential
        fields = [
            'credential_type', 'username', 'hash_type',
            'host', 'service', 'source', 'status', 'notes',
        ]
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'e.g. admin, svc_backup, root'}),
            'hash_type': forms.TextInput(attrs={'placeholder': 'NTLM, bcrypt, MD5…'}),
            'service': forms.TextInput(attrs={'placeholder': 'SSH, RDP, HTTP /admin, MySQL'}),
            'source': forms.TextInput(attrs={'placeholder': 'mimikatz, DB dump, phishing…'}),
            'notes': forms.Textarea(attrs={'rows': 3}),
        }

    def __init__(self, *args, engagement=None, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            if not isinstance(field.widget, (forms.CheckboxInput, forms.RadioSelect)):
                field.widget.attrs.setdefault('class', 'form-input')

        if engagement:
            self.fields['host'].queryset = DiscoveredHost.objects.filter(engagement=engagement)
        else:
            self.fields['host'].queryset = DiscoveredHost.objects.none()

        self.fields['host'].required = False
        self.fields['host'].empty_label = '— No host (optional) —'

    def save(self, commit=True):
        instance = super().save(commit=False)
        plaintext = self.cleaned_data.get('secret', '')
        # On create, always store whatever was entered (even empty).
        # On edit, only overwrite if the user typed something new — lets them
        # update metadata without re-pasting the secret.
        if plaintext or not instance.pk:
            instance.set_secret(plaintext)
        if commit:
            instance.save()
        return instance
