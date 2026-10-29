from django.core.exceptions import ValidationError as DjangoValidationError
from engagements.services import create_engagement, ensure_scope_editable
from django.db import transaction
from vulns.services.workflow import visible_findings
from django.conf import settings
from django_otp import user_has_device
from rest_framework import serializers
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

from credentials.models import Credential
from engagements.models import Engagement
from recon.models import DiscoveredHost
from reports.models import Report
from vulns.models import Evidence, Finding


class MFAAwareTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Authenticate both factors before creating any JWTs."""
    otp_code = serializers.CharField(required=False, write_only=True, max_length=32)

    def validate(self, attrs):
        from accounts.mfa import verify_code
        from rest_framework_simplejwt.serializers import TokenObtainSerializer
        TokenObtainSerializer.validate(self, attrs)
        enrolled = user_has_device(self.user, confirmed=True)
        if self.user.role in settings.MFA_REQUIRED_ROLES and not enrolled:
            raise AuthenticationFailed('MFA setup is required before issuing API tokens.', code='mfa_required')
        device = verify_code(self.user, attrs.get('otp_code', '')) if enrolled else None
        if enrolled and device is None:
            raise AuthenticationFailed('A valid MFA code is required.', code='mfa_required')
        refresh = self.get_token(self.user)
        refresh['auth_version'] = 2
        refresh['otp_device'] = device.persistent_id if device else None
        return {'refresh': str(refresh), 'access': str(refresh.access_token)}


class SecureTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        from .authentication import SecureJWTAuthentication
        token = self.token_class(attrs['refresh'])
        SecureJWTAuthentication().get_user(token)
        return super().validate(attrs)


class EngagementSerializer(serializers.ModelSerializer):
    scope_targets = serializers.ListField(
        child=serializers.CharField(), read_only=True,
    )
    finding_count = serializers.IntegerField(read_only=True)
    critical_count = serializers.IntegerField(read_only=True)
    high_count = serializers.IntegerField(read_only=True)
    client_name = serializers.CharField(
        required=False, allow_blank=True, write_only=False,
        help_text='Client name — writing this gets-or-creates a Client record.',
    )

    class Meta:
        model = Engagement
        fields = [
            'id', 'name', 'client', 'client_name', 'engagement_type', 'status',
            'description', 'in_scope', 'out_of_scope', 'rules_of_engagement', 'authorization_reference',
            'start_date', 'end_date', 'created_at', 'updated_at',
            'scope_targets', 'finding_count', 'critical_count', 'high_count',
        ]
        read_only_fields = ['id', 'client', 'created_at', 'updated_at']

    def _resolve_client(self, validated_data):
        name = (validated_data.pop('client_name', '') or '').strip()
        if not name:
            return None
        from engagements.models import Client
        client = Client.objects.filter(name__iexact=name).first()
        if client:
            from engagements.selectors import assignable_clients
            if not assignable_clients(self.context['request'].user).filter(pk=client.pk).exists():
                raise serializers.ValidationError({'client_name': 'This client is not available for this engagement.'})
        return client or Client.objects.create(name=name)

    @transaction.atomic
    def create(self, validated_data):
        client = self._resolve_client(validated_data)
        if client:
            validated_data['client'] = client
        actor = validated_data.pop('created_by')
        return create_engagement(actor=actor, engagement=Engagement(**validated_data))

    def validate(self, attrs):
        if self.instance:
            try:
                ensure_scope_editable(self.instance)
            except DjangoValidationError as exc:
                raise serializers.ValidationError(exc.messages)
        return attrs

    @transaction.atomic
    def update(self, instance, validated_data):
        instance = Engagement.objects.select_for_update().get(pk=instance.pk)
        try:
            ensure_scope_editable(instance)
        except DjangoValidationError as exc:
            raise serializers.ValidationError(exc.messages)
        client = self._resolve_client(validated_data)
        if client:
            validated_data['client'] = client
        return super().update(instance, validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['client_name'] = instance.client_name
        request = self.context.get('request')
        if request and request.user.role != 'admin' and instance.user_is_client(request.user):
            findings = visible_findings(request.user, instance.findings.all())
            data['finding_count'] = findings.count()
            data['critical_count'] = findings.filter(severity='critical').count()
            data['high_count'] = findings.filter(severity='high').count()
        return data


class ImmutableEngagementSerializer(serializers.ModelSerializer):
    def validate_engagement(self, value):
        if self.instance and value.pk != self.instance.engagement_id:
            raise serializers.ValidationError('Records cannot be moved between engagements.')
        return value


class FindingSerializer(ImmutableEngagementSerializer):
    engagement = serializers.PrimaryKeyRelatedField(queryset=Engagement.objects.all())
    cvss_vector_string = serializers.CharField(read_only=True)
    severity = serializers.ChoiceField(choices=Finding.Severity.choices, required=False)

    class Meta:
        model = Finding
        fields = [
            'id', 'engagement', 'title', 'severity', 'status',
            'cvss_score', 'cvss_vector_string',
            'attack_vector', 'attack_complexity', 'privileges_required',
            'user_interaction', 'scope',
            'confidentiality_impact', 'integrity_impact', 'availability_impact',
            'host', 'port', 'url', 'parameter', 'http_method', 'endpoint',
            'description', 'affected_hosts', 'proof_of_concept',
            'remediation', 'references', 'cwe_id',
            'tool_source', 'due_date', 'retest_status', 'retest_date',
            'review_state',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'cvss_score', 'cvss_vector_string', 'review_state',
            'created_at', 'updated_at',
        ]


class EvidenceSerializer(serializers.ModelSerializer):
    finding = serializers.PrimaryKeyRelatedField(queryset=Finding.objects.all())
    file = serializers.FileField()

    def validate_file(self, value):
        from vulns.forms import EvidenceForm
        form = EvidenceForm(files={'file': value})
        if not form.is_valid():
            raise serializers.ValidationError(form.errors.get('file', ['Invalid evidence upload.']))
        return form.cleaned_data['file']

    class Meta:
        model = Evidence
        fields = ['id', 'finding', 'file', 'caption', 'uploaded_at']
        read_only_fields = ['id', 'uploaded_at']


class DiscoveredHostSerializer(serializers.ModelSerializer):
    engagement = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = DiscoveredHost
        fields = [
            'id', 'engagement', 'hostname', 'ip_address',
            'ports', 'technologies', 'notes', 'created_at',
        ]
        read_only_fields = ['id', 'created_at']


class CredentialSerializer(ImmutableEngagementSerializer):
    """Credential without its plaintext secret. Use ``reveal=true`` on retrieve
    to include the decrypted secret (logged via AuditLog.CREDENTIAL_REVEAL).
    """

    engagement = serializers.PrimaryKeyRelatedField(queryset=Engagement.objects.all())
    secret = serializers.CharField(write_only=True, required=False, allow_blank=True)
    masked_secret = serializers.CharField(read_only=True)

    class Meta:
        model = Credential
        fields = [
            'id', 'engagement', 'credential_type', 'username',
            'secret', 'masked_secret', 'hash_type',
            'host', 'service', 'source', 'status', 'notes',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'masked_secret']

    def validate(self, attrs):
        attrs = super().validate(attrs)
        engagement = attrs.get('engagement') or getattr(self.instance, 'engagement', None)
        host = attrs.get('host') or getattr(self.instance, 'host', None)
        if host and engagement and host.engagement_id != engagement.pk:
            raise serializers.ValidationError({'host': 'Host must belong to this engagement.'})
        return attrs

    def create(self, validated_data):
        plaintext = validated_data.pop('secret', '')
        obj = Credential(**validated_data)
        obj.set_secret(plaintext)
        obj.save()
        return obj

    def update(self, instance, validated_data):
        plaintext = validated_data.pop('secret', None)
        for attr, val in validated_data.items():
            setattr(instance, attr, val)
        if plaintext is not None:
            instance.set_secret(plaintext)
        instance.save()
        return instance


class ReportSerializer(serializers.ModelSerializer):
    engagement = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Report
        fields = [
            'id', 'engagement', 'title', 'report_type',
            'generated_by', 'created_at', 'published_at', 'published_by',
        ]
        read_only_fields = fields


class ReviewActionSerializer(serializers.Serializer):
    state = serializers.ChoiceField(choices=['in_review', 'approved', 'changes_requested'])
    notes = serializers.CharField(required=False, allow_blank=True, default='')
