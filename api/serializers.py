from rest_framework import serializers

from credentials.models import Credential
from engagements.models import Engagement
from recon.models import DiscoveredHost
from reports.models import Report
from vulns.models import Evidence, Finding


class EngagementSerializer(serializers.ModelSerializer):
    scope_targets = serializers.ReadOnlyField()
    finding_count = serializers.ReadOnlyField()
    critical_count = serializers.ReadOnlyField()
    high_count = serializers.ReadOnlyField()

    class Meta:
        model = Engagement
        fields = [
            'id', 'name', 'client_name', 'engagement_type', 'status',
            'description', 'in_scope', 'out_of_scope', 'rules_of_engagement',
            'start_date', 'end_date', 'created_at', 'updated_at',
            'scope_targets', 'finding_count', 'critical_count', 'high_count',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class FindingSerializer(serializers.ModelSerializer):
    engagement = serializers.PrimaryKeyRelatedField(queryset=Engagement.objects.all())
    cvss_vector_string = serializers.ReadOnlyField()
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
            'id', 'cvss_score', 'cvss_vector_string',
            'created_at', 'updated_at',
        ]


class EvidenceSerializer(serializers.ModelSerializer):
    finding = serializers.PrimaryKeyRelatedField(queryset=Finding.objects.all())
    file = serializers.FileField()

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


class CredentialSerializer(serializers.ModelSerializer):
    """Credential without its plaintext secret. Use ``reveal=true`` on retrieve
    to include the decrypted secret (logged via AuditLog.CREDENTIAL_REVEAL).
    """

    engagement = serializers.PrimaryKeyRelatedField(queryset=Engagement.objects.all())
    secret = serializers.CharField(write_only=True, required=False, allow_blank=True)
    masked_secret = serializers.ReadOnlyField()

    class Meta:
        model = Credential
        fields = [
            'id', 'engagement', 'credential_type', 'username',
            'secret', 'masked_secret', 'hash_type',
            'host', 'service', 'source', 'status', 'notes',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'masked_secret']

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
            'generated_by', 'created_at',
        ]
        read_only_fields = fields
