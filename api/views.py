"""ViewSets backing /api/v1/. Queryset scoping honours engagement membership —
list results for non-admins are filtered to engagements the caller belongs to.
"""
from django.http import FileResponse
from django.shortcuts import get_object_or_404
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response

from accounts.models import AuditLog
from credentials.models import Credential
from engagements.models import Engagement
from recon.models import DiscoveredHost
from reports.models import Report
from vulns.models import Evidence, Finding

from .permissions import (
    CredentialVaultPermission,
    IsEngagementEditor,
    IsEngagementMember,
)
from .serializers import (
    CredentialSerializer,
    DiscoveredHostSerializer,
    EngagementSerializer,
    EvidenceSerializer,
    FindingSerializer,
    ReportSerializer,
)


def _accessible_engagement_ids(user):
    if user.role == 'admin':
        return Engagement.objects.values_list('id', flat=True)
    return Engagement.objects.filter(members__user=user).values_list('id', flat=True)


class EngagementViewSet(viewsets.ModelViewSet):
    serializer_class = EngagementSerializer
    permission_classes = [IsEngagementEditor]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return Engagement.objects.all()
        return Engagement.objects.filter(members__user=user).distinct()

    def perform_create(self, serializer):
        if self.request.user.role not in ('admin', 'pentester'):
            raise PermissionDenied('Only admins or pentesters can create engagements.')
        engagement = serializer.save(created_by=self.request.user)
        AuditLog.record(
            actor=self.request.user,
            action=AuditLog.Action.ENGAGEMENT_CREATE,
            target=str(engagement.pk),
            details={'engagement': engagement.name, 'via': 'api'},
        )

    def perform_destroy(self, instance):
        AuditLog.record(
            actor=self.request.user,
            action=AuditLog.Action.ENGAGEMENT_DELETE,
            target=str(instance.pk),
            details={'engagement': instance.name, 'via': 'api'},
        )
        instance.delete()

    @action(detail=True, methods=['get', 'post'], url_path='findings')
    def findings(self, request, pk=None):
        engagement = self.get_object()
        if request.method == 'GET':
            qs = engagement.findings.all()
            return Response(FindingSerializer(qs, many=True).data)
        # POST — create finding under this engagement
        if not engagement.user_can_edit(request.user):
            raise PermissionDenied('You do not have edit permissions on this engagement.')
        data = request.data.copy()
        data['engagement'] = str(engagement.pk)
        ser = FindingSerializer(data=data)
        ser.is_valid(raise_exception=True)
        finding = ser.save(found_by=request.user)
        return Response(FindingSerializer(finding).data, status=status.HTTP_201_CREATED)


class FindingViewSet(viewsets.ModelViewSet):
    serializer_class = FindingSerializer
    permission_classes = [IsEngagementEditor]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return Finding.objects.all()
        return Finding.objects.filter(
            engagement_id__in=_accessible_engagement_ids(user),
        )

    def perform_create(self, serializer):
        engagement = serializer.validated_data['engagement']
        if not engagement.user_can_edit(self.request.user):
            raise PermissionDenied('You do not have edit permissions on this engagement.')
        serializer.save(found_by=self.request.user)

    @action(detail=True, methods=['get', 'post'], url_path='evidence')
    def evidence(self, request, pk=None):
        finding = self.get_object()
        if request.method == 'GET':
            qs = finding.evidence.all()
            return Response(EvidenceSerializer(qs, many=True).data)
        if not finding.engagement.user_can_edit(request.user):
            raise PermissionDenied('You do not have edit permissions on this engagement.')
        data = request.data.copy()
        data['finding'] = str(finding.pk)
        ser = EvidenceSerializer(data=data)
        ser.is_valid(raise_exception=True)
        ev = ser.save(uploaded_by=request.user)
        return Response(EvidenceSerializer(ev).data, status=status.HTTP_201_CREATED)


class DiscoveredHostViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DiscoveredHostSerializer
    permission_classes = [IsEngagementMember]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return DiscoveredHost.objects.all()
        return DiscoveredHost.objects.filter(
            engagement_id__in=_accessible_engagement_ids(user),
        )


class CredentialViewSet(viewsets.ModelViewSet):
    serializer_class = CredentialSerializer
    permission_classes = [CredentialVaultPermission]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return Credential.objects.all()
        return Credential.objects.filter(
            engagement_id__in=_accessible_engagement_ids(user),
        )

    def perform_create(self, serializer):
        engagement = serializer.validated_data['engagement']
        role = engagement.get_user_role(self.request.user)
        if self.request.user.role != 'admin' and role not in ('lead', 'pentester'):
            raise PermissionDenied('Not permitted to create credentials here.')
        cred = serializer.save(found_by=self.request.user)
        AuditLog.record(
            actor=self.request.user,
            action=AuditLog.Action.CREDENTIAL_CREATE,
            target=str(cred.pk),
            details={'engagement': engagement.name, 'via': 'api'},
        )

    def perform_destroy(self, instance):
        AuditLog.record(
            actor=self.request.user,
            action=AuditLog.Action.CREDENTIAL_DELETE,
            target=str(instance.pk),
            details={'engagement': instance.engagement.name, 'via': 'api'},
        )
        instance.delete()

    def retrieve(self, request, *args, **kwargs):
        obj = self.get_object()
        data = self.get_serializer(obj).data
        if request.query_params.get('reveal', '').lower() in ('1', 'true', 'yes'):
            data['secret'] = obj.secret
            AuditLog.record(
                actor=request.user,
                action=AuditLog.Action.CREDENTIAL_REVEAL,
                target=str(obj.pk),
                details={'engagement': obj.engagement.name, 'via': 'api'},
            )
        return Response(data)


class ReportViewSet(viewsets.ReadOnlyModelViewSet):
    """Lists reports the caller can access and serves the PDF on a dedicated
    action so the metadata endpoint stays cheap."""
    serializer_class = ReportSerializer
    permission_classes = [IsEngagementMember]

    def get_queryset(self):
        user = self.request.user
        if user.role == 'admin':
            return Report.objects.all()
        return Report.objects.filter(
            engagement_id__in=_accessible_engagement_ids(user),
        )

    @action(detail=True, methods=['get'], url_path='pdf')
    def pdf(self, request, pk=None):
        report = self.get_object()
        if not report.file:
            return Response({'detail': 'Report file missing.'}, status=404)
        AuditLog.record(
            actor=request.user,
            action=AuditLog.Action.REPORT_DOWNLOADED,
            target=str(report.pk),
            details={'engagement': report.engagement.name, 'via': 'api'},
        )
        report.file.open('rb')
        return FileResponse(report.file, content_type='application/pdf')
