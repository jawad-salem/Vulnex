from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework.routers import APIRootView, DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .permissions import IsStaffOrPentester
from .views import (
    CredentialViewSet,
    DiscoveredHostViewSet,
    EngagementViewSet,
    FindingViewSet,
    ReportViewSet,
)
from .serializers import MFAAwareTokenObtainPairSerializer


class _StaffAPIRootView(APIRootView):
    """Gate the auto-generated /api/v1/ index — reviewers and clients have no
    programmatic-access use case and shouldn't enumerate the API surface."""
    permission_classes = [IsStaffOrPentester]


class _StaffOnlyRouter(DefaultRouter):
    APIRootView = _StaffAPIRootView


class MFAAwareTokenObtainPairView(TokenObtainPairView):
    serializer_class = MFAAwareTokenObtainPairSerializer


router = _StaffOnlyRouter()
router.register(r'engagements', EngagementViewSet, basename='engagement')
router.register(r'findings', FindingViewSet, basename='finding')
router.register(r'hosts', DiscoveredHostViewSet, basename='host')
router.register(r'credentials', CredentialViewSet, basename='credential')
router.register(r'reports', ReportViewSet, basename='report')

urlpatterns = [
    path('v1/', include(router.urls)),
    path('v1/auth/token/', MFAAwareTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('v1/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path(
        'schema/',
        SpectacularAPIView.as_view(permission_classes=[IsStaffOrPentester]),
        name='schema',
    ),
    path(
        'docs/',
        SpectacularSwaggerView.as_view(
            url_name='schema', permission_classes=[IsStaffOrPentester],
        ),
        name='docs',
    ),
]
