from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import (
    CredentialViewSet,
    DiscoveredHostViewSet,
    EngagementViewSet,
    FindingViewSet,
    ReportViewSet,
)

router = DefaultRouter()
router.register(r'engagements', EngagementViewSet, basename='engagement')
router.register(r'findings', FindingViewSet, basename='finding')
router.register(r'hosts', DiscoveredHostViewSet, basename='host')
router.register(r'credentials', CredentialViewSet, basename='credential')
router.register(r'reports', ReportViewSet, basename='report')

urlpatterns = [
    path('v1/', include(router.urls)),
    path('v1/auth/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('v1/auth/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('schema/', SpectacularAPIView.as_view(), name='schema'),
    path('docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='docs'),
]
