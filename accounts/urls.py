from django.urls import path
from . import views

app_name = 'accounts'

urlpatterns = [
    path('login/', views.CustomLoginView.as_view(), name='login'),
    path('logout/', views.CustomLogoutView.as_view(), name='logout'),
    path('profile/', views.profile, name='profile'),
    # MFA
    path('mfa/setup/', views.mfa_setup, name='mfa_setup'),
    path('mfa/verify/', views.mfa_verify, name='mfa_verify'),
    path('mfa/disable/', views.mfa_disable, name='mfa_disable'),
    # Admin user management
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<int:pk>/edit/', views.user_edit, name='user_edit'),
    path('users/<int:pk>/delete/', views.user_delete, name='user_delete'),
    path('audit/', views.audit_log, name='audit_log'),
    # API keys (per-user, self-managed)
    path('api-keys/', views.api_key_list, name='api_key_list'),
    path('api-keys/create/', views.api_key_create, name='api_key_create'),
    path('api-keys/<uuid:pk>/revoke/', views.api_key_revoke, name='api_key_revoke'),
]
