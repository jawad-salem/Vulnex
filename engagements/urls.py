from django.urls import path
from . import views

app_name = 'engagements'

urlpatterns = [
    path('', views.engagement_list, name='list'),
    path('new/', views.engagement_create, name='create'),
    # Clients directory — must come before <uuid:pk>/ so "clients" isn't parsed as one
    path('clients/', views.client_list, name='client_list'),
    path('clients/<uuid:pk>/', views.client_detail, name='client_detail'),
    path('<uuid:pk>/', views.engagement_detail, name='detail'),
    path('<uuid:pk>/edit/', views.engagement_edit, name='edit'),
    path('<uuid:pk>/delete/', views.engagement_delete, name='delete'),
    path('<uuid:pk>/status/', views.engagement_update_status, name='update_status'),
    # Team management
    path('<uuid:pk>/invite/', views.invite_member, name='invite'),
    path('<uuid:pk>/remove/<uuid:member_pk>/', views.remove_member, name='remove_member'),
    path('<uuid:pk>/cancel-invite/<uuid:invitation_pk>/', views.cancel_invitation, name='cancel_invitation'),
    path('join/<uuid:token>/', views.accept_invitation, name='accept_invitation'),
]

