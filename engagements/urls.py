from django.urls import path
from . import views

app_name = 'engagements'

urlpatterns = [
    path('', views.engagement_list, name='list'),
    path('new/', views.engagement_create, name='create'),
    # Clients directory — must come before <uuid:pk>/ so "clients" isn't parsed as one
    path('clients/', views.client_list, name='client_list'),
    path('clients/new/', views.client_create, name='client_create'),
    path('clients/<uuid:pk>/', views.client_detail, name='client_detail'),
    path('clients/<uuid:pk>/edit/', views.client_edit, name='client_edit'),
    path('clients/<uuid:pk>/delete/', views.client_delete, name='client_delete'),
    path('<uuid:pk>/', views.engagement_detail, name='detail'),
    path('<uuid:pk>/edit/', views.engagement_edit, name='edit'),
    path('<uuid:pk>/delete/', views.engagement_delete, name='delete'),
    path('<uuid:pk>/status/', views.engagement_update_status, name='update_status'),
    # Team management
    path('<uuid:pk>/invite/', views.invite_member, name='invite'),
    path('<uuid:pk>/remove/<uuid:member_pk>/', views.remove_member, name='remove_member'),
    path('<uuid:pk>/cancel-invite/<uuid:invitation_pk>/', views.cancel_invitation, name='cancel_invitation'),
    path('join/<uuid:token>/', views.accept_invitation, name='accept_invitation'),
    # Attack-path mapper (red-team engagements)
    path('<uuid:pk>/attack-paths/', views.attack_path_list, name='attack_path_list'),
    path('<uuid:pk>/attack-paths/<uuid:path_pk>/', views.attack_path_detail, name='attack_path_detail'),
    path('<uuid:pk>/attack-paths/<uuid:path_pk>/data/', views.attack_path_data, name='attack_path_data'),
    path('<uuid:pk>/attack-paths/<uuid:path_pk>/delete/', views.attack_path_delete, name='attack_path_delete'),
    path('<uuid:pk>/attack-paths/<uuid:path_pk>/nodes/add/', views.attack_path_node_create, name='attack_path_node_create'),
    path('<uuid:pk>/attack-paths/<uuid:path_pk>/nodes/<uuid:node_pk>/delete/', views.attack_path_node_delete, name='attack_path_node_delete'),
    path('<uuid:pk>/attack-paths/<uuid:path_pk>/edges/add/', views.attack_path_edge_create, name='attack_path_edge_create'),
    path('<uuid:pk>/attack-paths/<uuid:path_pk>/edges/<uuid:edge_pk>/delete/', views.attack_path_edge_delete, name='attack_path_edge_delete'),
]

