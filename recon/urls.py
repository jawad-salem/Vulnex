from django.urls import path
from . import views

app_name = 'recon'

urlpatterns = [
    path('engagement/<uuid:engagement_pk>/', views.recon_dashboard, name='dashboard'),
    path('engagement/<uuid:engagement_pk>/scan/', views.start_scan, name='start_scan'),
    path('engagement/<uuid:engagement_pk>/import-nmap/', views.import_nmap, name='import_nmap'),
    path('scan/<uuid:pk>/', views.scan_detail, name='scan_detail'),
    path('scan/<uuid:pk>/delete/', views.scan_delete, name='scan_delete'),
    # Scheduled scans
    path('engagement/<uuid:engagement_pk>/schedule/', views.create_scheduled_scan, name='create_scheduled'),
    path('engagement/<uuid:engagement_pk>/schedule/<uuid:pk>/toggle/', views.toggle_scheduled_scan, name='toggle_scheduled'),
    path('engagement/<uuid:engagement_pk>/schedule/<uuid:pk>/delete/', views.delete_scheduled_scan, name='delete_scheduled'),
    # Scan pipelines
    path('engagement/<uuid:engagement_pk>/pipeline/', views.start_pipeline, name='start_pipeline'),
    path('engagement/<uuid:engagement_pk>/pipeline/<uuid:pk>/', views.pipeline_detail, name='pipeline_detail'),
    # Host management
    path('engagement/<uuid:engagement_pk>/host/add/', views.host_add, name='host_add'),
    path('engagement/<uuid:engagement_pk>/host/<int:host_pk>/', views.host_detail, name='host_detail'),
    path('engagement/<uuid:engagement_pk>/host/<int:host_pk>/edit/', views.host_edit, name='host_edit'),
    path('engagement/<uuid:engagement_pk>/host/<int:host_pk>/delete/', views.host_delete, name='host_delete'),
]
