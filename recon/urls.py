from django.urls import path
from . import views

app_name = 'recon'

urlpatterns = [
    path('engagement/<uuid:engagement_pk>/', views.recon_dashboard, name='dashboard'),
    path('engagement/<uuid:engagement_pk>/scan/', views.start_scan, name='start_scan'),
    path('engagement/<uuid:engagement_pk>/import-nmap/', views.import_nmap, name='import_nmap'),
    path('scan/<uuid:pk>/', views.scan_detail, name='scan_detail'),
    path('scan/<uuid:pk>/delete/', views.scan_delete, name='scan_delete'),
]

