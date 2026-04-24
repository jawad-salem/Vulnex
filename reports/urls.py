from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('engagement/<uuid:engagement_pk>/', views.report_dashboard, name='dashboard'),
    path('generate/<uuid:engagement_pk>/', views.generate_report, name='generate'),
    path('download/<uuid:pk>/', views.download_report, name='download'),
    path('preview/<uuid:engagement_pk>/', views.preview_report, name='preview'),

    # Report template library (admin only)
    path('templates/', views.template_list, name='template_list'),
    path('templates/new/', views.template_create, name='template_create'),
    path('templates/<uuid:pk>/edit/', views.template_edit, name='template_edit'),
    path('templates/<uuid:pk>/delete/', views.template_delete, name='template_delete'),
    path('templates/<uuid:pk>/preview/', views.template_preview, name='template_preview'),
]
