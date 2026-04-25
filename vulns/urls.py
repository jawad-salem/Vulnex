from django.urls import path
from . import views

app_name = 'vulns'

urlpatterns = [
    path('engagement/<uuid:engagement_pk>/', views.finding_list, name='list'),
    path('engagement/<uuid:engagement_pk>/new/', views.finding_create, name='create'),
    path('engagement/<uuid:engagement_pk>/import/', views.tool_import, name='import'),
    path('engagement/<uuid:engagement_pk>/import-csv/', views.finding_import_csv, name='import_csv'),
    path('<uuid:pk>/', views.finding_detail, name='detail'),
    path('<uuid:pk>/edit/', views.finding_edit, name='edit'),
    path('<uuid:pk>/delete/', views.finding_delete, name='delete'),
    path('<uuid:pk>/submit-review/', views.submit_for_review, name='submit_review'),
    path('<uuid:pk>/approve/', views.approve_finding, name='approve'),
    path('<uuid:pk>/request-changes/', views.request_changes, name='request_changes'),
    path('<uuid:pk>/merge/', views.finding_merge, name='merge'),
    path('evidence/<int:pk>/download/', views.evidence_download, name='evidence_download'),
    path('comment/<uuid:pk>/edit/', views.comment_edit, name='comment_edit'),
    path('comment/<uuid:pk>/delete/', views.comment_delete, name='comment_delete'),
    path('engagement/<uuid:engagement_pk>/export/csv/', views.export_csv, name='export_csv'),
    path('engagement/<uuid:engagement_pk>/export/json/', views.export_json, name='export_json'),
    # API endpoints for form auto-fill
    path('api/template/<int:pk>/', views.api_template_detail, name='api_template'),
    path('api/host/<int:pk>/', views.api_host_detail, name='api_host'),
    path('api/markdown-preview/', views.markdown_preview, name='markdown_preview'),
]

