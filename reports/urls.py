from django.urls import path
from . import views

app_name = 'reports'

urlpatterns = [
    path('generate/<uuid:engagement_pk>/', views.generate_report, name='generate'),
    path('download/<uuid:pk>/', views.download_report, name='download'),
    path('preview/<uuid:engagement_pk>/', views.preview_report, name='preview'),
]

