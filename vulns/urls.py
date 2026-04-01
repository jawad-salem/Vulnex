from django.urls import path
from . import views

app_name = 'vulns'

urlpatterns = [
    path('engagement/<uuid:engagement_pk>/', views.finding_list, name='list'),
    path('engagement/<uuid:engagement_pk>/new/', views.finding_create, name='create'),
    path('engagement/<uuid:engagement_pk>/import/', views.tool_import, name='import'),
    path('<uuid:pk>/', views.finding_detail, name='detail'),
    path('<uuid:pk>/edit/', views.finding_edit, name='edit'),
    path('<uuid:pk>/delete/', views.finding_delete, name='delete'),
]

