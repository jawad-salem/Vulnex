from django.urls import path
from . import views

app_name = 'engagements'

urlpatterns = [
    path('', views.engagement_list, name='list'),
    path('new/', views.engagement_create, name='create'),
    path('<uuid:pk>/', views.engagement_detail, name='detail'),
    path('<uuid:pk>/edit/', views.engagement_edit, name='edit'),
    path('<uuid:pk>/delete/', views.engagement_delete, name='delete'),
    path('<uuid:pk>/status/', views.engagement_update_status, name='update_status'),
]

