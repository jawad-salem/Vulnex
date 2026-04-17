from django.urls import path
from . import views

app_name = 'credentials'

urlpatterns = [
    path('engagement/<uuid:engagement_pk>/', views.credential_list, name='list'),
    path('engagement/<uuid:engagement_pk>/new/', views.credential_create, name='create'),
    path('engagement/<uuid:engagement_pk>/<uuid:pk>/edit/', views.credential_edit, name='edit'),
    path('engagement/<uuid:engagement_pk>/<uuid:pk>/delete/', views.credential_delete, name='delete'),
    path('engagement/<uuid:engagement_pk>/<uuid:pk>/reveal/', views.credential_reveal, name='reveal'),
]
