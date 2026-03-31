from django.urls import path
from . import views

app_name = 'methodology'

urlpatterns = [
    path('engagement/<uuid:engagement_pk>/', views.methodology_dashboard, name='dashboard'),
    path('engagement/<uuid:engagement_pk>/apply/<uuid:methodology_pk>/', views.apply_methodology, name='apply'),
    path('engagement/<uuid:engagement_pk>/item/<int:item_id>/', views.update_checklist_item, name='update_item'),
]

