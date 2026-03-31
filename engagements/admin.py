from django.contrib import admin
from .models import Engagement, EngagementNote, ActivityLog


@admin.register(Engagement)
class EngagementAdmin(admin.ModelAdmin):
    list_display = ('name', 'client_name', 'engagement_type', 'status', 'lead', 'start_date')
    list_filter = ('status', 'engagement_type')
    search_fields = ('name', 'client_name')


@admin.register(EngagementNote)
class EngagementNoteAdmin(admin.ModelAdmin):
    list_display = ('engagement', 'author', 'created_at')


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('engagement', 'user', 'action', 'timestamp')

