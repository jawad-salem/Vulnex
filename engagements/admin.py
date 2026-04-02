from django.contrib import admin
from .models import Engagement, EngagementNote, EngagementMember, Invitation, ActivityLog


@admin.register(Engagement)
class EngagementAdmin(admin.ModelAdmin):
    list_display = ('name', 'client_name', 'engagement_type', 'status', 'created_by', 'start_date')
    list_filter = ('status', 'engagement_type')
    search_fields = ('name', 'client_name')


@admin.register(EngagementMember)
class EngagementMemberAdmin(admin.ModelAdmin):
    list_display = ('engagement', 'user', 'role', 'joined_at')
    list_filter = ('role',)


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ('email', 'engagement', 'role', 'status', 'created_at')
    list_filter = ('status', 'role')


@admin.register(EngagementNote)
class EngagementNoteAdmin(admin.ModelAdmin):
    list_display = ('engagement', 'author', 'created_at')


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('engagement', 'user', 'action', 'timestamp')

