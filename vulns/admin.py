from django.contrib import admin
from .models import Finding, Evidence


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'status', 'engagement', 'cvss_score', 'created_at')
    list_filter = ('severity', 'status')
    search_fields = ('title', 'description')


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ('finding', 'caption', 'uploaded_by', 'uploaded_at')

