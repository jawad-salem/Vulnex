from django.contrib import admin
from .models import Finding, Evidence, FindingTemplate


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'status', 'engagement', 'cvss_score', 'created_at')
    list_filter = ('severity', 'status')
    search_fields = ('title', 'description')


@admin.register(Evidence)
class EvidenceAdmin(admin.ModelAdmin):
    list_display = ('finding', 'caption', 'uploaded_by', 'uploaded_at')


@admin.register(FindingTemplate)
class FindingTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'severity', 'cwe_id')
    search_fields = ('name', 'title')

