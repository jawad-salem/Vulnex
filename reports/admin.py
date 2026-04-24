from django.contrib import admin
from .models import Report, ReportTemplate


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'report_type', 'engagement', 'generated_by', 'created_at')


@admin.register(ReportTemplate)
class ReportTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_default', 'primary_color', 'accent_color', 'created_at')
    list_filter = ('is_default',)
    search_fields = ('name',)
