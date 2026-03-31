from django.contrib import admin
from .models import Methodology, ChecklistCategory, ChecklistItem, EngagementChecklist


class ChecklistItemInline(admin.TabularInline):
    model = ChecklistItem
    extra = 1


class ChecklistCategoryInline(admin.TabularInline):
    model = ChecklistCategory
    extra = 1


@admin.register(Methodology)
class MethodologyAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_default', 'created_at')
    inlines = [ChecklistCategoryInline]


@admin.register(ChecklistCategory)
class ChecklistCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'methodology', 'order')
    inlines = [ChecklistItemInline]


@admin.register(EngagementChecklist)
class EngagementChecklistAdmin(admin.ModelAdmin):
    list_display = ('engagement', 'checklist_item', 'status', 'completed_by')
    list_filter = ('status',)

