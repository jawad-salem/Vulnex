from django.contrib import admin
from .models import ReconScan, DiscoveredHost


@admin.register(ReconScan)
class ReconScanAdmin(admin.ModelAdmin):
    list_display = ('scan_type', 'target', 'status', 'engagement', 'created_at')
    list_filter = ('scan_type', 'status')


@admin.register(DiscoveredHost)
class DiscoveredHostAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'ip_address', 'engagement', 'created_at')

