from django.contrib import admin
from django.contrib.auth.models import Group


class VulnexAdminSite(admin.AdminSite):
    site_header = 'Vulnex Admin'
    site_title = 'Vulnex Admin'

    def has_permission(self, request):
        """Only allow superusers or users with admin role to access the admin panel."""
        if not super().has_permission(request):
            return False
        return request.user.is_superuser or (
            hasattr(request.user, 'role') and request.user.role == 'admin'
        )


# Hide Django's built-in Group model — Vulnex uses its own role system
admin.site.unregister(Group)
