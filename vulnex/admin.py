from django.contrib import admin
from django.contrib.auth.models import Group
from django.contrib.auth.views import redirect_to_login
from django.urls import reverse


class VulnexAdminSite(admin.AdminSite):
    site_header = 'Vulnex Admin'
    site_title = 'Vulnex Admin'

    def login(self, request, extra_context=None):
        # The default admin password form would bypass the shared MFA flow.
        return redirect_to_login(reverse('admin:index'), reverse('accounts:login'))

    def has_permission(self, request):
        """Only allow superusers or users with admin role to access the admin panel."""
        if not super().has_permission(request):
            return False
        return request.user.is_superuser or (
            hasattr(request.user, 'role') and request.user.role == 'admin'
        )


# Hide Django's built-in Group model — Vulnex uses its own role system
admin.site.unregister(Group)
