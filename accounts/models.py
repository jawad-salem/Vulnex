from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    class Role(models.TextChoices):
        ADMIN = 'admin', 'Admin'
        PENTESTER = 'pentester', 'Pentester'
        VIEWER = 'viewer', 'Viewer'

    role = models.CharField(max_length=20, choices=Role.choices, default=Role.PENTESTER)
    bio = models.TextField(blank=True)
    avatar_color = models.CharField(max_length=7, default='#534AB7')

    @property
    def initials(self):
        first = self.first_name[:1].upper() if self.first_name else ''
        last = self.last_name[:1].upper() if self.last_name else ''
        return first + last or self.username[:2].upper()

    @property
    def is_admin(self):
        return self.role == self.Role.ADMIN

    @property
    def is_pentester(self):
        return self.role in (self.Role.ADMIN, self.Role.PENTESTER)

    @property
    def is_viewer(self):
        return True  # Everyone can view

    def __str__(self):
        return self.get_full_name() or self.username

