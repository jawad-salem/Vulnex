from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'

    def ready(self):
        # Import for side effect: registers OpenApiAuthenticationExtension
        # subclasses so drf-spectacular discovers them.
        from . import schema_extensions  # noqa: F401
