"""drf-spectacular extensions.

Registers an OpenAPI security scheme for `APIKeyAuthentication` so
`/api/schema/` advertises both JWT and API-key auth surfaces and Swagger UI
shows an Authorize button for the API-key flow. Without this, spectacular
emits a runtime warning and the security definition is missing from the
generated schema.
"""
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class APIKeyAuthenticationScheme(OpenApiAuthenticationExtension):
    target_class = 'api.authentication.APIKeyAuthentication'
    name = 'ApiKeyAuth'

    def get_security_definition(self, auto_schema):
        return {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': (
                'Vulnex API key. Send as `Authorization: ApiKey '
                'vlnx_<prefix>_<secret>`.'
            ),
        }
