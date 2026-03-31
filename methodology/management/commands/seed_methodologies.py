"""Seed default testing methodologies (OWASP WSTG, PTES)."""
from django.core.management.base import BaseCommand
from methodology.models import Methodology, ChecklistCategory, ChecklistItem


OWASP_WSTG = {
    'name': 'OWASP WSTG v4.2',
    'description': 'OWASP Web Security Testing Guide — comprehensive web application testing checklist.',
    'categories': {
        'Information Gathering': [
            ('WSTG-INFO-01', 'Conduct search engine discovery and reconnaissance'),
            ('WSTG-INFO-02', 'Fingerprint web server'),
            ('WSTG-INFO-03', 'Review webserver metafiles for information leakage'),
            ('WSTG-INFO-04', 'Enumerate applications on webserver'),
            ('WSTG-INFO-05', 'Review webpage content for information leakage'),
            ('WSTG-INFO-06', 'Identify application entry points'),
            ('WSTG-INFO-07', 'Map execution paths through application'),
            ('WSTG-INFO-08', 'Fingerprint web application framework'),
            ('WSTG-INFO-09', 'Fingerprint web application'),
            ('WSTG-INFO-10', 'Map application architecture'),
        ],
        'Configuration and Deploy Management': [
            ('WSTG-CONF-01', 'Test network infrastructure configuration'),
            ('WSTG-CONF-02', 'Test application platform configuration'),
            ('WSTG-CONF-03', 'Test file extensions handling for sensitive information'),
            ('WSTG-CONF-04', 'Review old backup and unreferenced files'),
            ('WSTG-CONF-05', 'Enumerate infrastructure and application admin interfaces'),
            ('WSTG-CONF-06', 'Test HTTP methods'),
            ('WSTG-CONF-07', 'Test HTTP strict transport security'),
            ('WSTG-CONF-08', 'Test RIA cross domain policy'),
            ('WSTG-CONF-09', 'Test file permission'),
            ('WSTG-CONF-10', 'Test for subdomain takeover'),
            ('WSTG-CONF-11', 'Test cloud storage'),
        ],
        'Identity Management': [
            ('WSTG-IDNT-01', 'Test role definitions'),
            ('WSTG-IDNT-02', 'Test user registration process'),
            ('WSTG-IDNT-03', 'Test account provisioning process'),
            ('WSTG-IDNT-04', 'Test for account enumeration and guessable user account'),
            ('WSTG-IDNT-05', 'Test for weak or unenforced username policy'),
        ],
        'Authentication': [
            ('WSTG-ATHN-01', 'Test for credentials transported over an encrypted channel'),
            ('WSTG-ATHN-02', 'Test for default credentials'),
            ('WSTG-ATHN-03', 'Test for weak lock out mechanism'),
            ('WSTG-ATHN-04', 'Test for bypassing authentication schema'),
            ('WSTG-ATHN-05', 'Test remember password functionality'),
            ('WSTG-ATHN-06', 'Test for browser cache weaknesses'),
            ('WSTG-ATHN-07', 'Test for weak password policy'),
            ('WSTG-ATHN-08', 'Test for weak security question answer'),
            ('WSTG-ATHN-09', 'Test for weak password change or reset functionalities'),
            ('WSTG-ATHN-10', 'Test for weaker authentication in alternative channel'),
        ],
        'Authorization': [
            ('WSTG-ATHZ-01', 'Test directory traversal / file include'),
            ('WSTG-ATHZ-02', 'Test for bypassing authorization schema'),
            ('WSTG-ATHZ-03', 'Test for privilege escalation'),
            ('WSTG-ATHZ-04', 'Test for insecure direct object references'),
        ],
        'Session Management': [
            ('WSTG-SESS-01', 'Test for session management schema'),
            ('WSTG-SESS-02', 'Test for cookies attributes'),
            ('WSTG-SESS-03', 'Test for session fixation'),
            ('WSTG-SESS-04', 'Test for exposed session variables'),
            ('WSTG-SESS-05', 'Test for CSRF'),
            ('WSTG-SESS-06', 'Test for logout functionality'),
            ('WSTG-SESS-07', 'Test session timeout'),
            ('WSTG-SESS-08', 'Test for session puzzling'),
            ('WSTG-SESS-09', 'Test for session hijacking'),
        ],
        'Input Validation': [
            ('WSTG-INPV-01', 'Test for reflected cross-site scripting'),
            ('WSTG-INPV-02', 'Test for stored cross-site scripting'),
            ('WSTG-INPV-03', 'Test for HTTP verb tampering'),
            ('WSTG-INPV-04', 'Test for HTTP parameter pollution'),
            ('WSTG-INPV-05', 'Test for SQL injection'),
            ('WSTG-INPV-06', 'Test for LDAP injection'),
            ('WSTG-INPV-07', 'Test for XML injection'),
            ('WSTG-INPV-08', 'Test for SSI injection'),
            ('WSTG-INPV-09', 'Test for XPath injection'),
            ('WSTG-INPV-10', 'Test for IMAP SMTP injection'),
            ('WSTG-INPV-11', 'Test for code injection'),
            ('WSTG-INPV-12', 'Test for command injection'),
            ('WSTG-INPV-13', 'Test for format string injection'),
            ('WSTG-INPV-14', 'Test for incubated vulnerability'),
            ('WSTG-INPV-15', 'Test for HTTP splitting smuggling'),
            ('WSTG-INPV-16', 'Test for HTTP incoming requests'),
            ('WSTG-INPV-17', 'Test for host header injection'),
            ('WSTG-INPV-18', 'Test for server-side template injection'),
            ('WSTG-INPV-19', 'Test for SSRF'),
        ],
        'Error Handling': [
            ('WSTG-ERRH-01', 'Test for improper error handling'),
            ('WSTG-ERRH-02', 'Test for stack traces'),
        ],
        'Cryptography': [
            ('WSTG-CRYP-01', 'Test for weak transport layer security'),
            ('WSTG-CRYP-02', 'Test for padding oracle'),
            ('WSTG-CRYP-03', 'Test for sensitive information sent via unencrypted channels'),
            ('WSTG-CRYP-04', 'Test for weak encryption'),
        ],
        'Business Logic': [
            ('WSTG-BUSL-01', 'Test business logic data validation'),
            ('WSTG-BUSL-02', 'Test ability to forge requests'),
            ('WSTG-BUSL-03', 'Test integrity checks'),
            ('WSTG-BUSL-04', 'Test for process timing'),
            ('WSTG-BUSL-05', 'Test number of times a function can be used'),
            ('WSTG-BUSL-06', 'Test for circumvention of work flows'),
            ('WSTG-BUSL-07', 'Test defenses against application misuse'),
            ('WSTG-BUSL-08', 'Test upload of unexpected file types'),
            ('WSTG-BUSL-09', 'Test upload of malicious files'),
        ],
        'Client-Side': [
            ('WSTG-CLNT-01', 'Test for DOM-based cross-site scripting'),
            ('WSTG-CLNT-02', 'Test for JavaScript execution'),
            ('WSTG-CLNT-03', 'Test for HTML injection'),
            ('WSTG-CLNT-04', 'Test for client-side URL redirect'),
            ('WSTG-CLNT-05', 'Test for CSS injection'),
            ('WSTG-CLNT-06', 'Test for client-side resource manipulation'),
            ('WSTG-CLNT-07', 'Test cross-origin resource sharing'),
            ('WSTG-CLNT-08', 'Test for cross-site flashing'),
            ('WSTG-CLNT-09', 'Test for clickjacking'),
            ('WSTG-CLNT-10', 'Test WebSockets'),
            ('WSTG-CLNT-11', 'Test web messaging'),
            ('WSTG-CLNT-12', 'Test browser storage'),
            ('WSTG-CLNT-13', 'Test for cross-site script inclusion'),
        ],
    }
}


class Command(BaseCommand):
    help = 'Seed default testing methodologies (OWASP WSTG)'

    def handle(self, *args, **options):
        created = self._seed_methodology(OWASP_WSTG)
        if created:
            self.stdout.write(self.style.SUCCESS(f'Created methodology: {OWASP_WSTG["name"]}'))
        else:
            self.stdout.write(f'Methodology already exists: {OWASP_WSTG["name"]}')

    def _seed_methodology(self, data):
        if Methodology.objects.filter(name=data['name']).exists():
            return False

        methodology = Methodology.objects.create(
            name=data['name'],
            description=data['description'],
            is_default=True,
        )

        for order, (cat_name, items) in enumerate(data['categories'].items()):
            category = ChecklistCategory.objects.create(
                methodology=methodology,
                name=cat_name,
                order=order,
            )
            for item_order, (ref_id, title) in enumerate(items):
                ChecklistItem.objects.create(
                    category=category,
                    reference_id=ref_id,
                    title=title,
                    order=item_order,
                )

        return True
