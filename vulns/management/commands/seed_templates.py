from django.core.management.base import BaseCommand
from vulns.models import FindingTemplate

TEMPLATES = [
    {
        'name': 'Cross-Site Scripting (XSS) — Reflected',
        'title': 'Reflected Cross-Site Scripting (XSS)',
        'severity': 'medium',
        'description': (
            'A reflected cross-site scripting (XSS) vulnerability was identified. '
            'User-supplied input is reflected in the application response without proper '
            'sanitization or encoding, allowing an attacker to inject arbitrary JavaScript '
            'code that executes in the context of a victim\'s browser session.\n\n'
            'An attacker can craft a malicious URL that, when clicked by a victim, executes '
            'arbitrary JavaScript in their browser. This can be used to steal session cookies, '
            'redirect users to malicious sites, or perform actions on behalf of the victim.'
        ),
        'remediation': (
            '1. Implement context-aware output encoding for all user-supplied data.\n'
            '2. Use Content Security Policy (CSP) headers to restrict inline script execution.\n'
            '3. Set the HttpOnly flag on session cookies to prevent JavaScript access.\n'
            '4. Use a templating engine that auto-escapes output by default.\n'
            '5. Validate and sanitize all input on the server side.'
        ),
        'references': (
            'https://owasp.org/www-community/attacks/xss/\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-79',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'R',
        'confidentiality_impact': 'L', 'integrity_impact': 'L', 'availability_impact': 'N',
    },
    {
        'name': 'Cross-Site Scripting (XSS) — Stored',
        'title': 'Stored Cross-Site Scripting (XSS)',
        'severity': 'high',
        'description': (
            'A stored cross-site scripting (XSS) vulnerability was identified. '
            'User-supplied input is stored in the application (e.g. database) and rendered '
            'in responses to other users without proper sanitization, allowing persistent '
            'injection of arbitrary JavaScript code.\n\n'
            'Unlike reflected XSS, stored XSS does not require the victim to click a crafted link. '
            'Any user who views the affected page will have the malicious script executed in their browser.'
        ),
        'remediation': (
            '1. Implement context-aware output encoding for all stored user data.\n'
            '2. Sanitize HTML input using an allowlist-based sanitizer (e.g. DOMPurify).\n'
            '3. Use Content Security Policy (CSP) headers.\n'
            '4. Set HttpOnly and Secure flags on session cookies.\n'
            '5. Validate and sanitize all input on the server side before storage.'
        ),
        'references': (
            'https://owasp.org/www-community/attacks/xss/\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-79',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'L', 'user_interaction': 'R',
        'confidentiality_impact': 'L', 'integrity_impact': 'L', 'availability_impact': 'N',
    },
    {
        'name': 'SQL Injection',
        'title': 'SQL Injection',
        'severity': 'critical',
        'description': (
            'An SQL injection vulnerability was identified. The application incorporates '
            'user-supplied input into SQL queries without proper parameterization, allowing '
            'an attacker to manipulate the query logic.\n\n'
            'Successful exploitation can allow an attacker to read, modify, or delete data '
            'in the database, bypass authentication, or in some cases execute operating system '
            'commands on the database server.'
        ),
        'remediation': (
            '1. Use parameterized queries (prepared statements) for all database interactions.\n'
            '2. Use an ORM that handles parameterization automatically.\n'
            '3. Apply the principle of least privilege to database accounts.\n'
            '4. Implement input validation using allowlists where possible.\n'
            '5. Deploy a Web Application Firewall (WAF) as defense-in-depth.'
        ),
        'references': (
            'https://owasp.org/www-community/attacks/SQL_Injection\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-89',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'H', 'availability_impact': 'H',
    },
    {
        'name': 'Insecure Direct Object Reference (IDOR)',
        'title': 'Insecure Direct Object Reference (IDOR)',
        'severity': 'high',
        'description': (
            'An Insecure Direct Object Reference (IDOR) vulnerability was identified. '
            'The application exposes internal object references (such as database IDs or file names) '
            'and does not verify that the requesting user is authorized to access the referenced object.\n\n'
            'An attacker can modify the reference parameter to access or manipulate resources '
            'belonging to other users, such as viewing other users\' profiles, downloading private '
            'files, or modifying other users\' data.'
        ),
        'remediation': (
            '1. Implement proper authorization checks on every request that accesses user-specific resources.\n'
            '2. Use indirect references (e.g. mapping UUIDs) instead of sequential database IDs.\n'
            '3. Verify object ownership on the server side before granting access.\n'
            '4. Log and monitor for access control failures.'
        ),
        'references': (
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-639',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'L', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'H', 'availability_impact': 'N',
    },
    {
        'name': 'Cross-Site Request Forgery (CSRF)',
        'title': 'Cross-Site Request Forgery (CSRF)',
        'severity': 'medium',
        'description': (
            'A Cross-Site Request Forgery (CSRF) vulnerability was identified. '
            'The application does not adequately verify that state-changing requests originate '
            'from the authenticated user\'s intentional action.\n\n'
            'An attacker can host a malicious page that automatically submits requests to the '
            'vulnerable application on behalf of an authenticated victim who visits the attacker\'s page.'
        ),
        'remediation': (
            '1. Implement anti-CSRF tokens (synchronizer tokens) on all state-changing forms.\n'
            '2. Use the SameSite cookie attribute (Lax or Strict).\n'
            '3. Verify the Origin and Referer headers on state-changing requests.\n'
            '4. Require re-authentication for sensitive operations.'
        ),
        'references': (
            'https://owasp.org/www-community/attacks/csrf\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-352',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'R',
        'confidentiality_impact': 'N', 'integrity_impact': 'L', 'availability_impact': 'N',
    },
    {
        'name': 'Server-Side Request Forgery (SSRF)',
        'title': 'Server-Side Request Forgery (SSRF)',
        'severity': 'high',
        'description': (
            'A Server-Side Request Forgery (SSRF) vulnerability was identified. '
            'The application makes server-side HTTP requests using user-supplied URLs without '
            'adequate validation, allowing an attacker to make the server send requests to '
            'arbitrary internal or external destinations.\n\n'
            'This can be used to scan internal networks, access internal services (e.g. cloud metadata APIs), '
            'read local files, or pivot to further attacks against internal infrastructure.'
        ),
        'remediation': (
            '1. Validate and sanitize all user-supplied URLs using an allowlist of permitted domains.\n'
            '2. Block requests to private/internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).\n'
            '3. Disable unnecessary URL schemes (only allow http/https).\n'
            '4. Use network-level controls to restrict outbound traffic from application servers.\n'
            '5. Do not return raw responses from fetched URLs to the user.'
        ),
        'references': (
            'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-918',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'L', 'availability_impact': 'N',
    },
    {
        'name': 'Broken Authentication',
        'title': 'Broken Authentication',
        'severity': 'high',
        'description': (
            'A broken authentication vulnerability was identified. The application\'s authentication '
            'mechanism has weaknesses that could allow an attacker to compromise user accounts. '
            'This may include weak password policies, lack of brute-force protection, insecure session '
            'management, or credential exposure.\n\n'
            'Successful exploitation allows an attacker to assume the identity of other users, '
            'potentially including administrative accounts.'
        ),
        'remediation': (
            '1. Implement multi-factor authentication (MFA).\n'
            '2. Enforce strong password policies (minimum length, complexity requirements).\n'
            '3. Implement account lockout or rate limiting after failed login attempts.\n'
            '4. Use secure session management (random session IDs, proper expiration, secure cookie flags).\n'
            '5. Never expose credentials in URLs, logs, or error messages.'
        ),
        'references': (
            'https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-287',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'H', 'availability_impact': 'N',
    },
    {
        'name': 'Security Misconfiguration',
        'title': 'Security Misconfiguration',
        'severity': 'medium',
        'description': (
            'A security misconfiguration was identified. The application or its underlying infrastructure '
            'is configured in a way that introduces security risks. This may include default credentials, '
            'unnecessary services enabled, verbose error messages, missing security headers, or '
            'overly permissive CORS policies.\n\n'
            'Misconfigurations can provide attackers with information useful for further exploitation '
            'or direct access to sensitive functionality.'
        ),
        'remediation': (
            '1. Implement a hardened baseline configuration for all environments.\n'
            '2. Remove or disable unnecessary features, services, and default accounts.\n'
            '3. Ensure error messages do not reveal sensitive information.\n'
            '4. Implement all recommended security headers (HSTS, X-Frame-Options, CSP, etc.).\n'
            '5. Automate configuration auditing as part of CI/CD pipeline.'
        ),
        'references': (
            'https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_Security_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-16',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'L', 'integrity_impact': 'N', 'availability_impact': 'N',
    },
    {
        'name': 'Sensitive Data Exposure',
        'title': 'Sensitive Data Exposure',
        'severity': 'high',
        'description': (
            'Sensitive data exposure was identified. The application transmits or stores sensitive '
            'data (such as credentials, personal information, financial data, or API keys) without '
            'adequate protection.\n\n'
            'This may include transmission over unencrypted channels, weak encryption algorithms, '
            'sensitive data in URLs or logs, or inadequate access controls on stored sensitive data.'
        ),
        'remediation': (
            '1. Encrypt all sensitive data in transit using TLS 1.2+.\n'
            '2. Encrypt sensitive data at rest using strong encryption algorithms (AES-256).\n'
            '3. Do not store sensitive data unnecessarily — discard it as soon as possible.\n'
            '4. Ensure sensitive data is not logged or cached.\n'
            '5. Use strong key management practices.'
        ),
        'references': (
            'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-200',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'N', 'availability_impact': 'N',
    },
    {
        'name': 'Missing Security Headers',
        'title': 'Missing Security Headers',
        'severity': 'low',
        'description': (
            'One or more recommended HTTP security headers are missing from the application\'s '
            'responses. Security headers provide defense-in-depth against various client-side attacks '
            'and browser-based vulnerabilities.\n\n'
            'Missing headers may include: Content-Security-Policy, X-Content-Type-Options, '
            'X-Frame-Options, Strict-Transport-Security, Referrer-Policy, or Permissions-Policy.'
        ),
        'remediation': (
            '1. Add Content-Security-Policy (CSP) header with a restrictive policy.\n'
            '2. Add X-Content-Type-Options: nosniff.\n'
            '3. Add X-Frame-Options: DENY (or SAMEORIGIN if framing is needed).\n'
            '4. Add Strict-Transport-Security with a long max-age.\n'
            '5. Add Referrer-Policy: strict-origin-when-cross-origin.\n'
            '6. Add Permissions-Policy to restrict browser features.'
        ),
        'references': (
            'https://owasp.org/www-project-secure-headers/\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-693',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'N', 'integrity_impact': 'N', 'availability_impact': 'N',
    },
    {
        'name': 'XML External Entity (XXE) Injection',
        'title': 'XML External Entity (XXE) Injection',
        'severity': 'high',
        'description': (
            'An XML External Entity (XXE) injection vulnerability was identified. The application '
            'parses XML input from an untrusted source with external entity processing enabled, '
            'allowing an attacker to define malicious external entities.\n\n'
            'Exploitation can lead to disclosure of internal files, server-side request forgery (SSRF), '
            'denial of service via recursive entity expansion (billion laughs attack), or in some cases '
            'remote code execution.'
        ),
        'remediation': (
            '1. Disable external entity processing and DTD processing in the XML parser.\n'
            '2. Use less complex data formats such as JSON where possible.\n'
            '3. Patch or upgrade all XML processors and libraries.\n'
            '4. Implement server-side input validation and sanitization.\n'
            '5. Use SAST tools to detect XXE in source code.'
        ),
        'references': (
            'https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-611',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'N', 'availability_impact': 'L',
    },
    {
        'name': 'Unrestricted File Upload',
        'title': 'Unrestricted File Upload',
        'severity': 'high',
        'description': (
            'An unrestricted file upload vulnerability was identified. The application allows users '
            'to upload files without adequate validation of file type, content, or size. An attacker '
            'can upload malicious files such as web shells, scripts, or executables.\n\n'
            'Successful exploitation may allow remote code execution on the server, defacement, '
            'storage of malicious content, or client-side attacks against other users.'
        ),
        'remediation': (
            '1. Validate file type using allowlists (check MIME type and file extension).\n'
            '2. Validate file content (magic bytes) rather than relying solely on extensions.\n'
            '3. Store uploaded files outside the web root or on a separate storage service.\n'
            '4. Rename uploaded files to random names to prevent direct access.\n'
            '5. Set file size limits and scan uploads for malware.\n'
            '6. Serve uploaded files with Content-Disposition: attachment header.'
        ),
        'references': (
            'https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-434',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'L', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'H', 'availability_impact': 'H',
    },
    {
        'name': 'Path Traversal',
        'title': 'Path Traversal / Directory Traversal',
        'severity': 'high',
        'description': (
            'A path traversal vulnerability was identified. The application uses user-supplied input '
            'to construct file paths without adequate sanitization, allowing an attacker to access '
            'files and directories outside the intended directory.\n\n'
            'Using sequences like "../" an attacker can read sensitive system files (e.g. /etc/passwd, '
            'configuration files, application source code) or in some cases write to arbitrary locations.'
        ),
        'remediation': (
            '1. Validate user input against an allowlist of permitted file names.\n'
            '2. Use a chroot jail or sandboxed file system for file operations.\n'
            '3. Canonicalize paths and verify they remain within the intended base directory.\n'
            '4. Avoid passing user-supplied input directly to file system APIs.\n'
            '5. Apply the principle of least privilege to the application\'s file system access.'
        ),
        'references': (
            'https://owasp.org/www-community/attacks/Path_Traversal\n'
            'https://cwe.mitre.org/data/definitions/22.html'
        ),
        'cwe_id': 'CWE-22',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'N', 'availability_impact': 'N',
    },
    {
        'name': 'Command Injection',
        'title': 'OS Command Injection',
        'severity': 'critical',
        'description': (
            'An OS command injection vulnerability was identified. The application passes user-supplied '
            'input to a system shell or command execution function without proper sanitization, allowing '
            'an attacker to execute arbitrary operating system commands.\n\n'
            'Successful exploitation grants the attacker full control over the application server with '
            'the privileges of the web application process.'
        ),
        'remediation': (
            '1. Avoid calling OS commands directly — use language-native libraries instead.\n'
            '2. If OS commands are necessary, use parameterized APIs (e.g. subprocess with shell=False).\n'
            '3. Validate input against a strict allowlist of expected values.\n'
            '4. Escape all special shell characters if shell execution cannot be avoided.\n'
            '5. Run the application with minimal OS-level privileges.'
        ),
        'references': (
            'https://owasp.org/www-community/attacks/Command_Injection\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-78',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'H', 'availability_impact': 'H',
    },
    {
        'name': 'Broken Access Control — Privilege Escalation',
        'title': 'Broken Access Control — Vertical Privilege Escalation',
        'severity': 'critical',
        'description': (
            'A vertical privilege escalation vulnerability was identified. The application does not '
            'properly enforce role-based access controls, allowing a lower-privileged user to access '
            'functionality or data restricted to higher-privileged roles (e.g. admin).\n\n'
            'An attacker can escalate their privileges by directly accessing administrative endpoints, '
            'modifying role parameters, or manipulating authorization tokens.'
        ),
        'remediation': (
            '1. Implement server-side access control checks on every request.\n'
            '2. Deny access by default — only grant permissions explicitly.\n'
            '3. Use role-based access control (RBAC) with clearly defined permission levels.\n'
            '4. Do not rely on client-side controls or hidden UI elements for access control.\n'
            '5. Log and alert on access control failures.'
        ),
        'references': (
            'https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-269',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'L', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'H', 'availability_impact': 'H',
    },
    {
        'name': 'JWT / Token Vulnerability',
        'title': 'Insecure JSON Web Token (JWT) Implementation',
        'severity': 'high',
        'description': (
            'An insecure JWT implementation was identified. The application uses JSON Web Tokens '
            'for authentication or authorization with weaknesses in token generation, validation, '
            'or handling.\n\n'
            'Common issues include: accepting the "none" algorithm, using weak signing secrets, '
            'not validating token expiration, allowing algorithm confusion attacks, or storing '
            'sensitive data in the token payload without encryption.'
        ),
        'remediation': (
            '1. Use strong, asymmetric signing algorithms (RS256) or strong HMAC secrets.\n'
            '2. Explicitly reject the "none" algorithm and enforce expected algorithm.\n'
            '3. Validate all claims: expiration (exp), issuer (iss), audience (aud).\n'
            '4. Keep token lifetimes short and implement token refresh mechanisms.\n'
            '5. Do not store sensitive data in JWT payloads — they are base64-encoded, not encrypted.\n'
            '6. Implement token revocation for logout and password changes.'
        ),
        'references': (
            'https://portswigger.net/web-security/jwt\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-347',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'H', 'integrity_impact': 'H', 'availability_impact': 'N',
    },
    {
        'name': 'Open Redirect',
        'title': 'Open Redirect',
        'severity': 'medium',
        'description': (
            'An open redirect vulnerability was identified. The application accepts user-controlled '
            'input in a URL redirection parameter without validating the destination, allowing an '
            'attacker to redirect users to malicious external sites.\n\n'
            'This is commonly exploited in phishing attacks where the attacker sends a link that '
            'appears to point to the legitimate application but redirects the victim to a '
            'credential-harvesting page.'
        ),
        'remediation': (
            '1. Avoid using user-supplied input for redirect destinations.\n'
            '2. If redirects are necessary, use an allowlist of permitted redirect URLs.\n'
            '3. Use indirect references (e.g. mapping IDs to URLs) instead of direct URL parameters.\n'
            '4. Validate that redirect targets are relative URLs or belong to trusted domains.\n'
            '5. Display a warning page before redirecting to external sites.'
        ),
        'references': (
            'https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html\n'
            'https://cwe.mitre.org/data/definitions/601.html'
        ),
        'cwe_id': 'CWE-601',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'R',
        'confidentiality_impact': 'L', 'integrity_impact': 'L', 'availability_impact': 'N',
    },
    {
        'name': 'CORS Misconfiguration',
        'title': 'Cross-Origin Resource Sharing (CORS) Misconfiguration',
        'severity': 'medium',
        'description': (
            'A CORS misconfiguration was identified. The application returns overly permissive '
            'Access-Control-Allow-Origin headers, allowing untrusted origins to read responses '
            'from the application.\n\n'
            'Common misconfigurations include reflecting the Origin header without validation, '
            'using a wildcard (*) with credentials, or allowing null origins. This can enable '
            'an attacker to steal sensitive data via a malicious website.'
        ),
        'remediation': (
            '1. Implement a strict allowlist of permitted origins.\n'
            '2. Never reflect the Origin header without validation.\n'
            '3. Do not use wildcard (*) with Access-Control-Allow-Credentials: true.\n'
            '4. Avoid allowing the "null" origin.\n'
            '5. Restrict exposed headers and allowed methods to the minimum required.'
        ),
        'references': (
            'https://portswigger.net/web-security/cors\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cors'
        ),
        'cwe_id': 'CWE-942',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'R',
        'confidentiality_impact': 'H', 'integrity_impact': 'N', 'availability_impact': 'N',
    },
    {
        'name': 'Clickjacking',
        'title': 'Clickjacking (UI Redress Attack)',
        'severity': 'medium',
        'description': (
            'The application is vulnerable to clickjacking. It can be embedded in an iframe on a '
            'malicious site, allowing an attacker to overlay transparent UI elements and trick users '
            'into clicking on hidden actions within the framed application.\n\n'
            'This can be used to trick authenticated users into performing unintended actions such as '
            'changing account settings, making purchases, or granting permissions.'
        ),
        'remediation': (
            '1. Set the X-Frame-Options header to DENY or SAMEORIGIN.\n'
            '2. Implement a Content Security Policy (CSP) with frame-ancestors directive.\n'
            '3. Use JavaScript frame-busting as defense-in-depth (not a sole defense).\n'
            '4. Consider using SameSite cookie attributes to prevent cross-origin framing attacks.'
        ),
        'references': (
            'https://owasp.org/www-community/attacks/Clickjacking\n'
            'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html'
        ),
        'cwe_id': 'CWE-1021',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'R',
        'confidentiality_impact': 'N', 'integrity_impact': 'L', 'availability_impact': 'N',
    },
    {
        'name': 'Weak Password Policy',
        'title': 'Weak Password Policy',
        'severity': 'medium',
        'description': (
            'The application enforces a weak password policy that allows users to set passwords '
            'that do not meet industry-standard complexity requirements. This increases the risk '
            'of successful brute-force or credential stuffing attacks.\n\n'
            'Weaknesses may include: no minimum length requirement, no complexity requirements, '
            'allowing common passwords, no account lockout mechanism, or no password expiration policy.'
        ),
        'remediation': (
            '1. Enforce minimum password length of at least 12 characters.\n'
            '2. Check passwords against known breached password databases (e.g. HIBP).\n'
            '3. Implement account lockout or progressive delays after failed login attempts.\n'
            '4. Encourage use of password managers and passphrases.\n'
            '5. Implement multi-factor authentication (MFA) as an additional control.\n'
            '6. Do not use password complexity rules (uppercase + symbol) — length is more effective.'
        ),
        'references': (
            'https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html\n'
            'https://pages.nist.gov/800-63-3/sp800-63b.html'
        ),
        'cwe_id': 'CWE-521',
        'attack_vector': 'N', 'attack_complexity': 'L',
        'privileges_required': 'N', 'user_interaction': 'N',
        'confidentiality_impact': 'L', 'integrity_impact': 'N', 'availability_impact': 'N',
    },
]


class Command(BaseCommand):
    help = 'Seed pre-built finding templates (XSS, SQLi, IDOR, etc.)'

    def handle(self, *args, **options):
        created = 0
        for tpl_data in TEMPLATES:
            _, was_created = FindingTemplate.objects.get_or_create(
                name=tpl_data['name'],
                defaults=tpl_data,
            )
            if was_created:
                created += 1
        self.stdout.write(self.style.SUCCESS(
            f'Done. {created} templates created, {len(TEMPLATES) - created} already existed.'
        ))
