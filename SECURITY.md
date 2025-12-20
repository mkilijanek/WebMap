# Security Policy and Best Practices

## Overview

This document outlines the security improvements implemented in WebMap and provides guidelines for secure deployment and operation.

## Security Improvements Summary

### Critical Fixes Implemented ✅

1. **Command Injection Prevention (CVE-001)**
   - Replaced `os.popen()` with `subprocess.run()`
   - Command arguments passed as list (no shell interpretation)
   - Added timeout protection (30 seconds)
   - File: `api.py:178-228`

2. **Path Traversal Protection (CVE-002)**
   - Implemented `safe_join()` function for secure path operations
   - Added filename validation (alphanumeric, dash, underscore, dot only)
   - Prevents `../` and absolute path attacks
   - File: `security_utils.py`, applied throughout `api.py`

3. **Secure Django Configuration (CVE-003, CVE-004, CVE-005)**
   - `SECRET_KEY` from environment variable with auto-generation fallback
   - `DEBUG = False` by default (configurable via environment)
   - `ALLOWED_HOSTS` restricted to localhost by default
   - File: `docker/settings.py:11-36`

4. **Input Validation (CVE-008, CVE-009)**
   - Comprehensive validation for all user inputs
   - IP address validation
   - Port number validation (1-65535)
   - MD5 hash validation
   - CPE string validation
   - File: `security_utils.py`

5. **XXE Protection (CVE-007)**
   - Added `disable_entities=True` to XML parsing
   - File: `api.py:143`

6. **CSRF Protection (CVE-008)**
   - Added `@csrf_protect` decorators to POST endpoints
   - Added `@require_http_methods(['POST'])` decorators
   - Files: `api.py:39, api.py:230`

7. **Security Headers (CVE-013)**
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: same-origin`
   - Content Security Policy (CSP) configuration
   - File: `docker/settings.py:133-167`

8. **Session Security (CVE-014)**
   - `SESSION_COOKIE_HTTPONLY = True`
   - `SESSION_COOKIE_SAMESITE = Strict`
   - Session timeout: 1 hour
   - File: `docker/settings.py:139-143`

9. **Dependency Security (CVE-012)**
   - All dependencies pinned to specific versions
   - Updated to latest secure versions:
     - Django 5.2.9 (LTS, 2025-2028) - **Fixed 4 SQL injection CVEs**
     - requests 2.32.5
     - xmltodict 0.14.2
     - Added defusedxml 0.7.1
   - File: `requirements.txt`

10. **Django SQL Injection Fixes (December 2025)** ✅
   - Upgraded Django from 4.2.15 to 5.2.9 LTS
   - Fixed CVE-2025-64459 (CRITICAL) - Django SQL injection
   - Fixed CVE-2024-53908 (HIGH) - SQL injection in HasKey(lhs, rhs) on Oracle
   - Fixed CVE-2025-57833 (HIGH) - SQL injection in FilteredRelation column aliases
   - Fixed CVE-2025-59681 (HIGH) - SQL injection in QuerySet operations on MySQL/MariaDB
   - See: `DJANGO_UPDATE.md` for details

---

## Deployment Security Checklist

### Before Deploying

- [ ] Set `DJANGO_SECRET_KEY` environment variable (50+ random characters)
- [ ] Set `DEBUG=False` in production environment
- [ ] Configure `ALLOWED_HOSTS` with specific hostnames
- [ ] Review and restrict file system permissions on `/opt/xml` and `/opt/notes`
- [ ] Install all dependencies from pinned `requirements.txt`
- [ ] Run security audit: `pip-audit`
- [ ] Run static analysis: `bandit -r .`
- [ ] Review firewall rules
- [ ] Ensure application is NOT exposed to public internet

### Environment Variables

```bash
# Required for production
export DJANGO_SECRET_KEY="your-50-character-random-secret-key-here"
export DEBUG="False"
export ALLOWED_HOSTS="localhost,127.0.0.1"

# Optional - for HTTPS deployments
export SECURE_SSL_REDIRECT="True"
export SESSION_COOKIE_SECURE="True"
export CSRF_COOKIE_SECURE="True"
```

Generate a secure SECRET_KEY:
```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

---

## Security Best Practices

### 1. Network Isolation

**CRITICAL:** This application is designed for localhost use only.

- ✅ Run on `localhost` / `127.0.0.1` only
- ✅ Use firewall to block external access
- ✅ If remote access needed, use VPN or SSH tunnel
- ❌ NEVER expose directly to internet

### 2. File System Permissions

```bash
# XML files directory (read-only for web server)
chmod 755 /opt/xml
chown -R webmap-user:webmap-group /opt/xml

# Notes directory (read-write for web server)
chmod 750 /opt/notes
chown -R webmap-user:webmap-group /opt/notes

# Application files (read-only for web server)
chmod 755 /opt/nmapdashboard
chown -R root:webmap-group /opt/nmapdashboard
```

### 3. Input Validation

All user inputs are now validated using `security_utils.py`:

- **Filenames**: Only alphanumeric, dash, underscore, dot
- **IP Addresses**: Valid IPv4 format
- **Port Numbers**: 1-65535
- **MD5 Hashes**: 32 hex characters
- **CPE Strings**: Valid CPE format

### 4. XML File Handling

When adding Nmap XML files:

```bash
# Validate XML before uploading
xmllint --noout scan.xml

# Check for malicious content
grep -i "<!ENTITY" scan.xml  # Should return nothing

# Copy to container safely
docker cp scan.xml webmap:/opt/xml/scan.xml
```

### 5. Monitoring and Logging

Enable Django logging for security events:

```python
# Add to settings.py
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': '/var/log/webmap/security.log',
        },
    },
    'loggers': {
        'django.security': {
            'handlers': ['file'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}
```

Monitor these logs for:
- Failed validation attempts
- Path traversal attempts
- Unusual API call patterns
- CSRF token failures

---

## Remaining Vulnerabilities

### XSS (Stored) - Partial Mitigation

**Status:** ⚠️ Partially mitigated, requires further work

**Location:** `views.py` and `pdf.py` - HTML string concatenation

**Risk:** MEDIUM

**Current Mitigations:**
- Django's `html.escape()` used in many places
- Notes content basic sanitization

**Remaining Issues:**
- Manual HTML string concatenation still used
- Some XML fields rendered without full sanitization
- Base64 decoded content not fully validated

**Recommended Fix:**
```python
# Replace manual HTML concatenation with Django templates
# Before:
html = '<div>' + user_content + '</div>'

# After:
from django.template import Template, Context
template = Template('<div>{{ content }}</div>')
html = template.render(Context({'content': user_content}))
```

**Additional Mitigation:**
- Implement Content Security Policy (CSP) - partially done
- Use DOMPurify on client side
- Sanitize all XML content before storage

### File Upload Validation

**Status:** ⚠️ Needs implementation

**Risk:** MEDIUM

**Current State:**
- No file size validation before processing
- No file type validation (magic bytes)
- No rate limiting on file operations

**Recommended Implementation:**
```python
def validate_xml_file(filepath, max_size=10485760):  # 10MB
    # Check file size
    if os.path.getsize(filepath) > max_size:
        raise ValidationError('File too large')

    # Validate it's actually XML (magic bytes)
    with open(filepath, 'rb') as f:
        header = f.read(5)
        if not header.startswith(b'<?xml'):
            raise ValidationError('Invalid XML file')

    # Validate against schema
    # ... implement XML schema validation
```

---

## Security Testing

### Automated Security Scanning

```bash
# Install security tools
pip install bandit safety pip-audit

# Run security linter
bandit -r . -f json -o reports/bandit-report.json

# Check dependency vulnerabilities
safety check --json > reports/safety-report.json

# Audit pip packages
pip-audit --format json > reports/pip-audit-report.json
```

### Manual Security Testing

1. **Path Traversal Test**
   ```bash
   # Should be blocked by validation
   curl -X POST http://localhost:8000/api/savenotes/ \
     -d "scanfile=../../etc/passwd&hashstr=test&notes=test"
   ```

2. **Command Injection Test**
   ```bash
   # Should be prevented by subprocess.run()
   # Session key manipulation no longer possible
   ```

3. **XSS Test**
   ```xml
   <!-- Test with malicious XML -->
   <nmaprun>
     <host>
       <hostnames>
         <hostname name="<script>alert('XSS')</script>"/>
       </hostnames>
     </host>
   </nmaprun>
   ```

4. **XXE Test**
   ```xml
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
   <nmaprun>&xxe;</nmaprun>
   ```

### OWASP ZAP Scan

```bash
# Run OWASP ZAP against the application
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t http://host.docker.internal:8000
```

---

## Incident Response

If you suspect a security breach:

1. **Immediate Actions**
   - Stop the application: `docker stop webmap`
   - Isolate the system from network
   - Preserve logs and file system for forensics

2. **Investigation**
   - Check `/var/log/webmap/security.log`
   - Review `/opt/xml` and `/opt/notes` for unusual files
   - Check system logs: `journalctl -u webmap`
   - Review Django session data

3. **Recovery**
   - Restore from clean backup
   - Rotate all secrets (SECRET_KEY, session data)
   - Update to latest security patches
   - Review and strengthen access controls

---

## Security Contacts

- **Report Security Issues:** Create a private security advisory on GitHub
- **Security Updates:** Subscribe to Django security mailing list
- **CVE Database:** Monitor https://cve.mitre.org/ for related CVEs

---

## Changelog

### 2025-12-20 - Major Security Update

**Fixed:**
- CVE-001: Command Injection in PDF generation
- CVE-002: Path Traversal vulnerabilities
- CVE-003: Hardcoded SECRET_KEY
- CVE-004: DEBUG mode in production
- CVE-005: Unrestricted ALLOWED_HOSTS
- CVE-007: XXE injection vulnerability
- CVE-008: Missing CSRF protection
- CVE-009: Insufficient input validation
- CVE-012: Unpinned dependencies
- CVE-013: Missing security headers
- CVE-014: Weak session configuration

**Added:**
- `security_utils.py` - Input validation module
- Comprehensive input validation
- Security headers
- Environment-based configuration
- Security documentation

**Updated:**
- `requirements.txt` - Pinned all dependency versions
- `docker/settings.py` - Secure configuration
- `api.py` - Security fixes for all endpoints

---

## License

This security documentation is provided as-is. Implementation of security measures is the responsibility of the deployer.

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Django Security](https://docs.djangoproject.com/en/stable/topics/security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
