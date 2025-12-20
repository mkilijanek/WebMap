# Security Update Guide

## 🔒 Critical Security Update - December 2025

This guide explains how to update your WebMap installation to include critical security fixes.

---

## ⚠️ URGENT: What Changed

### Critical Vulnerabilities Fixed

1. **Command Injection (CRITICAL)** - Remote Code Execution via PDF generation
2. **Path Traversal (CRITICAL)** - Arbitrary file read/write/delete
3. **Hardcoded Secrets (HIGH)** - SECRET_KEY exposed in code
4. **Debug Mode (HIGH)** - Information disclosure
5. **Open Host Headers (HIGH)** - Host header injection
6. **XXE Injection (HIGH)** - XML External Entity attacks
7. **CSRF Bypass (MEDIUM)** - Cross-Site Request Forgery
8. **Input Validation (MEDIUM)** - Various injection vectors

**See `SECURITY_ANALYSIS.md` for complete vulnerability details.**

---

## 📋 Update Steps

### 1. Backup Current Installation

```bash
# Backup data
docker cp webmap:/opt/xml ./backup-xml-$(date +%Y%m%d)
docker cp webmap:/opt/notes ./backup-notes-$(date +%Y%m%d)
docker cp webmap:/opt/nmapdashboard/db.sqlite3 ./backup-db-$(date +%Y%m%d).sqlite3

# Backup container
docker commit webmap webmap-backup-$(date +%Y%m%d)
```

### 2. Stop Current Container

```bash
docker stop webmap
docker rm webmap
```

### 3. Update Code

```bash
# Clone updated repository (or pull latest)
git pull origin main

# Or if using a specific security branch:
git checkout claude/security-vulnerability-analysis-r7g3q
git pull
```

### 4. Update Dependencies

The updated `requirements.txt` includes:

```txt
Django==4.2.15          # Updated for security
requests==2.32.5        # Latest stable
xmltodict==0.14.2       # Security fixes
defusedxml==0.7.1       # NEW: XXE protection
```

### 5. Set Environment Variables

```bash
# Generate a secure SECRET_KEY
export DJANGO_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(50))")

# Set production defaults
export DEBUG=False
export ALLOWED_HOSTS=localhost,127.0.0.1

# Save to .env file (recommended)
cat > .env << EOF
DJANGO_SECRET_KEY=${DJANGO_SECRET_KEY}
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1,[::1]
EOF

# Protect .env file
chmod 600 .env
```

### 6. Rebuild Docker Image (if using Docker)

```bash
# Build new image with security fixes
docker build -t webmap:secure .

# Or update existing Dockerfile to include:
# COPY security_utils.py /opt/nmapdashboard/nmapreport/
# RUN pip install -r requirements.txt --no-cache-dir
```

### 7. Start Updated Container

```bash
docker run -d \
  --name webmap \
  -h webmap \
  -p 8000:8000 \
  -v $(pwd)/backup-xml-$(date +%Y%m%d):/opt/xml \
  -v $(pwd)/backup-notes-$(date +%Y%m%d):/opt/notes \
  --env-file .env \
  webmap:secure
```

### 8. Verify Security Updates

```bash
# Check container logs
docker logs webmap

# Should see warning if DJANGO_SECRET_KEY not set:
# "RuntimeWarning: DJANGO_SECRET_KEY not set in environment"

# Verify DEBUG=False (no detailed error pages)
curl http://localhost:8000/nonexistent
# Should return generic 404, NOT detailed traceback

# Verify ALLOWED_HOSTS
curl -H "Host: malicious.com" http://localhost:8000/
# Should return 400 Bad Request

# Test security headers
curl -I http://localhost:8000/
# Should include:
# X-Frame-Options: DENY
# X-Content-Type-Options: nosniff
# Referrer-Policy: same-origin
```

---

## 🔍 Security Verification Tests

### Test 1: Path Traversal Prevention

```bash
# This should FAIL (403/400) with new security:
curl -v "http://localhost:8000/setscanfile/../../etc/passwd"

# Expected: ValidationError or SuspiciousFileOperation
```

### Test 2: Command Injection Prevention

```bash
# PDF generation now uses subprocess.run() with shell=False
# Command injection no longer possible via session manipulation
```

### Test 3: Input Validation

```bash
# Invalid IP address - should fail
curl -X POST http://localhost:8000/api/getcve/ \
  -d "host=invalid-ip&port=80&cpe=cpe:/a:test"

# Invalid port - should fail
curl -X POST http://localhost:8000/api/getcve/ \
  -d "host=192.168.1.1&port=99999&cpe=cpe:/a:test"
```

### Test 4: CSRF Protection

```bash
# POST without CSRF token - should fail
curl -X POST http://localhost:8000/api/savenotes/ \
  -d "hashstr=abc123&notes=test"

# Expected: 403 Forbidden (CSRF verification failed)
```

---

## 🛠️ Troubleshooting

### Issue: "DJANGO_SECRET_KEY not set" Warning

**Solution:**
```bash
# Generate and set SECRET_KEY
export DJANGO_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(50))")

# Or add to Docker run command:
docker run -e DJANGO_SECRET_KEY="your-key-here" ...
```

### Issue: "Bad Request (400)" on Access

**Cause:** Incorrect Host header

**Solution:**
```bash
# Add your hostname to ALLOWED_HOSTS
export ALLOWED_HOSTS=localhost,127.0.0.1,your-hostname.local
```

### Issue: "ValidationError" on File Operations

**Cause:** Filename contains invalid characters

**Solution:**
- Use only alphanumeric, dash, underscore, and dot in filenames
- No spaces, no `..`, no `/` in filenames
- Example: `scan_2025-12-20.xml` ✅
- Example: `../../../etc/passwd.xml` ❌

### Issue: CSRF Token Failures

**Cause:** CSRF middleware not enabled or cookies not sent

**Solution:**
- Ensure `django.middleware.csrf.CsrfViewMiddleware` is in `MIDDLEWARE`
- Send CSRF token with POST requests
- For API calls, include CSRF token in headers

---

## 📊 Security Audit Commands

Run these after update to verify security:

```bash
# 1. Static code analysis
pip install bandit
bandit -r . -ll -f txt -o security-audit.txt

# 2. Dependency vulnerability scan
pip install safety
safety check --json > dependency-audit.json

# 3. Pip package audit
pip install pip-audit
pip-audit --format json > pip-audit.json

# 4. Check for hardcoded secrets
pip install detect-secrets
detect-secrets scan > .secrets.baseline

# 5. Check file permissions
find /opt/xml /opt/notes -type f -ls
# Should NOT be world-writable
```

---

## 🔐 Recommended Security Hardening

### 1. File System Permissions

```bash
# Set restrictive permissions on data directories
docker exec webmap chmod 750 /opt/notes
docker exec webmap chmod 755 /opt/xml

# Limit file sizes
docker exec webmap find /opt/xml -type f -size +50M -delete
```

### 2. Network Isolation

```bash
# Use Docker network isolation
docker network create webmap-internal
docker run --network webmap-internal ...

# Or use host firewall
sudo ufw allow from 127.0.0.1 to any port 8000
sudo ufw deny 8000
```

### 3. Monitoring

```bash
# Enable Django logging
mkdir -p /var/log/webmap
docker run -v /var/log/webmap:/var/log/webmap ...

# Monitor logs
tail -f /var/log/webmap/security.log
```

### 4. Rate Limiting (Future Enhancement)

Consider adding Django rate limiting:
```bash
pip install django-ratelimit
```

---

## 📈 What's Next

### Future Security Improvements

1. **XSS Prevention**
   - Replace HTML string concatenation with Django templates
   - Implement strict Content Security Policy
   - Add HTML sanitization library (DOMPurify)

2. **Authentication**
   - Add user authentication system
   - Implement role-based access control (RBAC)
   - Multi-factor authentication (MFA)

3. **Audit Logging**
   - Log all file access
   - Log all API calls
   - Intrusion detection

4. **File Upload Security**
   - File size limits (implemented)
   - File type validation (magic bytes)
   - Malware scanning integration
   - XML schema validation

---

## 📞 Support

### Reporting Security Issues

- **GitHub:** Create private security advisory
- **Email:** (set up security contact)

### Documentation

- `SECURITY_ANALYSIS.md` - Detailed vulnerability analysis
- `SECURITY.md` - Security policy and best practices
- `README.md` - General usage documentation

---

## ✅ Post-Update Checklist

- [ ] Backed up all data
- [ ] Updated to latest code
- [ ] Set DJANGO_SECRET_KEY environment variable
- [ ] Set DEBUG=False
- [ ] Configured ALLOWED_HOSTS
- [ ] Installed updated dependencies
- [ ] Verified security headers present
- [ ] Tested path traversal prevention
- [ ] Tested CSRF protection
- [ ] Reviewed security audit output
- [ ] Restricted file system permissions
- [ ] Configured logging
- [ ] Verified application is NOT exposed to internet

---

## ⚖️ License

These security updates are provided under the same license as the main project.

---

**Last Updated:** 2025-12-20
**Security Update Version:** 1.0
**Branch:** claude/security-vulnerability-analysis-r7g3q
