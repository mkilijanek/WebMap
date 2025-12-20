# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| Latest (main) | :white_check_mark: | Active development |
| < 2.0   | :x:                | No longer supported |

## Reporting a Vulnerability

**Please DO NOT report security vulnerabilities through public GitHub issues.**

We take the security of WebMap seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### How to Report

1. **GitHub Security Advisories** (Preferred)
   - Go to the [Security tab](https://github.com/mkilijanek/WebMap/security/advisories)
   - Click "Report a vulnerability"
   - Fill in the details about the vulnerability

2. **Email**
   - Send an email to: [security contact - to be configured]
   - Use subject line: `[SECURITY] WebMap Vulnerability Report`
   - Include as much detail as possible (see below)

### What to Include

Please include the following information in your report:

- **Type of vulnerability** (e.g., XSS, SQL injection, path traversal)
- **Full paths of affected source file(s)**
- **Location of the affected code** (tag/branch/commit or direct URL)
- **Step-by-step instructions to reproduce** the issue
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the vulnerability** and how it could be exploited
- **Any potential mitigations** you've identified

### What to Expect

- **Acknowledgment**: We'll acknowledge receipt within 48 hours
- **Communication**: We'll keep you informed about the progress
- **Credit**: With your permission, we'll credit you in the security advisory
- **Timeline**:
  - CRITICAL: Fix within 24-48 hours
  - HIGH: Fix within 1 week
  - MEDIUM: Fix within 2 weeks
  - LOW: Fix within 30 days

### Security Update Process

1. **Vulnerability confirmed** → Issue triaged and prioritized
2. **Fix developed** → Security patch created on private branch
3. **Testing** → Comprehensive testing of the fix
4. **Release** → Security update released with advisory
5. **Disclosure** → Public disclosure after users have time to update (typically 7-14 days)

## Security Measures in Place

### Automated Security Scanning

This repository uses multiple automated security tools:

- **GitHub Dependabot**: Automatic dependency vulnerability scanning
- **CodeQL**: Advanced semantic code analysis
- **Bandit**: Python security linter
- **Trivy**: Comprehensive vulnerability scanner
- **pip-audit**: Python dependency auditing
- **Safety**: Known security vulnerability checking
- **Semgrep**: Static application security testing (SAST)
- **TruffleHog**: Secret scanning

### CI/CD Security

All code changes are automatically scanned for:
- Known vulnerabilities in dependencies
- Security anti-patterns in code
- Exposed secrets or credentials
- Container vulnerabilities
- License compliance issues

### Security Best Practices

- All dependencies are pinned to specific versions
- Security headers configured (CSP, X-Frame-Options, etc.)
- Input validation on all user inputs
- Path traversal protection
- Command injection prevention
- XSS protection
- CSRF protection
- XXE protection

## Known Security Limitations

**⚠️ IMPORTANT:** This application is designed for **LOCAL USE ONLY**.

### Not Recommended For

- ❌ Exposure to public internet
- ❌ Multi-tenant environments
- ❌ Production environments without additional hardening
- ❌ Environments with untrusted users

### Recommended Use Cases

- ✅ Local network security assessments
- ✅ Development and testing environments
- ✅ Single-user localhost deployments
- ✅ VPN-protected internal networks

## Security Configuration

### Required Security Configuration

Before deploying, ensure you:

1. **Set environment variables:**
   ```bash
   export DJANGO_SECRET_KEY="<random-50-char-string>"
   export DEBUG=False
   export ALLOWED_HOSTS="localhost,127.0.0.1"
   ```

2. **Review security settings** in `docker/settings.py`

3. **Restrict file permissions:**
   ```bash
   chmod 750 /opt/notes
   chmod 755 /opt/xml
   ```

4. **Use firewall rules** to limit access

See [SECURITY.md](../SECURITY.md) for complete security documentation.

## Security Disclosure Policy

We follow the principle of **Coordinated Vulnerability Disclosure**:

- We request a **90-day embargo** before public disclosure
- We'll work with you to understand and fix the vulnerability
- We'll credit you (with permission) in security advisories
- Critical vulnerabilities may be disclosed sooner if actively exploited

## Security Hall of Fame

We recognize and thank security researchers who responsibly disclose vulnerabilities:

<!-- List will be updated as vulnerabilities are reported and fixed -->
- *No reports yet - be the first!*

## Bug Bounty Program

Currently, we do not offer a paid bug bounty program. However:

- We deeply appreciate responsible disclosure
- We'll publicly acknowledge your contribution
- Your name will be added to our Security Hall of Fame

## Additional Resources

- [SECURITY_ANALYSIS.md](../SECURITY_ANALYSIS.md) - Detailed vulnerability analysis
- [SECURITY.md](../SECURITY.md) - Security best practices
- [SECURITY_UPDATE_GUIDE.md](../SECURITY_UPDATE_GUIDE.md) - Update instructions
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

## Contact

- **GitHub Issues**: For non-security bugs and features
- **Security Advisories**: For security vulnerabilities
- **Discussions**: For questions and community support

---

**Last Updated**: 2025-12-20
**Version**: 1.0
