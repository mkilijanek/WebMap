<p align="center">
<img width="300" src="https://i.imgur.com/puyIfHT.jpg" /><br>
A Web Dashbord for Nmap XML Report
</p>

<p align="center">
  <a href="https://github.com/mkilijanek/WebMap/actions/workflows/security-scan.yml">
    <img src="https://github.com/mkilijanek/WebMap/actions/workflows/security-scan.yml/badge.svg" alt="Security Scan">
  </a>
  <a href="https://github.com/mkilijanek/WebMap/actions/workflows/codeql-analysis.yml">
    <img src="https://github.com/mkilijanek/WebMap/actions/workflows/codeql-analysis.yml/badge.svg" alt="CodeQL">
  </a>
  <a href="https://github.com/mkilijanek/WebMap/security/policy">
    <img src="https://img.shields.io/badge/security-policy-blue.svg" alt="Security Policy">
  </a>
  <a href="https://github.com/mkilijanek/WebMap/security/dependabot">
    <img src="https://img.shields.io/badge/dependabot-enabled-success.svg" alt="Dependabot">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License">
  </a>
</p>

> **⚠️ SECURITY NOTICE**: This application is designed for **LOCAL USE ONLY**. Do NOT expose to the internet without proper security hardening. See [SECURITY.md](SECURITY.md) for details.

![WebMap](https://i.imgur.com/U9S089v.png)

![WebMap](https://i.imgur.com/Ptijc67.png)

![WebMap](https://i.imgur.com/alWZix9.png)

## Table Of Contents
- [Security](#security)
- [SBOM (Software Bill of Materials)](#sbom-software-bill-of-materials)
- [Usage](#usage)
- [Video](#video)
- [Features](#features)
- [XML Filenames](#xml-filenames)
- [CVE and Exploits](#cve-and-exploits)
- [Third Parts](#third-parts)
- [Security Issues](#security-issues)
- [Security Automation](#security-automation)
- [Contributors](#contributors)
- [Contacts](#contacts)

## Security

🔒 **Security is a top priority for this project.**

### Security Features

- ✅ **Automated Vulnerability Scanning**: GitHub Dependabot, CodeQL, Trivy
- ✅ **Static Security Analysis**: Bandit, Semgrep
- ✅ **Secret Scanning**: TruffleHog, detect-secrets
- ✅ **Dependency Monitoring**: Daily scans for vulnerable dependencies
- ✅ **Input Validation**: Comprehensive validation on all user inputs
- ✅ **Security Headers**: CSP, X-Frame-Options, HSTS
- ✅ **CSRF Protection**: Django CSRF middleware enabled
- ✅ **Path Traversal Protection**: Secure file path handling
- ✅ **Command Injection Prevention**: Subprocess with no shell execution
- ✅ **XXE Protection**: Disabled external entities in XML parsing

### Security Documentation

- 📄 [SECURITY.md](SECURITY.md) - Security policy and best practices
- 📄 [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) - Detailed vulnerability analysis (14 CVEs fixed)
- 📄 [SECURITY_UPDATE_GUIDE.md](SECURITY_UPDATE_GUIDE.md) - Update instructions
- 📄 [SECURITY_AUTOMATION.md](SECURITY_AUTOMATION.md) - Automated security scanning setup
- 📄 [SBOM.md](SBOM.md) - Software Bill of Materials documentation
- 📄 [.github/SECURITY.md](.github/SECURITY.md) - GitHub security policy

### Reporting Security Issues

**DO NOT** report security vulnerabilities through public GitHub issues.

Please use the [GitHub Security Advisories](https://github.com/mkilijanek/WebMap/security/advisories) feature or contact the maintainers directly.

See [SECURITY.md](SECURITY.md#reporting-a-vulnerability) for details.

## SBOM (Software Bill of Materials)

🎯 **Complete transparency of all software components**

WebMap provides comprehensive Software Bill of Materials (SBOM) in industry-standard formats.

### Why SBOM?

SBOM is like an "ingredient list" for software, enabling:

- ✅ **Vulnerability Management**: Quickly identify vulnerable components
- ✅ **Compliance**: Meet regulatory requirements (Executive Order 14028, NTIA)
- ✅ **License Management**: Track all software licenses
- ✅ **Supply Chain Security**: Understand your software supply chain
- ✅ **Transparency**: Show users what's in the software

### Available Formats

**CycloneDX (OWASP):**
- `.sbom/sbom.cyclonedx.json` - JSON format (recommended)
- `.sbom/sbom.cyclonedx.xml` - XML format
- Best for: Security scanning, DevSecOps

**SPDX (Linux Foundation):**
- `.sbom/sbom.spdx.json` - JSON format
- Best for: License compliance, legal reviews
- ISO/IEC 5962:2021 international standard

### Automatic Generation

SBOM is automatically generated on:
- Every release (attached to GitHub Release)
- Every push to main/master/develop
- Monthly (1st of month)
- Manual trigger via GitHub Actions

### Current Components

| Component | Version | License | Purpose |
|-----------|---------|---------|---------|
| Django | 5.2.9 | BSD-3-Clause | Web framework (LTS) |
| requests | 2.32.5 | Apache-2.0 | HTTP library |
| xmltodict | 0.14.2 | MIT | XML parsing |
| defusedxml | 0.7.1 | Python-2.0 | Secure XML |

### Using the SBOM

```bash
# Scan for vulnerabilities with Trivy
trivy sbom .sbom/sbom.cyclonedx.json

# Scan with OSV Scanner (Google)
osv-scanner --sbom=.sbom/sbom.cyclonedx.json

# Validate SBOM
cyclonedx validate --input-file .sbom/sbom.cyclonedx.json

# Extract licenses
jq '.components[].licenses' .sbom/sbom.cyclonedx.json
```

### Compliance

✅ **NTIA Minimum Elements** - All 7 required elements included
✅ **Executive Order 14028** - Federal software requirements met
✅ **ISO/IEC 5962:2021** - SPDX international standard
✅ **CycloneDX v1.6** - Latest OWASP specification
✅ **Automatically scanned** - Trivy + OSV integration

See [SBOM.md](SBOM.md) for complete documentation.

## Usage
You should use this with docker, just by sending this command:
```bash
$ mkdir /tmp/webmap
$ docker run -d \
         --name webmap \
         -h webmap \
         -p 8000:8000 \
         -v /tmp/webmap:/opt/xml \
         rev3rse/webmap

$ # now you can run Nmap and save the XML Report on /tmp/webmap
$ nmap -sT -A -T4 -oX /tmp/webmap/myscan.xml 192.168.1.0/24
```
Now point your browser to http://localhost:8000

### Quick and Dirty
```bash
$ curl -sL http://bit.ly/webmapsetup | bash
```

## Video
-- coming soon...

## Features
- Import and parse Nmap XML files
- Statistics and Charts on discovered services, ports, OS, etc...
- Inspect a single host by clicking on its IP address
- Attach labels on a host
- Insert notes for a specific host
- Create a PDF Report with charts, details, labels and notes
- Copy to clipboard as Nikto, Curl or Telnet commands
- Search for CVE and Exploits based on CPE collected by Nmap

## XML Filenames
When creating the PDF version of the Nmap XML Report, the XML filename is used as document title on the first page. 
WebMap will replace some parts of the filename as following:

- `_` will replaced by a space (` `)
- `.xml` will be removed

Example: `ACME_Ltd..xml`<br>
PDF title: `ACME Ltd.`

## CVE and Exploits
thanks to the amazing API services by circl.lu, WebMap is able to looking for CVE and Exploits for each CPE collected by Nmap. 
Not all CPE are checked over the circl.lu API, but only when a specific version is specified 
(for example: `cpe:/a:microsoft:iis:7.5` and not `cpe:/o:microsoft:windows`).

## Third Parts
- [Django](https://www.djangoproject.com)
- [Materialize CSS](https://materializecss.com)
- [Clipboard.js](https://clipboardjs.com)
- [Chart.js](https://www.chartjs.org)
- [Wkhtmltopdf](https://wkhtmltopdf.org)
- [API cve.circl.lu](https://cve.circl.lu)

## Security Issues

⚠️ **IMPORTANT**: This app is **NOT intended to be exposed on the internet**.

### Security Warnings

- **DO NOT** expose this application to the public internet
- **DO NOT** use in multi-tenant environments without additional security
- **DO** use only on localhost or secure internal networks
- **DO** use VPN for remote access if needed
- **DO** configure firewall rules to restrict access

### Why Localhost Only?

This application is designed as a **security assessment tool** for local use:

1. **Sensitive Data**: Stores network scan results containing private/confidential information
2. **Attack Surface**: Minimized by restricting to localhost
3. **Use Case**: Intended for security professionals performing authorized assessments

### Security Improvements (December 2025)

Recent security update addressed **14 vulnerabilities** including:

- ✅ **CRITICAL**: Command Injection (RCE) - **FIXED**
- ✅ **CRITICAL**: Path Traversal - **FIXED**
- ✅ **HIGH**: Hardcoded SECRET_KEY - **FIXED**
- ✅ **HIGH**: DEBUG mode in production - **FIXED**
- ✅ **HIGH**: Unrestricted ALLOWED_HOSTS - **FIXED**
- ✅ **HIGH**: XXE Injection - **FIXED**
- ✅ And 8 more vulnerabilities - **ALL FIXED**

See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for complete details.

### Deployment Security Checklist

Before deploying, ensure:

```bash
# Set environment variables
export DJANGO_SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(50))")
export DEBUG=False
export ALLOWED_HOSTS=localhost,127.0.0.1

# Verify security settings
pip install -r requirements.txt
bandit -r . -ll
pip-audit --require requirements.txt
```

See [SECURITY_UPDATE_GUIDE.md](SECURITY_UPDATE_GUIDE.md) for complete deployment instructions.

## Security Automation

This project uses **automated security scanning** to ensure continuous security:

### Automated Tools

- **GitHub Dependabot**: Daily dependency vulnerability scanning
- **CodeQL**: Weekly semantic code analysis
- **Bandit**: Python security linter (on every commit)
- **Trivy**: Comprehensive vulnerability scanner
- **pip-audit**: Python package vulnerability checker
- **Semgrep**: SAST (Static Application Security Testing)
- **TruffleHog**: Secret scanning in git history
- **Pre-commit hooks**: Local security checks before commit

### GitHub Actions Workflows

All security scans run automatically:

- 🔍 **Security Scan**: Runs on every push and daily at 2:00 AM UTC
- 🔍 **CodeQL Analysis**: Runs weekly on Monday at 3:00 AM UTC
- 🔍 **Dependency Review**: Runs on every pull request
- 🤖 **Dependabot**: Auto-merges security patches

### Setting Up Local Security Tools

```bash
# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run all security checks locally
pre-commit run --all-files

# Or run specific tools
bandit -r . -ll
pip-audit --require requirements.txt
safety check
```

See [SECURITY_AUTOMATION.md](SECURITY_AUTOMATION.md) for complete documentation.

### Security Monitoring

All security findings are visible in:

- **GitHub Security Tab**: Code scanning alerts, Dependabot alerts
- **Actions Artifacts**: Detailed reports (pip-audit, bandit, trivy, etc.)
- **Pull Request Comments**: Automatic security analysis on PRs

### Security Metrics

Current security status:

- ✅ **0** Critical vulnerabilities
- ✅ **0** High vulnerabilities
- ✅ **100%** dependencies with pinned versions
- ✅ **14** CVEs fixed in latest update
- ✅ **6** automated security tools active

## Contributors
This project is currently a beta, and I'm not super skilled on Django so, every type of contribution is appreciated. 
I'll mention all contributors in this section of the README file.

### Contributors List
- s3th_0x [@adubaldo](https://github.com/adubaldo) (bug on single host report)
- Neetx [@Neetx](https://github.com/Neetx) (bug on xml with no host up)

## Contacts
Twitter: [@Menin_TheMiddle](https://twitter.com/Menin_TheMiddle)<br>
YouTube: [Rev3rseSecurity](https://www.youtube.com/rev3rsesecurity)
