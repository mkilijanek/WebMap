# Security Automation Documentation

## Overview

This document describes the automated security scanning and monitoring setup for WebMap, including GitHub Actions workflows, Dependabot configuration, and local development tools.

---

## 🤖 Automated Security Tools

### 1. GitHub Dependabot

**Purpose**: Automatically detect and update vulnerable dependencies

**Configuration**: `.github/dependabot.yml`

**Features**:
- **Daily scans** for Python dependencies (pip)
- **Weekly scans** for Docker and GitHub Actions
- Automatic PR creation for security updates
- Priority handling for CRITICAL/HIGH vulnerabilities
- Auto-merge capability for patch updates

**Schedule**:
- Python dependencies: Daily at 3:00 AM UTC
- Docker: Weekly on Monday at 3:00 AM UTC
- GitHub Actions: Weekly on Monday at 4:00 AM UTC

**Configuration**:
```yaml
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
```

**How it works**:
1. Dependabot scans `requirements.txt` daily
2. Compares against vulnerability databases
3. Creates PR for each outdated/vulnerable dependency
4. Auto-merges CRITICAL/HIGH security patches (if configured)

---

### 2. GitHub CodeQL

**Purpose**: Advanced semantic code analysis for security vulnerabilities

**Configuration**: `.github/workflows/codeql-analysis.yml`

**Languages Analyzed**:
- Python
- JavaScript

**Queries Run**:
- `security-extended`: Extended security query suite
- `security-and-quality`: Security and code quality checks

**Schedule**:
- Every push to main/develop/claude/* branches
- Every pull request
- Weekly scan on Monday at 3:00 AM UTC

**Detects**:
- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Path traversal
- Unsafe deserialization
- Information disclosure
- And 200+ other vulnerability patterns

**Results**: Available in GitHub Security tab → Code scanning alerts

---

### 3. Security Scanning Workflow

**Purpose**: Comprehensive multi-tool security scanning

**Configuration**: `.github/workflows/security-scan.yml`

**Tools Included**:

#### a) pip-audit
- Checks Python dependencies against PyPI Advisory Database
- Generates JSON and Markdown reports
- Runs on every push and daily at 2:00 AM UTC

#### b) Safety
- Checks dependencies against Safety DB
- 50,000+ known vulnerabilities tracked
- JSON report generated

#### c) Bandit
- Static analysis security linter for Python
- Detects security anti-patterns in code
- Configurable severity/confidence levels
- Configuration: `.bandit`

#### d) TruffleHog
- Scans for exposed secrets in code history
- Checks for API keys, passwords, tokens
- Verifies found secrets (reduces false positives)

#### e) Semgrep
- Static application security testing (SAST)
- Community rules + custom rules
- SARIF and JSON output

#### f) Trivy
- Comprehensive vulnerability scanner
- Checks OS packages, dependencies, config files
- Results uploaded to GitHub Security tab

**Reports**: All reports saved as artifacts for 30 days

---

### 4. Dependency Review

**Purpose**: Review dependency changes in pull requests

**Configuration**: `.github/workflows/dependency-review.yml`

**Features**:
- Runs on every pull request
- Checks for new vulnerabilities
- Validates licenses
- Blocks CRITICAL/HIGH vulnerabilities
- Comments summary on PR

**License Policy**:
- ✅ Allowed: MIT, Apache-2.0, BSD, ISC, Python-2.0
- ❌ Denied: GPL, LGPL, AGPL, CC-BY-NC

**Thresholds**:
- Fail on CVSS score ≥ 7.0
- Fail on severity: CRITICAL
- Fail on runtime dependencies only

---

### 5. Pre-commit Hooks

**Purpose**: Local security checks before committing code

**Configuration**: `.pre-commit-config.yaml`

**Installation**:
```bash
pip install pre-commit
pre-commit install
```

**Hooks Included**:

**Security Checks**:
- `bandit`: Python security linter
- `detect-secrets`: Find hardcoded secrets
- `python-safety`: Check dependency vulnerabilities
- `detect-private-key`: Detect SSH/GPG keys
- `detect-aws-credentials`: Detect AWS keys

**Code Quality**:
- `black`: Python code formatter
- `isort`: Import sorting
- `flake8`: Linting and style guide
- `django-upgrade`: Django best practices

**File Checks**:
- `trailing-whitespace`: Remove trailing whitespace
- `end-of-file-fixer`: Ensure files end with newline
- `check-yaml`: Validate YAML syntax
- `check-json`: Validate JSON syntax
- `check-added-large-files`: Prevent large files (>10MB)
- `check-merge-conflict`: Detect merge conflicts

**Infrastructure Checks**:
- `hadolint`: Dockerfile linting
- `shellcheck`: Shell script analysis
- `yamllint`: YAML linting
- `markdownlint`: Markdown linting

**Usage**:
```bash
# Run on all files
pre-commit run --all-files

# Run on staged files only
pre-commit run

# Skip pre-commit for emergency commits
git commit --no-verify -m "Emergency fix"
```

---

## 📊 Security Dashboard

### GitHub Security Tab

All security findings are aggregated in the GitHub Security tab:

**Code Scanning**:
- CodeQL alerts
- Trivy vulnerability alerts
- Semgrep findings

**Dependabot Alerts**:
- Vulnerable dependencies
- Recommended updates
- CVE details

**Secret Scanning**:
- Exposed secrets detected by TruffleHog
- GitHub native secret scanning (if enabled)

---

## 🔄 Automated Workflows

### Daily Operations

**2:00 AM UTC**: Security scanning workflow
- pip-audit
- Safety check
- Bandit analysis
- Trivy scan

**3:00 AM UTC**: Dependabot Python dependencies check
- Scans requirements.txt
- Creates PRs for updates
- Auto-merges security patches

**Monday 3:00 AM UTC**:
- CodeQL analysis
- Docker dependency check
- GitHub Actions updates

### On Every Push

**Triggered**:
- Security scanning
- CodeQL analysis
- Pre-commit hooks (local)

### On Every Pull Request

**Triggered**:
- Dependency review
- Security scanning
- CodeQL analysis
- Dependabot auto-merge check

---

## 🚨 Alert Management

### Severity Levels

**CRITICAL (CVSS 9.0-10.0)**:
- Immediate notification
- Auto-create issue
- Auto-merge fix (if available)
- Timeline: Fix within 24-48 hours

**HIGH (CVSS 7.0-8.9)**:
- Daily notification
- Create issue
- Auto-merge patch/minor updates
- Timeline: Fix within 1 week

**MEDIUM (CVSS 4.0-6.9)**:
- Weekly notification
- Manual review required
- Timeline: Fix within 2 weeks

**LOW (CVSS 0.1-3.9)**:
- Monthly notification
- Scheduled for next release
- Timeline: Fix within 30 days

### Notification Channels

**GitHub**:
- Security alerts in Security tab
- Email notifications (if enabled)
- PR comments
- Issue creation

**Pull Requests**:
- Dependabot creates PRs for updates
- Automated comments on security issues
- CI/CD status checks

---

## 📈 Metrics and Reporting

### Available Reports

All reports stored as GitHub Actions artifacts (30-day retention):

1. **pip-audit-report.json**: Python dependency vulnerabilities
2. **safety-report.json**: Safety database checks
3. **bandit-report.json**: Static analysis findings
4. **semgrep-report.sarif**: SAST results
5. **trivy-results.sarif**: Comprehensive vulnerability scan
6. **codeql-results**: CodeQL analysis results

### Downloading Reports

```bash
# Using GitHub CLI
gh run download <run-id> -n pip-audit-report
gh run download <run-id> -n bandit-report

# Or download from GitHub UI:
# Actions → Workflow Run → Artifacts section
```

### Viewing SARIF Files

```bash
# Install SARIF viewer
npm install -g @microsoft/sarif-multitool

# View SARIF report
sarif view trivy-results.sarif
```

---

## 🔧 Configuration Files

| File | Purpose |
|------|---------|
| `.github/dependabot.yml` | Dependabot configuration |
| `.github/workflows/security-scan.yml` | Security scanning workflow |
| `.github/workflows/codeql-analysis.yml` | CodeQL configuration |
| `.github/workflows/dependency-review.yml` | PR dependency review |
| `.github/workflows/dependabot-auto-merge.yml` | Auto-merge logic |
| `.github/dependency-review-config.yml` | Dependency review rules |
| `.pre-commit-config.yaml` | Pre-commit hooks |
| `.bandit` | Bandit linter configuration |
| `.github/SECURITY.md` | GitHub security policy |

---

## 🛠️ Maintenance

### Weekly Tasks

- [ ] Review Dependabot PRs
- [ ] Check Security tab for new alerts
- [ ] Review and merge security updates
- [ ] Update security documentation

### Monthly Tasks

- [ ] Review security metrics
- [ ] Update allowed license list
- [ ] Review ignored vulnerabilities
- [ ] Audit pre-commit hook configuration
- [ ] Test manual security scans

### Quarterly Tasks

- [ ] Full security audit
- [ ] Update security tooling versions
- [ ] Review and update security policies
- [ ] Penetration testing (if applicable)

---

## 🔍 Manual Security Scans

### Run Locally

```bash
# Install security tools
pip install bandit safety pip-audit detect-secrets

# Run Bandit
bandit -r . -ll -f json -o bandit-report.json

# Run Safety
safety check --json > safety-report.json

# Run pip-audit
pip-audit --require requirements.txt

# Run detect-secrets
detect-secrets scan > .secrets.baseline
detect-secrets audit .secrets.baseline

# Run all pre-commit hooks
pre-commit run --all-files
```

### Docker Security Scan

```bash
# Install Trivy
brew install trivy  # macOS
# or
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -

# Scan Docker image
trivy image webmap:latest

# Scan filesystem
trivy fs .

# Scan config files
trivy config .
```

---

## 🔐 Secret Management

### Preventing Secret Commits

**Pre-commit hook**: `detect-secrets` runs before every commit

**GitHub scanning**: TruffleHog scans history for secrets

**Remediation** if secret committed:
1. Rotate the compromised secret immediately
2. Remove from git history: `git filter-branch` or BFG Repo-Cleaner
3. Force push (if safe): `git push --force`
4. Notify security team

### Baseline Management

```bash
# Create baseline (first time)
detect-secrets scan > .secrets.baseline

# Audit baseline
detect-secrets audit .secrets.baseline

# Update baseline
detect-secrets scan --baseline .secrets.baseline
```

---

## 📚 Additional Resources

### Documentation
- [GitHub Dependabot](https://docs.github.com/en/code-security/dependabot)
- [GitHub CodeQL](https://codeql.github.com/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Pre-commit Hooks](https://pre-commit.com/)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)

### Security Databases
- [GitHub Advisory Database](https://github.com/advisories)
- [PyPI Advisory Database](https://pypi.org/security/)
- [CVE Database](https://cve.mitre.org/)
- [NVD](https://nvd.nist.gov/)

### Tools
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Snyk](https://snyk.io/)
- [WhiteSource](https://www.whitesourcesoftware.com/)

---

## ✅ Verification Checklist

After setup, verify:

- [ ] Dependabot is enabled in repository settings
- [ ] CodeQL is showing in Security tab
- [ ] Security scanning workflow runs successfully
- [ ] Pre-commit hooks installed locally
- [ ] All workflow files are valid YAML
- [ ] Secret scanning is enabled
- [ ] Branch protection rules configured
- [ ] Security policy published
- [ ] Alerts configured in GitHub settings

---

## 🆘 Troubleshooting

### Dependabot Not Running

**Check**:
1. Repository settings → Security → Dependabot alerts (enabled?)
2. `.github/dependabot.yml` syntax valid
3. Branch protection not blocking bot

### CodeQL Failing

**Common issues**:
- Language not correctly detected
- Build step failing (for compiled languages)
- Configuration syntax error

**Fix**:
```yaml
# Ensure correct language
languages: [ 'python', 'javascript' ]

# Check queries syntax
queries: +security-extended,security-and-quality
```

### Pre-commit Not Running

**Install**:
```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

**Bypass** (emergency only):
```bash
git commit --no-verify -m "Emergency commit"
```

---

**Last Updated**: 2025-12-20
**Version**: 1.0
