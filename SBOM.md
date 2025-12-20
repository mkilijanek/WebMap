# Software Bill of Materials (SBOM) Documentation

## Overview

WebMap provides comprehensive Software Bill of Materials (SBOM) in industry-standard formats to ensure transparency, security, and compliance.

---

## What is SBOM?

A **Software Bill of Materials (SBOM)** is a complete, formally structured list of components, libraries, and modules that are required to build and run a software application.

Think of it as an "ingredient list" for software.

### Why SBOM Matters

**Security:**
- Quickly identify vulnerable components
- Track security advisories for dependencies
- Respond faster to zero-day vulnerabilities
- Enable automated vulnerability scanning

**Compliance:**
- Meet regulatory requirements (Executive Order 14028, FDA, etc.)
- Satisfy customer security questionnaires
- Comply with industry standards (NIST, ISO)
- Demonstrate supply chain security

**Transparency:**
- Show users what's in the software
- Build trust with clear component information
- Enable informed risk decisions

**License Management:**
- Track all software licenses
- Ensure license compliance
- Avoid legal issues
- Manage OSS obligations

**Supply Chain Security:**
- Understand your software supply chain
- Identify supply chain risks
- Detect malicious packages
- Verify component authenticity

---

## Available Formats

WebMap provides SBOM in **two industry-standard formats**:

### 1. CycloneDX (OWASP)

**Location:** `.sbom/sbom.cyclonedx.{json,xml}`

**Specification:** [CycloneDX v1.6](https://cyclonedx.org/)

**Maintained By:** OWASP (Open Web Application Security Project)

**Best For:**
- ✅ Security vulnerability management
- ✅ DevSecOps pipelines
- ✅ Vulnerability scanning tools
- ✅ License compliance
- ✅ Software composition analysis (SCA)

**Key Features:**
- Comprehensive security metadata
- Vulnerability references
- License information
- Dependency graphs
- External references (PURLs, CPEs)
- Cryptographic hashes

**Example Structure:**
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "name": "Django",
      "version": "4.2.15",
      "purl": "pkg:pypi/django@4.2.15",
      "licenses": [...],
      "hashes": [...]
    }
  ]
}
```

### 2. SPDX (Linux Foundation)

**Location:** `.sbom/sbom.spdx.json`

**Specification:** [SPDX v2.3](https://spdx.dev/)

**Maintained By:** Linux Foundation

**Best For:**
- ✅ License compliance
- ✅ Legal reviews
- ✅ Open source governance
- ✅ Broader ecosystem compatibility
- ✅ Enterprise compliance tools

**Key Features:**
- Detailed license information
- Copyright statements
- File-level analysis
- Relationship metadata
- Legal review ready
- International standard (ISO/IEC 5962:2021)

**Example Structure:**
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-Django",
      "name": "Django",
      "versionInfo": "4.2.15",
      "licenseDeclared": "BSD-3-Clause",
      "licenseConcluded": "BSD-3-Clause"
    }
  ]
}
```

---

## Current Components

### Direct Dependencies

| Component | Version | License | Purpose | Security |
|-----------|---------|---------|---------|----------|
| **Django** | 4.2.15 | BSD-3-Clause | Web framework | ✅ LTS version |
| **requests** | 2.32.5 | Apache-2.0 | HTTP library | ✅ Latest stable |
| **xmltodict** | 0.14.2 | MIT | XML parsing | ✅ Updated |
| **defusedxml** | 0.7.1 | Python-2.0 | Secure XML | ✅ Security lib |

### Transitive Dependencies

All transitive (indirect) dependencies are automatically included in the SBOM with:
- Exact versions
- License information
- Package URLs (PURLs)
- Download locations

---

## SBOM Generation

### Automated (Recommended)

SBOMs are **automatically generated** via GitHub Actions:

**Triggers:**
- ✅ Every push to main/master/develop
- ✅ Every release (tagged version)
- ✅ Monthly (1st of month at 4:00 AM UTC)
- ✅ Manual dispatch (on-demand)

**Workflow:** `.github/workflows/sbom-generation.yml`

**Process:**
1. Checkout code
2. Install SBOM tools (cyclonedx-bom, spdx-tools)
3. Generate CycloneDX SBOM (JSON + XML)
4. Validate SBOM
5. Scan for vulnerabilities (Trivy + OSV)
6. Upload as artifacts (90-day retention)
7. Commit to repository (if push/release)
8. Attach to GitHub Release (if release)

**Artifacts:**
- CycloneDX JSON (`.sbom/sbom.cyclonedx.json`)
- CycloneDX XML (`.sbom/sbom.cyclonedx.xml`)
- SPDX JSON (`.sbom/sbom.spdx.json`)

### Manual Generation

#### Prerequisites

```bash
# Install SBOM generation tools
pip install cyclonedx-bom spdx-tools
```

#### Generate CycloneDX SBOM

```bash
# JSON format (recommended)
cyclonedx-py requirements requirements.txt \
  --of JSON \
  --sv 1.6 \
  --mc-type application \
  -o .sbom/sbom.cyclonedx.json

# XML format
cyclonedx-py requirements requirements.txt \
  --of XML \
  --sv 1.6 \
  --mc-type application \
  -o .sbom/sbom.cyclonedx.xml
```

#### Generate SPDX SBOM

SPDX generation for Python is more complex. The template is provided in `.sbom/sbom.spdx.json`.

For automated SPDX generation, consider:
```bash
# Using syft (Anchore)
syft packages -o spdx-json requirements.txt > .sbom/sbom.spdx.json

# Using Microsoft sbom-tool
sbom-tool generate -b .sbom -bc . -pn WebMap -pv 2.0 -ps WebMap -nsb https://github.com/mkilijanek/WebMap
```

---

## Using the SBOM

### Vulnerability Scanning

#### OSV Scanner (Google)

```bash
# Install
go install github.com/google/osv-scanner/cmd/osv-scanner@latest

# Scan SBOM
osv-scanner --sbom=.sbom/sbom.cyclonedx.json

# Output to SARIF
osv-scanner --sbom=.sbom/sbom.cyclonedx.json --format=sarif --output=osv-results.sarif
```

#### Grype (Anchore)

```bash
# Install
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh

# Scan SBOM
grype sbom:.sbom/sbom.cyclonedx.json

# Output JSON
grype sbom:.sbom/sbom.cyclonedx.json -o json > grype-results.json
```

#### Trivy (Aqua Security)

```bash
# Install
brew install trivy  # or see: https://aquasecurity.github.io/trivy/

# Scan SBOM
trivy sbom .sbom/sbom.cyclonedx.json

# Scan with severity filtering
trivy sbom .sbom/sbom.cyclonedx.json --severity CRITICAL,HIGH
```

### License Compliance

#### CycloneDX CLI

```bash
# Install
npm install -g @cyclonedx/cyclonedx-cli

# Analyze licenses
cyclonedx analyze --input .sbom/sbom.cyclonedx.json --licenses

# Export license report
cyclonedx analyze --input .sbom/sbom.cyclonedx.json --licenses --output-format json
```

#### Manual Review

```bash
# Extract all licenses (CycloneDX)
jq '.components[].licenses[]' .sbom/sbom.cyclonedx.json

# Extract all licenses (SPDX)
jq '.packages[].licenseDeclared' .sbom/sbom.spdx.json

# Count components by license
jq -r '.components[].licenses[].license.id' .sbom/sbom.cyclonedx.json | sort | uniq -c
```

### Dependency Management

#### OWASP Dependency-Track

Dependency-Track is a continuous SCA (Software Composition Analysis) platform.

**Setup:**
1. Deploy Dependency-Track: https://dependencytrack.org/
2. Create project in Dependency-Track
3. Upload SBOM:

```bash
curl -X POST "https://dependencytrack.example.com/api/v1/bom" \
  -H "X-Api-Key: YOUR-API-KEY" \
  -H "Content-Type: multipart/form-data" \
  -F "project=YOUR-PROJECT-UUID" \
  -F "bom=@.sbom/sbom.cyclonedx.json"
```

**Features:**
- Continuous vulnerability monitoring
- Policy violations
- License risk analysis
- Metrics and reporting
- REST API
- Webhook notifications

#### GitHub Dependency Graph

GitHub automatically ingests some SBOM data. To enhance:

```bash
# Use dependency submission API
# See: https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/using-the-dependency-submission-api
```

---

## SBOM Validation

### CycloneDX Validation

```bash
# Install CycloneDX CLI
npm install -g @cyclonedx/cyclonedx-cli

# Validate SBOM
cyclonedx validate --input-file .sbom/sbom.cyclonedx.json --fail-on-errors

# Validate against specific version
cyclonedx validate --input-file .sbom/sbom.cyclonedx.json --input-version 1.6
```

### SPDX Validation

```bash
# Install SPDX tools
pip install spdx-tools

# Validate SBOM
pyspdxtools -i .sbom/sbom.spdx.json

# Detailed validation
spdx-tools validate .sbom/sbom.spdx.json
```

---

## Compliance

### NTIA Minimum Elements

Our SBOM includes all **NTIA minimum elements** for SBOM:

| Element | Included | Location |
|---------|----------|----------|
| **Supplier Name** | ✅ | `components[].supplier` (CycloneDX) |
| **Component Name** | ✅ | `components[].name` |
| **Version** | ✅ | `components[].version` |
| **Other Unique Identifiers** | ✅ | `components[].purl` (Package URL) |
| **Dependency Relationships** | ✅ | `dependencies[]` |
| **SBOM Author** | ✅ | `metadata.tools` |
| **Timestamp** | ✅ | `metadata.timestamp` |

**Reference:** [NTIA SBOM Minimum Elements](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)

### Executive Order 14028

Our SBOM complies with **Executive Order 14028** (Improving the Nation's Cybersecurity) requirements for software sold to US Federal Government:

- ✅ Machine-readable SBOM
- ✅ Contains all components and dependencies
- ✅ Uniquely identifies each component
- ✅ Includes component relationships
- ✅ Standard format (CycloneDX, SPDX)
- ✅ Regularly updated

**Reference:** [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)

### ISO/IEC 5962:2021

SPDX is an international standard (ISO/IEC 5962:2021) for communicating software bill of material information.

---

## Integration Examples

### CI/CD Pipeline

```yaml
# Example: GitLab CI
sbom_scan:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy sbom .sbom/sbom.cyclonedx.json --severity CRITICAL,HIGH --exit-code 1
  artifacts:
    reports:
      dependency_scanning: trivy-results.json
```

### Docker Build

```dockerfile
# Include SBOM in Docker image
FROM python:3.11-slim
COPY .sbom/sbom.cyclonedx.json /opt/sbom/
LABEL org.opencontainers.image.sbom=/opt/sbom/sbom.cyclonedx.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: sbom-validation
      name: Validate SBOM
      entry: cyclonedx validate --input-file .sbom/sbom.cyclonedx.json
      language: system
      pass_filenames: false
```

---

## Metadata

### SBOM Document Information

Each SBOM includes metadata about its generation:

**CycloneDX:**
```json
{
  "metadata": {
    "timestamp": "2025-12-20T...",
    "tools": [
      {
        "vendor": "CycloneDX",
        "name": "cyclonedx-python",
        "version": "..."
      }
    ],
    "component": {
      "type": "application",
      "name": "WebMap",
      "version": "2.0"
    }
  }
}
```

**SPDX:**
```json
{
  "creationInfo": {
    "created": "2025-12-20T00:00:00Z",
    "creators": [
      "Tool: spdx-tools",
      "Organization: WebMap Project"
    ],
    "licenseListVersion": "3.22"
  }
}
```

---

## FAQ

### Why two formats (CycloneDX and SPDX)?

Different organizations and tools prefer different formats:
- **CycloneDX**: Preferred by security tools, DevSecOps teams
- **SPDX**: Preferred by legal teams, enterprise compliance

Providing both ensures maximum compatibility.

### How often is SBOM updated?

- **Automatically**: On every push, release, and monthly
- **Manually**: Anytime via GitHub Actions workflow dispatch

### Can I trust the SBOM?

Yes! The SBOM is:
- ✅ Generated automatically from `requirements.txt`
- ✅ Validated against format specifications
- ✅ Scanned for vulnerabilities
- ✅ Signed by GitHub Actions
- ✅ Reproducible

### What about transitive dependencies?

Transitive dependencies are automatically included by the SBOM generation tools based on dependency resolution.

### How do I report an SBOM issue?

Open an issue on GitHub or submit a PR with corrections.

---

## Tools & Resources

### SBOM Tools

- **CycloneDX:** https://cyclonedx.org/tool-center/
- **SPDX:** https://spdx.dev/tools/
- **Syft:** https://github.com/anchore/syft
- **OSV Scanner:** https://google.github.io/osv-scanner/

### Vulnerability Scanners

- **Trivy:** https://trivy.dev/
- **Grype:** https://github.com/anchore/grype
- **OSV Scanner:** https://google.github.io/osv-scanner/
- **OWASP Dependency-Check:** https://owasp.org/www-project-dependency-check/

### SCA Platforms

- **OWASP Dependency-Track:** https://dependencytrack.org/
- **Snyk:** https://snyk.io/
- **Sonatype Nexus:** https://www.sonatype.com/products/nexus-repository
- **JFrog Xray:** https://jfrog.com/xray/

### Standards & Specs

- **CycloneDX Specification:** https://cyclonedx.org/specification/overview/
- **SPDX Specification:** https://spdx.github.io/spdx-spec/
- **NTIA Guidelines:** https://www.ntia.gov/page/software-bill-materials
- **CISA SBOM:** https://www.cisa.gov/sbom

---

## Support

For SBOM-related questions:

- **Generation Issues:** Check `.github/workflows/sbom-generation.yml`
- **Format Questions:** See specification links above
- **Vulnerability Scanning:** See SECURITY_AUTOMATION.md
- **License Compliance:** Contact maintainers

---

**Last Updated:** 2025-12-20 (automated)
**SBOM Version:** CycloneDX 1.6, SPDX 2.3
**Next Update:** Automatic (on next push/release)
