# Software Bill of Materials (SBOM)

This directory contains Software Bill of Materials (SBOM) documents for WebMap.

## What is SBOM?

A Software Bill of Materials (SBOM) is a comprehensive inventory of all components, libraries, and dependencies used in this software. It's like an "ingredient list" for software, essential for:

- **Security**: Quickly identify if vulnerable components are present
- **Compliance**: Meet regulatory requirements (e.g., Executive Order 14028)
- **License Management**: Track all software licenses
- **Supply Chain Security**: Understand your software supply chain
- **Transparency**: Provide users with clear component information

## Available Formats

This project provides SBOM in two standard formats:

### 1. CycloneDX (OWASP Standard)

**Files:**
- `sbom.cyclonedx.json` - JSON format (recommended for automation)
- `sbom.cyclonedx.xml` - XML format

**Specification:** [CycloneDX v1.6](https://cyclonedx.org/specification/overview/)

**Best For:**
- Security use cases
- Vulnerability scanning integration
- DevSecOps pipelines
- License compliance

### 2. SPDX (Linux Foundation Standard)

**Files:**
- `sbom.spdx.json` - JSON format
- `sbom.spdx.rdf` - RDF/XML format (if generated)

**Specification:** [SPDX v2.3](https://spdx.dev/specifications/)

**Best For:**
- License compliance
- Legal reviews
- Open source governance
- Broader ecosystem compatibility

## Generation

SBOMs are automatically generated:

### Automated (GitHub Actions)

The SBOM is automatically regenerated on:
- Every release (tagged version)
- Every push to main/master branch
- Manual workflow dispatch

See: `.github/workflows/sbom-generation.yml`

### Manual Generation

```bash
# CycloneDX SBOM
pip install cyclonedx-bom
cyclonedx-py requirements requirements.txt --of JSON -o .sbom/sbom.cyclonedx.json
cyclonedx-py requirements requirements.txt --of XML -o .sbom/sbom.cyclonedx.xml

# SPDX SBOM (requires additional tools)
pip install spdx-tools
# Manual SPDX generation requires more complex tooling
```

## Contents

Current SBOM includes:

### Direct Dependencies

- **Django** v5.2.9 - Web framework (LTS, supported until April 2028)
- **requests** v2.32.5 - HTTP library
- **xmltodict** v0.14.2 - XML parsing
- **defusedxml** v0.7.1 - Secure XML parsing

### Transitive Dependencies

All indirect dependencies are automatically included with their:
- Package names
- Exact versions
- Package URLs (PURLs)
- Distribution URLs
- License information (where available)

## Using the SBOM

### Vulnerability Scanning

```bash
# Using OSV Scanner (Google)
osv-scanner --sbom=.sbom/sbom.cyclonedx.json

# Using Grype (Anchore)
grype sbom:.sbom/sbom.cyclonedx.json

# Using Trivy
trivy sbom .sbom/sbom.cyclonedx.json
```

### License Compliance

```bash
# Using CycloneDX CLI
cyclonedx analyze --input .sbom/sbom.cyclonedx.json --licenses

# Manual review
cat .sbom/sbom.cyclonedx.json | jq '.components[].licenses'
```

### Dependency Graph

```bash
# Using CycloneDX CLI
cyclonedx analyze --input .sbom/sbom.cyclonedx.json --dependencies
```

## Verification

### Integrity

Each SBOM includes:
- Serial number (unique identifier)
- Timestamp of generation
- Tool information (what generated it)
- Spec version

### Validation

```bash
# Validate CycloneDX SBOM
cyclonedx validate --input-file .sbom/sbom.cyclonedx.json

# Validate SPDX SBOM
pyspdxtools -i .sbom/sbom.spdx.json
```

## Integration

### CI/CD Pipeline

SBOM is automatically:
1. Generated on each release
2. Uploaded as release asset
3. Scanned for vulnerabilities
4. Published to dependency tracking systems

### Dependency Track

Import SBOM into OWASP Dependency-Track:

```bash
curl -X POST "https://dependencytrack.example.com/api/v1/bom" \
  -H "X-Api-Key: YOUR-API-KEY" \
  -H "Content-Type: multipart/form-data" \
  -F "project=YOUR-PROJECT-UUID" \
  -F "bom=@.sbom/sbom.cyclonedx.json"
```

### Compliance

This SBOM complies with:

- ✅ **NTIA Minimum Elements** for SBOM
- ✅ **Executive Order 14028** (US Federal)
- ✅ **CycloneDX v1.6** specification
- ✅ **SPDX v2.3** specification
- ✅ **OWASP Dependency-Track** compatible
- ✅ **OSV Scanner** compatible

## NTIA Minimum Elements

Our SBOM includes all required NTIA minimum elements:

1. ✅ **Supplier Name** - Package maintainer/organization
2. ✅ **Component Name** - Package name
3. ✅ **Version** - Exact version string
4. ✅ **Other Unique Identifiers** - Package URLs (PURLs)
5. ✅ **Dependency Relationships** - Component graph
6. ✅ **SBOM Author** - GitHub Actions / cyclonedx-py
7. ✅ **Timestamp** - Generation date/time

## Metadata

### SBOM Document Information

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:...",
  "version": 1,
  "metadata": {
    "timestamp": "2025-12-20T...",
    "tools": [
      {
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

## Support

For questions about SBOM:

- **SBOM Format**: See specification links above
- **Generation Issues**: Check GitHub Actions workflow
- **Vulnerability Scanning**: See SECURITY_AUTOMATION.md
- **License Questions**: See LICENSE file

## Updates

SBOM is automatically updated:
- **On Release**: New version tagged
- **On Dependency Update**: Dependabot merges PR
- **Monthly**: Scheduled regeneration

Last updated: 2025-12-20 (automated)

## References

- [NTIA SBOM Minimum Elements](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)
- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/)
- [Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/)
- [OWASP Dependency-Track](https://dependencytrack.org/)
- [OSV Schema](https://ossf.github.io/osv-schema/)
