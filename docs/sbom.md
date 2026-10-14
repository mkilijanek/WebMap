# Software bill of materials

`.sbom/` holds the SBOM of what the container installs from PyPI:
`requirements.txt`, gunicorn and all their transitive dependencies,
resolved in a clean virtual environment.

| File | Format |
|---|---|
| `.sbom/sbom.cyclonedx.json` | CycloneDX 1.6, JSON |
| `.sbom/sbom.cyclonedx.xml` | CycloneDX 1.6, XML |
| `.sbom/sbom.spdx.json` | SPDX 2.3, JSON (converted from the CycloneDX file by Trivy) |

Not included: the Debian packages of the base image (Python, wkhtmltopdf
and its libraries) and the vendored front-end files in `static/vendor/`
(listed with versions, licences and checksums in
[static/vendor/README.md](../static/vendor/README.md)). For a complete
image inventory, scan the built image: `trivy image --format cyclonedx
webmap:local`.

## Regenerating

`.github/workflows/sbom-generation.yml` builds the SBOM on every push to
`v2/master`, monthly and on demand, validates it, scans it with Trivy and
OSV-Scanner, and attaches it to releases. The committed files are updated
by hand (the workflow does not push to the protected branch):

```bash
python3 -m venv /tmp/webmap-env
/tmp/webmap-env/bin/pip install -r requirements.txt gunicorn==23.0.0
pip install cyclonedx-bom==7.5.0
cyclonedx-py environment /tmp/webmap-env --pyproject pyproject.toml \
  --of JSON --sv 1.6 --mc-type application -o .sbom/sbom.cyclonedx.json
cyclonedx-py environment /tmp/webmap-env --pyproject pyproject.toml \
  --of XML --sv 1.6 --mc-type application -o .sbom/sbom.cyclonedx.xml
trivy sbom --format spdx-json --output .sbom/sbom.spdx.json .sbom/sbom.cyclonedx.json
```

## Using it

```bash
trivy sbom .sbom/sbom.cyclonedx.json
cp .sbom/sbom.cyclonedx.json /tmp/bom.cdx.json && osv-scanner scan source -L /tmp/bom.cdx.json
jq -r '.components[] | "\(.name) \(.version)"' .sbom/sbom.cyclonedx.json
```

OSV-Scanner chooses the parser from the file name, hence the copy to
`*.cdx.json`.
