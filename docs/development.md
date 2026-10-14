# Development

## Layout

The repository root is the Django app `nmapreport`; `docker/` holds the
project-level settings, URLs and container files.

| File | Purpose |
|---|---|
| `views.py` | Scan list, scan overview, host details (HTML built in Python) |
| `api.py` | JSON/POST endpoints: labels, notes, CVE lookup, port details, PDF |
| `pdf.py` | Self-contained HTML report rendered to PDF by wkhtmltopdf |
| `scan.py` | Loading, validating and caching Nmap XML; annotations on disk |
| `auth.py` | Login view with failed-login limit and logging |
| `security_utils.py` | Input validation and path confinement |
| `functions.py` | Escaping and small helpers |
| `static/async.js` | All front-end behaviour (no inline scripts) |
| `docker/settings.py` | Django settings, all read from the environment |

## Running the tests

Python 3.12 or newer (Django 6.x requirement).

```bash
python3 -m venv /tmp/webmap-venv
/tmp/webmap-venv/bin/pip install -r requirements.txt

mkdir -p /tmp/webmap-dev && cd /tmp/webmap-dev
/tmp/webmap-venv/bin/django-admin startproject nmapdashboard .
ln -s /path/to/WebMap nmapreport
cp nmapreport/docker/settings.py nmapreport/docker/urls.py nmapdashboard/

export WEBMAP_DB_PATH=$PWD/db.sqlite3 DJANGO_SECRET_KEY=dev-only
/tmp/webmap-venv/bin/python manage.py test nmapreport
```

The tests create their own temporary XML and notes directories; they do
not touch `/opt/xml` or `/opt/notes`. The PDF tests use a fake
`wkhtmltopdf`. CI runs the same steps (`tests` job in
`.github/workflows/security-scan.yml`).

To click through the UI locally, also set `WEBMAP_XML_DIR`,
`WEBMAP_NOTES_DIR`, `WEBMAP_USER` and `WEBMAP_PASSWORD`, then run
`manage.py migrate`, `manage.py webmap_user` and `manage.py runserver`.

## Conventions

- Every value that comes from a scan file, notes or the CVE API goes
  through `esc()` (HTML) before it is concatenated into markup. Data for
  JavaScript goes into `data-*` attributes or `django.utils.html.json_script`,
  never into generated code.
- No inline `<script>` or `on*=` attributes: the CSP blocks them. Add
  behaviour to `static/async.js` and trigger it with `data-action`.
- No third-party URLs for scripts, styles or fonts: vendor them in
  `static/vendor/` and record the checksum in its README.
- API views return JSON errors with a 4xx/5xx status (`api.jsonapi`).
- New behaviour gets a test in `tests.py`.

## Local security checks

```bash
pip install pre-commit && pre-commit install
pre-commit run --all-files          # file hygiene, Bandit, django-upgrade,
                                    # yamllint, hadolint, shellcheck

pip install bandit pip-audit
bandit -r . --ini .bandit --severity-level medium --confidence-level medium
pip-audit -r requirements.txt
```

Semgrep, CodeQL and Trivy run in CI; see below for running them locally.

## CI workflows

All workflows run on pushes to `v2/master` and on pull requests against
it (plus `main`/`master`/`develop` and `claude/*` pushes where listed).
Actions are pinned to commit SHAs; tools downloaded by scripts are pinned
to a version and checked against a SHA-256.

| Workflow | Jobs | Blocking |
|---|---|---|
| `security-scan.yml` | unit tests; pip-audit (requirements + gunicorn); Bandit; TruffleHog (verified secrets, full history); Semgrep (report only, artifact); Trivy fs scan (vulnerabilities, Dockerfile, secrets → Security tab) | tests, pip-audit, Bandit, TruffleHog |
| `codeql-analysis.yml` | CodeQL for Python, JavaScript and the workflow files, `security-extended` + `security-and-quality` | results in the Security tab |
| `dependency-review.yml` | New dependencies in a PR: fails on moderate or worse vulnerabilities and on licences outside the allow-list in `.github/dependency-review-config.yml` | yes |
| `sbom-generation.yml` | CycloneDX + SPDX SBOM of the resolved environment, validation, Trivy and OSV-Scanner scans, attached to releases | validation |
| `dependabot-auto-merge.yml` | Auto-merge for Dependabot patch updates; minor/major get a review comment | n/a |

Auto-merge merges as soon as branch protection allows it. Without required
status checks on `v2/master` it merges immediately, so configure branch
protection (require the `Unit Tests`, `Dependency Vulnerability Scan` and
`Static Security Analysis (Bandit)` checks) before relying on it.

Code-scanning and Dependabot alerts are visible in the repository's
Security tab.

### Running the CI scanners locally

```bash
# Semgrep (registry rules need semgrep.dev; or clone semgrep/semgrep-rules)
pip install semgrep
semgrep scan --metrics off --config p/python --config p/django \
  --config p/javascript --config p/github-actions --exclude static/vendor

# Trivy
trivy fs --scanners vuln,secret,misconfig .

# CodeQL (bundle from github.com/github/codeql-action/releases)
codeql database create /tmp/cqdb --db-cluster \
  --language=python,javascript,actions --source-root .
codeql database analyze /tmp/cqdb/python \
  codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=python.sarif
```

## Dependency updates

- Dependabot opens PRs for pip (daily), the Docker base image and GitHub
  Actions (weekly). Review requests go to the code owners
  (`.github/CODEOWNERS`).
- For a manual update: change the pin in `requirements.txt`, run the tests
  and `pip-audit`, regenerate the SBOM ([sbom.md](sbom.md)), and note the
  change in `CHANGELOG.md`.
- Django: stay on a supported release. 6.1 is a feature release; move to
  the next LTS when it is out and read its release notes for removed
  settings first. Check with `manage.py check --deploy` and the
  `django-upgrade` pre-commit hook.
- Front-end libraries in `static/vendor/`: take them from the npm registry
  tarball, compare the tarball hash with the registry's `dist.integrity`,
  and record the file's sha384 in `static/vendor/README.md`.
