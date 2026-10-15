<p align="center">
<img width="300" src="https://i.imgur.com/puyIfHT.jpg" alt="WebMap" /><br>
A web dashboard for Nmap XML reports
</p>

<p align="center">
  <a href="https://github.com/mkilijanek/WebMap/actions/workflows/security-scan.yml">
    <img src="https://github.com/mkilijanek/WebMap/actions/workflows/security-scan.yml/badge.svg" alt="Security Scan">
  </a>
  <a href="https://github.com/mkilijanek/WebMap/actions/workflows/codeql-analysis.yml">
    <img src="https://github.com/mkilijanek/WebMap/actions/workflows/codeql-analysis.yml/badge.svg" alt="CodeQL">
  </a>
  <a href="SECURITY.md">
    <img src="https://img.shields.io/badge/security-policy-blue.svg" alt="Security Policy">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-GPL--3.0-blue.svg" alt="License: GPL-3.0">
  </a>
</p>

> **Scope:** WebMap is built for one analyst on `localhost` or a trusted
> internal network. Scan results are sensitive; do not expose an instance to
> the internet. See [SECURITY.md](SECURITY.md).

WebMap reads the XML files Nmap writes (`nmap -oX`) and shows them as a
browsable dashboard: hosts, ports, services, charts, per-host notes and
labels, CVE lookups for the CPEs Nmap reports, and a PDF report.

This repository (`mkilijanek/WebMap`, default branch `v2/master`) is a
security-hardened fork of [Rev3rseSecurity/WebMap](https://github.com/Rev3rseSecurity/WebMap).

![WebMap](https://i.imgur.com/U9S089v.png)

## Contents

- [Quick start](#quick-start)
- [Features](#features)
- [Configuration](#configuration)
- [Security](#security)
- [Documentation](#documentation)
- [XML file names](#xml-file-names)
- [CVE and exploits](#cve-and-exploits)
- [Third-party components](#third-party-components)
- [Contributors](#contributors)
- [Licence](#licence)

## Quick start

Build the image from this repository and keep the port bound to localhost.
WebMap asks for a login; the user is created (or its password updated) at
every container start from `WEBMAP_USER` / `WEBMAP_PASSWORD`. Django's
password validators apply: a rejected password stops the container.

```bash
docker build -f docker/Dockerfile -t webmap:local .
mkdir -p /tmp/webmap

docker run -d \
  --name webmap \
  -h webmap \
  -p 127.0.0.1:8000:8000 \
  -e DJANGO_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')" \
  -e WEBMAP_USER=webmap \
  -e WEBMAP_PASSWORD='<choose a strong password>' \
  -v /tmp/webmap:/opt/xml:ro \
  webmap:local

# run Nmap and save the XML report where the container can read it
nmap -sT -A -T4 -oX /tmp/webmap/myscan.xml 192.168.1.0/24
```

Open http://localhost:8000 and log in. `docker/setup.txt` does the same
interactively. For Docker secrets use `WEBMAP_PASSWORD_FILE` instead of
`WEBMAP_PASSWORD` (an environment variable stays visible in
`docker inspect`).

Labels, notes and CVE results are stored in `/opt/notes` inside the
container. Mount a volume there (`-v webmap-notes:/opt/notes`) if they must
survive a container rebuild.

Upgrading from a version that keyed annotations by file name only:
`docker exec webmap python manage.py webmap_migrate_annotations` attaches
the old ones to the scan files currently in `/opt/xml` (`--dry-run` to
preview). Annotations now belong to one scan: they are keyed by the file
name and a hash of its content, so a new scan saved under the same name
starts clean.

## Features

- Import and parse Nmap XML files (incomplete files from a running scan are
  listed with an error instead of breaking the page)
- Statistics and charts on discovered services, ports and OS types
- Host detail view, including hosts with only an IPv6 or MAC address
- Labels and plain-text notes per host (any language, stored as UTF-8)
- PDF report with statistics, port tables, NSE output, labels, notes and
  CVEs, rendered on the server and returned directly (no file is left on
  disk)
- Copy curl, Nikto or Telnet commands for an open port to the clipboard
  (arguments are shell-quoted)
- CVE and exploit lookup for the CPEs Nmap reports

## Configuration

All settings come from environment variables. The important ones:

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_SECRET_KEY` | random per start (sessions are lost on restart) | Signing key; set it |
| `WEBMAP_USER` / `WEBMAP_PASSWORD` / `WEBMAP_PASSWORD_FILE` | `webmap` / none | Login user created at start |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Host names the app answers to |
| `WEBMAP_HTTPS` | `false` | Secure cookies, behind a TLS reverse proxy |
| `CSRF_TRUSTED_ORIGINS` | empty | e.g. `https://webmap.example.internal` behind a proxy |

The full list, including the reverse-proxy, HSTS, login-limit and logging
settings, is in [docs/configuration.md](docs/configuration.md);
[.env.example](.env.example) is a template for `docker run --env-file`.

## Security

What the application does, as of the v1.2 review (2026-10-14):

- **Authentication** on every view (Django login, `LoginRequiredMiddleware`),
  failed logins limited per user name and client address and logged.
- **Output encoding**: every value from Nmap XML, notes and CVE data is
  HTML-escaped; JavaScript receives data only through `data-*` attributes
  and a JSON block, never through generated code.
- **Content-Security-Policy**: scripts, styles and fonts only from the app
  itself (`script-src 'self'`, no inline scripts), `frame-ancestors 'none'`.
  All front-end libraries and fonts are vendored in `static/vendor/`.
- **CSRF**: state changes are POST-only with Django's CSRF protection;
  cookies are `HttpOnly`, `SameSite=Strict`, `Secure` with `WEBMAP_HTTPS`.
- **Files**: scan and annotation names are validated, paths resolved
  (symlinks included) and confined to their directory; annotations can
  only be written for hosts of the selected scan.
- **XML**: parsed with entity expansion disabled and a size limit
  (`WEBMAP_MAX_XML_MB`, default 100).
- **PDF**: `wkhtmltopdf` gets the HTML on stdin with JavaScript and local
  file access disabled; no shell, no callback to the web server.
- **Container**: runs as an unprivileged user that cannot modify the code;
  no TLS of its own (put a reverse proxy in front for remote access).

Known limitations and accepted risks are listed in
[SECURITY.md](SECURITY.md#known-limitations). Report vulnerabilities
privately, as described there, not in public issues.

## Documentation

| Document | Contents |
|---|---|
| [SECURITY.md](SECURITY.md) | Security policy, reporting, threat model, controls, limitations |
| [docs/configuration.md](docs/configuration.md) | All environment variables |
| [docs/deployment.md](docs/deployment.md) | Running the container, TLS reverse proxy, hardening checklist |
| [docs/development.md](docs/development.md) | Running the tests, local scanners, CI workflows, dependency updates |
| [docs/sbom.md](docs/sbom.md) | Software bill of materials in `.sbom/` |
| [docs/security-history.md](docs/security-history.md) | Past security reviews and what fixed each finding |
| [CHANGELOG.md](CHANGELOG.md) | Notable changes |

## XML file names

Scan files must be in `/opt/xml`, end in `.xml` and use only letters,
digits, `-`, `_` and `.` (no leading dot). Other files are not listed.

The PDF report uses the file name as its title: `.xml` is removed and `_`
becomes a space. Example: `ACME_Ltd..xml` gives the title `ACME Ltd.`

## CVE and exploits

WebMap looks up CVEs and exploits for each CPE Nmap collected, using the
[CIRCL](https://cve.circl.lu) API (`WEBMAP_CVE_API`). Only CPEs with a
version are checked (for example `cpe:/a:microsoft:iis:7.5`, not
`cpe:/o:microsoft:windows`), and only CPEs that appear in the selected scan
for that host and port. The lookup sends the CPE strings, not host
addresses, to the API.

CIRCL has moved its cve-search service to Vulnerability-Lookup. Whether the
legacy `/api/cvefor/<cpe>` endpoint and its response format are still served
could not be verified during the v1.2 review (the API was not reachable from
the review environment). If lookups return "Failed to fetch CVE data from
external API", check the endpoint first.

## Third-party components

Runtime (Python): [Django](https://www.djangoproject.com),
[requests](https://requests.readthedocs.io),
[xmltodict](https://github.com/martinblech/xmltodict),
[gunicorn](https://gunicorn.org) (container only).
System: [wkhtmltopdf](https://wkhtmltopdf.org) from Debian (container only).

Front end, vendored in `static/vendor/` with checksums in
[static/vendor/README.md](static/vendor/README.md):
[Materialize CSS](https://materializecss.com), [jQuery](https://jquery.com),
[Chart.js](https://www.chartjs.org), [Clipboard.js](https://clipboardjs.com),
[Font Awesome Free](https://fontawesome.com),
[Material Icons](https://github.com/google/material-design-icons).

## Contributors

Original project by Andrea "theMiddle" Menin
([@Menin_TheMiddle](https://twitter.com/Menin_TheMiddle)), Rev3rse Security.

- s3th_0x [@adubaldo](https://github.com/adubaldo) (bug on single host report)
- Neetx [@Neetx](https://github.com/Neetx) (bug on xml with no host up)

## Licence

GNU General Public License v3.0, see [LICENSE](LICENSE).
