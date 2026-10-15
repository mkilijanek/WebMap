# Security Policy

WebMap shows Nmap scan results, which describe the attack surface of the
networks you scan. Treat an instance and its data as sensitive.

## Supported versions

Only the current `v2/master` branch receives security fixes. There are no
release branches or backports.

| Version | Supported |
|---|---|
| `v2/master` (latest commit) | yes |
| upstream `Rev3rseSecurity/WebMap`, older forks | no |

## Reporting a vulnerability

Do not report vulnerabilities in public issues, pull requests or
discussions.

Use GitHub's private vulnerability reporting:
[Security → Report a vulnerability](https://github.com/mkilijanek/WebMap/security/advisories/new).
If that is not available to you, open an issue that asks for a private
contact without describing the problem.

Please include the affected commit, the steps or a crafted Nmap XML file
that reproduces the issue, and the impact you expect.

This is a maintainer-run project without a security team. Reports are
handled on a best-effort basis, without a guaranteed response or fix time.
Confirmed issues are fixed on `v2/master` and described in a GitHub
security advisory; reporters are credited unless they ask not to be.

## Threat model

Intended deployment: one analyst (or a small trusted team) using a single
login, on `localhost` or a trusted internal network, optionally behind a
TLS reverse proxy. WebMap is not designed for internet exposure or for
users who must not see each other's data (there are no per-user
permissions: every logged-in user sees every scan).

What WebMap treats as untrusted input:

- **Nmap XML content.** A scanned host controls banners, service names,
  NSE script output, host names and CPE strings. A hostile host can try to
  attack the analyst's browser (stored XSS) or the PDF renderer through the
  report. This is the main threat the application is built against.
- **Scan file names**, from whoever can write to `/opt/xml`.
- **CVE API responses** from `cve.circl.lu` (fetched over HTTPS).
- **Requests** from anyone who can reach the port before logging in.

What WebMap trusts: the operator who runs the container, writes scan files
and holds the login.

## Security controls

| Area | Control | Where |
|---|---|---|
| Authentication | Django login on every view (`LoginRequiredMiddleware` plus `login_required` on the app's URLs); user created from `WEBMAP_USER`/`WEBMAP_PASSWORD(_FILE)` with Django's password validators | `docker/settings.py`, `urls.py`, `management/commands/webmap_user.py` |
| Brute force | Failed logins counted per user name and per client address; at `WEBMAP_LOGIN_MAX_FAILURES` (default 5) further attempts are refused for `WEBMAP_LOGIN_LOCKOUT_SECONDS` (default 900) without checking the password | `auth.py` |
| Audit | Successful, failed and refused logins, CVE lookup failures, PDF failures and unexpected API errors are logged to stdout | `auth.py`, `api.py`, `LOGGING` in `docker/settings.py` |
| XSS | All Nmap, notes and CVE values HTML-escaped (`esc()`); links from CVE data only if `http(s)`; notes are plain text; no inline JavaScript in pages; data for scripts passed in `data-*` attributes and a JSON block | `views.py`, `functions.py`, `pdf.py`, `static/async.js` |
| CSP | `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'` | `SECURE_CSP` in `docker/settings.py` |
| Supply chain (front end) | All JavaScript, CSS and fonts vendored with recorded checksums; no CDN | `static/vendor/` |
| CSRF | POST-only state changes, Django CSRF middleware, `SameSite=Strict` cookies | `api.py`, `views.py` |
| Headers | `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: same-origin`, `Cross-Origin-Opener-Policy: same-origin`; HSTS opt-in | `docker/settings.py` |
| Sessions | `HttpOnly`, `SameSite=Strict`, 1 hour, end with the browser; `Secure` with `WEBMAP_HTTPS` | `docker/settings.py` |
| Files | Scan names restricted to `[A-Za-z0-9_.-]`, no leading dot; paths resolved with symlinks and confined to their directory; annotations only for hosts of the selected scan; atomic writes | `security_utils.py`, `scan.py`, `api.py` |
| XML parsing | `xmltodict` with `disable_entities=True`, size limit `WEBMAP_MAX_XML_MB`, malformed files reported instead of crashing | `scan.py` |
| CVE lookup (SSRF) | Fixed HTTPS endpoint, CPE strictly validated, only CPEs present in the selected scan, no redirects, 10 s timeout, response shape checked | `api.py`, `security_utils.py` |
| PDF | `wkhtmltopdf` started without a shell, HTML on stdin, `--disable-javascript --disable-local-file-access`, one at a time, 60 s timeout | `api.py`, `pdf.py` |
| Container | Non-root user; code tree root-owned and read-only for that user; only `/opt/notes` and `/opt/webmap-data` writable; `HEALTHCHECK` | `docker/Dockerfile` |
| Dependencies | Pinned versions; Dependabot; pip-audit, Trivy, OSV-Scanner, CodeQL, Bandit, Semgrep, TruffleHog in CI | `.github/` |

## Known limitations

These are accepted for the intended deployment and documented so that
nobody relies on protection that is not there.

- **No TLS in the container.** gunicorn speaks plain HTTP on port 8000.
  For anything but `localhost`, put a TLS reverse proxy in front and set
  `WEBMAP_HTTPS=true` ([docs/deployment.md](docs/deployment.md)).
- **One permission level.** Every logged-in user can read every scan and
  change every annotation.
- **Login limit is per process.** Counters live in Django's local-memory
  cache; the container runs one gunicorn worker, so this holds. With more
  workers or replicas, configure a shared cache. Behind a reverse proxy
  every request appears to come from the proxy's address, so the
  per-address limit then acts as a global one (the per-user limit is
  unaffected).
- **A locked-out user is locked out too.** Someone who can reach the login
  page can keep the account locked by failing logins. Keep the port on
  `localhost` or an internal network.
- **`style-src 'unsafe-inline'`.** The generated markup uses `style=""`
  attributes. This does not allow script execution, but CSS injection
  would not be blocked by the CSP (all values are escaped regardless).
- **HTML is built by string concatenation** in `views.py` and `pdf.py` and
  rendered with `|safe`. Every value is escaped by hand with `esc()`; a
  missed call would be an XSS bug, with the CSP as the second line of
  defence. Moving the markup into Django templates (auto-escaping) is the
  long-term fix.
- **wkhtmltopdf is unmaintained** (archived upstream, old QtWebKit). Known
  issues include CVE-2022-35583 (SSRF through injected HTML). WebMap only
  passes escaped HTML, disables JavaScript and local file access, and does
  not load remote resources; residual risk remains in the rendering engine
  itself. Replacing it (e.g. WeasyPrint) is planned work.
- **Django 6.1 is not an LTS release.** It is supported until the next
  feature release plus a short overlap; plan the move to the next LTS.
- **CVE lookup endpoint.** The legacy CIRCL `/api/cvefor/` endpoint could
  not be verified during the v1.2 review; see the README.
- **Static files** are served by Django (`django.views.static.serve`),
  which the Django documentation does not recommend for heavy production
  use. For the single-user deployment this is acceptable.
- **Annotation keys use MD5** (of addresses and file name plus SHA-256 of
  the content). They are identifiers, not a security control
  (`usedforsecurity=False`).

## Security reviews

Each review, its findings and the pull requests that fixed them are listed
in [docs/security-history.md](docs/security-history.md).
