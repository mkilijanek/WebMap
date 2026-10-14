# Changelog

Notable changes to this fork (`mkilijanek/WebMap`, branch `v2/master`).
Security findings are described in
[docs/security-history.md](docs/security-history.md).

## Unreleased: v1.2 security review

### Security
- Content-Security-Policy (`script-src 'self'`, no inline scripts,
  `frame-ancestors 'none'`); all fonts and icon CSS vendored, no CDN left.
- Failed-login limit per user name and client address
  (`WEBMAP_LOGIN_MAX_FAILURES`, `WEBMAP_LOGIN_LOCKOUT_SECONDS`); logins
  and API failures logged to stdout.
- HTTPS settings configurable: `WEBMAP_HTTPS`, `CSRF_TRUSTED_ORIGINS`,
  `WEBMAP_TRUSTED_PROXY`, `WEBMAP_SSL_REDIRECT`, `WEBMAP_HSTS_SECONDS`.
- Labels and notes can only be stored for hosts of the selected scan.
- `safe_join` resolves symlinks.
- Container: code owned by root, database in `/opt/webmap-data`,
  `HEALTHCHECK`.
- CI: workflows run on pull requests to `v2/master`; Python 3.12;
  pip-audit, Bandit and TruffleHog failures fail the run; unit tests in
  CI; actions pinned to SHAs; downloaded tools checksum-verified;
  Dependabot auto-merge limited to patch updates.

### Changed
- API errors use HTTP status codes (400/404/429/500/502/504) instead of
  200 with an error body.
- Parsed scans are cached with a size limit (`WEBMAP_SCAN_CACHE`).
- `WEBMAP_XML_DIR`, `WEBMAP_NOTES_DIR`, `WEBMAP_DB_PATH`, `WEBMAP_CVE_API`
  added.
- SBOM covers transitive dependencies and gunicorn.
- Documentation rewritten: README, SECURITY.md, `docs/`. Removed the
  outdated `SECURITY_ANALYSIS.md`, `SECURITY_AUTOMATION.md`,
  `SECURITY_UPDATE_GUIDE.md`, `DJANGO_UPDATE.md`, `SBOM.md` and the
  duplicate `.github/SECURITY.md`; their still-relevant content is in
  `docs/`.

### Fixed
- Notes with non-ASCII characters (e.g. Polish diacritics) can be saved.
- Tests no longer touch `/opt/xml` and `/opt/notes`.

### Removed
- `defusedxml` (never used), `sanitize_notes_content`, the unused
  `port/<port>/` view.

## 2026-10-14

- PR #39: Django 6.1.2, CodeQL quality fixes, third-party actions pinned.
- PR #38: v1.1 review fixes (issues #27-#37): Django login, PDF rendered
  from stdin, scan-bound annotations (`webmap_migrate_annotations`),
  vendored JavaScript, IPv6/MAC hosts, robust XML parsing.
- PR #26: v1.0 review fixes: stored XSS, broken import, Docker build of
  this fork with pinned dependencies, POST + CSRF for state changes.
- Dependency updates: Django 6.1 (#25), xmltodict 1.0.4 (#13), requests
  2.34.2, GitHub Actions.

## 2025-12-20

- PR #2: first security hardening (input validation, `subprocess` without
  shell, secret key and debug from the environment, Django 5.2.9), security
  workflows, Dependabot and SBOM.
