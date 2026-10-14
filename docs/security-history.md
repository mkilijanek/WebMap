# Security review history

Reviews of this fork, newest first, with the pull requests that fixed the
findings. Severity is the reviewer's rating at the time. The full review
reports (Polish, with evidence, MITRE ATT&CK mapping and confidence levels)
are kept outside the repository by the maintainer.

## v1.2: 2026-10-14, whole code base, CI and documentation

Commit reviewed: `775bd70` (after PR #39). Manual review of all Python,
JavaScript, templates, Dockerfile, workflows and documentation; Bandit,
pip-audit, Semgrep (semgrep-rules: python, javascript, html, dockerfile,
github-actions, bash), CodeQL (python, javascript, actions;
security-extended + security-and-quality), Trivy fs, hadolint; UI checked
in headless Chromium with the new CSP.

Scanner results on the reviewed commit: pip-audit, CodeQL and Trivy
(vulnerabilities) clean; Bandit low only (subprocess, accepted); Trivy and
hadolint flagged the missing `HEALTHCHECK`; Semgrep findings were
mutable action tags (true positive, R-02) and false positives or accepted
patterns (escaped HTML via `|safe`, jQuery `.html()` on escaped strings).

| ID | Severity | Finding | Fixed in |
|---|---|---|---|
| R-01 | Medium | Security CI ineffective: PRs to `v2/master` not scanned; Python 3.11 cannot install Django 6.1, so pip-audit and Safety failed silently; every scanner `\|\| true`; dependency-review config invalid (allow + deny licences) | v1.2 PR |
| R-02 | Medium | Dependabot auto-merge approved and merged minor updates without review; severity logic dead (`alert-state` is not a severity), comment script referenced an undefined variable; GitHub-owned actions and the Semgrep image not pinned | v1.2 PR |
| R-03 | Medium | No limit on failed logins and no authentication logging | v1.2 PR |
| R-04 | Medium | No Content-Security-Policy; inline JavaScript throughout; icon fonts and CSS loaded from Google Fonts (no SRI possible) and use.fontawesome.com | v1.2 PR |
| R-05 | Low | HTTPS settings documented in `.env.example` were never read; no way to set `CSRF_TRUSTED_ORIGINS` or trust a proxy, so TLS deployments either broke or ran without `Secure` cookies | v1.2 PR |
| R-06 | Low | Annotation API wrote files for any MD5 value (unbounded files); errors returned with HTTP 200; unexpected exceptions swallowed without logging | v1.2 PR |
| R-07 | Low | Parsed scans cached without limit (memory growth with many large files) | v1.2 PR |
| R-08 | Low | Test suite wrote to the real `/opt/xml` and deleted recent files in `/opt/notes` | v1.2 PR |
| R-09 | Low | App user owned the code directory and could replace `manage.py`, which runs at every start; no `HEALTHCHECK` | v1.2 PR |
| R-10 | Low | Notes with non-ASCII characters could not be saved (`btoa`) | v1.2 PR |
| R-11 | Low | Dependabot Docker updates pointed at `/` (Dockerfile is in `docker/`); deprecated `reviewers` key | v1.2 PR |
| R-12 | Info | `safe_join` did not resolve symlinks | v1.2 PR |
| R-13 | Info | Dead or misleading code: blacklist `sanitize_notes_content`, unused `defusedxml` presented as XXE protection, unreachable `port` view, debug block in the template | v1.2 PR |
| R-14 | Info | `.pre-commit-config.yaml` unusable (missing `.secrets.baseline`, formatters rewriting the tab-indented code, Python 3.11, old hook versions) | v1.2 PR |
| R-15 | Info | Documentation out of date or wrong: claimed CSP and HSTS, wrong licence badge (Apache-2.0, the licence is GPL-3.0), "CVE-001".."CVE-014" labels that are not CVE identifiers, SBOM listing Django 5.2.9 and only direct dependencies, unrealistic response-time promises | v1.2 PR |
| R-16 | Info | CIRCL cve-search API endpoint compatibility could not be verified | open, documented |
| R-17 | Info | HTML built by string concatenation with `\|safe` | open, documented |
| R-18 | Info | wkhtmltopdf unmaintained (CVE-2022-35583 class issues mitigated, not removed) | open, documented |

## v1.1: 2026-10-14, application logic

Commit reviewed: `6ecea82`. Findings filed as issues #27 to #37.

| ID | Severity | Finding | Fixed in |
|---|---|---|---|
| N-01 | Medium | Stored XSS through the scan file name (`#scantitle`) | #38 |
| N-02 | Medium | Third-party scripts without SRI, unpinned `buttons.js`, Google `jsapi` in the PDF renderer | #38 |
| N-03 | Medium | CVE check skipped ports (CPE map reset per port, results overwritten) | #38 |
| K-01 | Medium | No authentication; PDF at a predictable public URL | #38 |
| N-04 | Low | `html.escape` used in JS-in-attribute and shell-in-clipboard contexts | #38 |
| N-05 | Low | CPE with `../` traversed paths on the CVE API; unchecked JSON shape caused a persistent 500 | #38 |
| N-06 | Low | Labels, notes and CVEs carried over to a new scan with the same file name | #38 |
| N-07 | Low | Hosts without IPv4 inherited the previous host's address or broke the index | #38 |
| N-08 | Low | Index and report failed on `-sS -sU` (several `scaninfo`) and on incomplete XML | #38 |
| N-09 | Low | Synchronous PDF generation with an HTTP callback into the same worker | #38 |
| F-08 | Low | Session ID in `wkhtmltopdf`'s argv (from v1.0) | #38 |

PR #39 then cleared the open Security-tab alerts (Django 6.1.2, CodeQL
quality findings, third-party actions pinned to SHAs).

## v1.0: 2026-10-14, first review of `v2/master`

Commit reviewed: `003c1d5`.

| ID | Severity | Finding | Fixed in |
|---|---|---|---|
| F-01 | High (availability) | App did not start: broken `security_utils` import | #26 |
| F-02 | High | Dockerfile built the unpatched upstream with unpinned dependencies | #26 |
| F-03 | High | Stored XSS from scanned-host data | #26 |
| F-04 | High | XSS in `/view/pdf/` rendered by wkhtmltopdf 0.12.4 with JavaScript: SSRF and local file read | #26 |
| F-05 | Medium | CVE data fetched over HTTP and rendered unescaped | #26 |
| F-06 | Medium | No authentication; state changes via GET | #26 (CSRF/POST), #38 (login) |
| F-07 | Medium | Notes inserted as raw HTML and into raw JS context | #26 |
| F-08 | Low | Session ID in wkhtmltopdf argv | #38 |
| F-09 | Low | Absolute paths in error messages | #26 |
| F-10 | Low | `CSP_*` settings had no effect; `defusedxml` unused | #26 (removed dead settings), v1.2 PR (real CSP, dependency removed) |
| F-11 | Info | `requirements.txt` called Django 6.1 an LTS | #26 |

## 2025-12-20: initial hardening (PR #2)

The first analysis of the fork (formerly `SECURITY_ANALYSIS.md`) listed 14
issues under the labels "CVE-001" to "CVE-014". These were internal
labels, not CVE identifiers. Status as of v1.2:

| Label | Issue | Status |
|---|---|---|
| CVE-001 | Command injection in PDF generation (`os.popen` with the session key concatenated into the command) | Fixed in #2 (`subprocess` without shell); session id removed from argv in #38 |
| CVE-002 | Path traversal in file names | Fixed in #2 (`security_utils.safe_join`, name validation); symlinks handled in v1.2 |
| CVE-003 | Hard-coded `SECRET_KEY` | Fixed in #2 |
| CVE-004 | `DEBUG = True` | Fixed in #2 |
| CVE-005 | `ALLOWED_HOSTS = ['*']` | Fixed in #2 |
| CVE-006 | Stored XSS | Partly mitigated in #2; fixed in #26 and #38 (F-03, F-07, N-01, N-04); CSP in v1.2 |
| CVE-007 | XXE | Fixed in #2 (`disable_entities=True`) |
| CVE-008 | Missing CSRF protection | Fixed in #2 and #26 (POST-only state changes) |
| CVE-009 | Insufficient input validation | Fixed in #2 (`security_utils`) |
| CVE-010 | Unvalidated CPE sent to the CVE API over HTTP, response used without checks | Fixed in #2 and #26 (HTTPS, CPE validation, timeout); response shape and path segments in #38 (N-05) |
| CVE-011 | Information disclosure in error messages | Fixed in #26 (F-09) and v1.2 (paths no longer in exceptions) |
| CVE-012 | Unpinned dependencies | Fixed in #2 |
| CVE-013 | Missing security headers | Partly in #2 (the CSP settings had no effect, F-10); CSP added in v1.2 |
| CVE-014 | Weak session configuration | Fixed in #2 |

The same PR upgraded Django from 4.2.15 to 5.2.9 for CVE-2025-64459,
CVE-2024-53908, CVE-2025-57833 and CVE-2025-59681; Django has since moved
to 6.1.2 (#25, #39).
