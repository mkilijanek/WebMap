# Configuration

WebMap reads its configuration from environment variables when the
container (or `manage.py`) starts. `docker/settings.py` is the only place
they are read; [.env.example](../.env.example) lists them for
`docker run --env-file`.

Boolean variables accept `true`, `1`, `yes`, `on` (case-insensitive);
anything else is false. Lists are comma-separated.

## Core

| Variable | Default | Notes |
|---|---|---|
| `DJANGO_SECRET_KEY` | random at every start | Signs sessions and CSRF tokens. Without it, every restart logs everybody out and a warning is printed. Generate with `python3 -c "import secrets; print(secrets.token_urlsafe(50))"`. |
| `DEBUG` | `false` | Never enable on an instance anyone else can reach: error pages show code and settings. |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1,[::1]` | Host names (the `Host` header) the app answers to. Add the proxy's public name when running behind one. |
| `WEBMAP_LOG_LEVEL` | `INFO` | Level of the `nmapreport` loggers (logins, CVE and PDF errors). Logs go to stdout/stderr (`docker logs`). |

## Login user

Read by `manage.py webmap_user`, which `docker/entrypoint.sh` runs at
every start. The password is checked against Django's password validators
(length, similarity to the user name, common passwords, all-numeric); a
rejected password stops the container.

| Variable | Default | Notes |
|---|---|---|
| `WEBMAP_USER` | `webmap` | Created if missing, re-activated and given the current password otherwise. |
| `WEBMAP_PASSWORD` | none | Plain value. Visible in `docker inspect` and to processes that can read the container's environment. |
| `WEBMAP_PASSWORD_FILE` | none | Path to a file with the password (e.g. a Docker secret at `/run/secrets/...`). Takes precedence over `WEBMAP_PASSWORD`. |

Without either password variable no user is created or changed and a
warning is printed.

## Login limit

| Variable | Default | Notes |
|---|---|---|
| `WEBMAP_LOGIN_MAX_FAILURES` | `5` | Failed logins allowed per user name and per client address within the lockout window. `0` disables the limit. |
| `WEBMAP_LOGIN_LOCKOUT_SECONDS` | `900` | Length of the window; it starts with the first failure. While locked, login attempts get HTTP 429 and the password is not checked. |

The counters are kept in the process's memory: they reset on restart and
are not shared between gunicorn workers (the container runs one).

## HTTPS and reverse proxy

The container serves plain HTTP. For remote access put a TLS reverse proxy
in front (see [deployment.md](deployment.md)) and set:

| Variable | Default | Notes |
|---|---|---|
| `WEBMAP_HTTPS` | `false` | Session and CSRF cookies get the `Secure` flag: the browser then sends them over HTTPS only. |
| `CSRF_TRUSTED_ORIGINS` | empty | Origins allowed to POST, e.g. `https://webmap.example.internal`. Needed when the proxy's scheme or host differs from what Django sees. |
| `WEBMAP_TRUSTED_PROXY` | `false` | Trust `X-Forwarded-Proto: https` from the proxy. Set it only if the proxy always overwrites that header; otherwise any client can claim HTTPS. |
| `WEBMAP_SSL_REDIRECT` | `false` | Redirect HTTP to HTTPS. Requires `WEBMAP_TRUSTED_PROXY` behind a TLS-terminating proxy, or every request redirects in a loop. |
| `WEBMAP_HSTS_SECONDS` | `0` (off) | `Strict-Transport-Security` max-age. Once a browser has seen it, plain HTTP stops working for that host name for the whole period; start small (e.g. `3600`). |
| `WEBMAP_HSTS_INCLUDE_SUBDOMAINS` | `false` | Adds `includeSubDomains` to HSTS. |

## Data locations and limits

| Variable | Default | Notes |
|---|---|---|
| `WEBMAP_XML_DIR` | `/opt/xml` | Nmap XML files. Read-only access is enough. |
| `WEBMAP_NOTES_DIR` | `/opt/notes` | Labels, notes and CVE results. Must be writable. |
| `WEBMAP_DB_PATH` | `/opt/webmap-data/db.sqlite3` | SQLite database (users and sessions). Its directory must be writable. |
| `WEBMAP_MAX_XML_MB` | `100` | Larger scan files are refused. |
| `WEBMAP_SCAN_CACHE` | `4` | Parsed scan files kept in memory (least recently used are dropped). |

## External services and tools

| Variable | Default | Notes |
|---|---|---|
| `WEBMAP_CVE_API` | `https://cve.circl.lu/api/cvefor/` | Prefix the URL-encoded CPE string is appended to. Must return a JSON list of objects with an `id`. |
| `WKHTMLTOPDF_PATH` | `wkhtmltopdf` on `PATH`, then `/opt/wkhtmltox/bin/wkhtmltopdf` | PDF renderer. |

## Fixed settings

Not configurable on purpose (change `docker/settings.py` if you must):
the Content-Security-Policy, `X-Frame-Options: DENY`, `SameSite=Strict`
and `HttpOnly` cookies, 1-hour sessions that end with the browser, and
`LoginRequiredMiddleware`.
