# Deployment

## Container

`docker/Dockerfile` builds this repository on `python:3.12-slim-bookworm`
with the pinned `requirements.txt`, gunicorn and Debian's `wkhtmltopdf`.

```bash
docker build -f docker/Dockerfile -t webmap:local .
```

Layout inside the container:

| Path | Owner / access | Contents |
|---|---|---|
| `/opt/nmapdashboard` | root, read-only for the app | Django project and the app (`nmapreport/`) |
| `/opt/webmap-data` | `webmap`, read-write | SQLite database (users, sessions) |
| `/opt/xml` | read | Nmap XML files; mount read-only |
| `/opt/notes` | `webmap`, read-write | Labels, notes, CVE results; mount a volume to keep them |

The process runs as the unprivileged `webmap` user: gunicorn, one worker,
four threads, port 8000, plain HTTP. `HEALTHCHECK` tests that the port
accepts connections.

Minimal run, bound to localhost:

```bash
docker run -d --name webmap \
  -p 127.0.0.1:8000:8000 \
  --env-file .env \
  -v /srv/webmap/xml:/opt/xml:ro \
  -v webmap-notes:/opt/notes \
  --read-only --tmpfs /tmp \
  -v webmap-data:/opt/webmap-data \
  --cap-drop ALL --security-opt no-new-privileges \
  webmap:local
```

`--read-only`, `--cap-drop ALL` and `no-new-privileges` are optional
hardening; the app writes only to `/opt/notes`, `/opt/webmap-data` and
`/tmp`. With `-v webmap-data:/opt/webmap-data` the database (and the
users in it) survives rebuilds; the login user is still reset from the
environment at every start.

## Remote access through a TLS reverse proxy

The container has no TLS. Keep port 8000 on `127.0.0.1` (or an internal
Docker network) and terminate TLS in a reverse proxy. Example for nginx on
the same host:

```nginx
server {
    listen 443 ssl;
    server_name webmap.example.internal;

    ssl_certificate     /etc/ssl/webmap/fullchain.pem;
    ssl_certificate_key /etc/ssl/webmap/privkey.pem;

    # PDF reports of large scans take a while
    proxy_read_timeout 90s;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        # overwrite, never append: WebMap trusts this header only when
        # WEBMAP_TRUSTED_PROXY=true
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

and start the container with:

```
ALLOWED_HOSTS=webmap.example.internal
CSRF_TRUSTED_ORIGINS=https://webmap.example.internal
WEBMAP_HTTPS=true
WEBMAP_TRUSTED_PROXY=true
WEBMAP_SSL_REDIRECT=true
WEBMAP_HSTS_SECONDS=3600
```

Behind a proxy every request reaches WebMap from the proxy's address, so
the per-address login limit counts all clients together; the per-user
limit still applies. Restrict who can reach the proxy (VPN, firewall,
client certificates) rather than relying on the login alone.

## Hardening checklist

- [ ] `DJANGO_SECRET_KEY` set to a random 50-character value and kept out
      of version control.
- [ ] `DEBUG` unset or `false`.
- [ ] A strong `WEBMAP_PASSWORD`, preferably via `WEBMAP_PASSWORD_FILE`.
- [ ] Port published on `127.0.0.1` only, or behind a TLS proxy with
      `WEBMAP_HTTPS=true` and `CSRF_TRUSTED_ORIGINS` set.
- [ ] `/opt/xml` mounted read-only; only trusted people can write scan
      files.
- [ ] `/opt/notes` on a volume that is backed up if annotations matter.
- [ ] `docker logs webmap` reviewed for `login failed` / `login refused`.
- [ ] Image rebuilt regularly (Debian security updates for wkhtmltopdf and
      its libraries; Python dependency updates via Dependabot).
- [ ] `python manage.py check --deploy` reviewed after configuration
      changes (expected warnings on a localhost-only HTTP setup: HSTS,
      SSL redirect, secure cookies).

## Upgrading

1. Pull `v2/master` and rebuild the image.
2. Recreate the container with the same volumes and environment.
3. Coming from a version before 2026-10-14 (annotations keyed by file name
   only): run `docker exec webmap python manage.py
   webmap_migrate_annotations --dry-run`, then without `--dry-run`.
4. Coming from a version before the v1.2 review: the database moved from
   `/opt/nmapdashboard/db.sqlite3` to `/opt/webmap-data/db.sqlite3`. It only
   holds the login user and sessions, which are recreated at start; nothing
   needs to be migrated.
