# WebMap
# -
# Builds this repository (not upstream) with the pinned requirements.txt.
#
# Usage, from the repository root:
#   $ docker build -f docker/Dockerfile -t webmap:local .
#   $ mkdir -p /tmp/webmap
#   $ docker run -d --name webmap -p 127.0.0.1:8000:8000 \
#       -e DJANGO_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')" \
#       -e WEBMAP_USER=webmap -e WEBMAP_PASSWORD='<choose a strong password>' \
#       -v /tmp/webmap:/opt/xml:ro -v webmap-notes:/opt/notes webmap:local
#
# Nmap Example:
#   $ nmap -sT -A -oX /tmp/webmap/myscan.xml 192.168.1.0/24
#
# Now you can point your browser to http://localhost:8000 and log in with
# WEBMAP_USER / WEBMAP_PASSWORD (or WEBMAP_PASSWORD_FILE for a Docker secret).
# Keep it bound to localhost or put it behind a TLS reverse proxy: there is
# no HTTPS here. All settings: docs/configuration.md; remote access and
# hardening: docs/deployment.md.

FROM python:3.14-slim-bookworm

# Not version-pinned on purpose: the rebuild should pick up Debian security
# updates. wkhtmltopdf is unmaintained upstream; see SECURITY.md.
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends wkhtmltopdf && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt gunicorn==23.0.0 && \
    mkdir -p /opt/nmapdashboard /opt/webmap-data /opt/xml /opt/notes && \
    django-admin startproject nmapdashboard /opt/nmapdashboard

COPY . /opt/nmapdashboard/nmapreport
COPY docker/settings.py docker/urls.py /opt/nmapdashboard/nmapdashboard/

WORKDIR /opt/nmapdashboard
# The code under /opt/nmapdashboard stays owned by root, so the app user
# cannot change what runs at the next start; it can only write its database
# (/opt/webmap-data) and the annotations (/opt/notes). /opt/xml only needs
# to be readable.
RUN DJANGO_SECRET_KEY=build-only python manage.py migrate --noinput && \
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin webmap && \
    chown -R webmap /opt/webmap-data /opt/notes

USER webmap
EXPOSE 8000

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8000), 4).close()"]

# One process so the per-process fallback SECRET_KEY stays consistent.
CMD ["/opt/nmapdashboard/nmapreport/docker/entrypoint.sh"]
