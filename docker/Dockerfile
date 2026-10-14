# WebMap
# -
# Builds this repository (not upstream) with the pinned requirements.txt.
#
# Usage, from the repository root:
#   $ docker build -f docker/Dockerfile -t webmap:local .
#   $ mkdir -p /tmp/webmap
#   $ docker run -d --name webmap -p 127.0.0.1:8000:8000 \
#       -e DJANGO_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')" \
#       -v /tmp/webmap:/opt/xml webmap:local
#
# Nmap Example:
#   $ nmap -sT -A -oX /tmp/webmap/myscan.xml 192.168.1.0/24
#
# Now you can point your browser to http://localhost:8000
# WebMap has no authentication: keep it bound to localhost.

FROM python:3.12-slim-bookworm

RUN apt-get update && \
    apt-get install -y --no-install-recommends wkhtmltopdf && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt gunicorn==23.0.0 && \
    mkdir -p /opt/nmapdashboard /opt/xml /opt/notes && \
    django-admin startproject nmapdashboard /opt/nmapdashboard

COPY . /opt/nmapdashboard/nmapreport
COPY docker/settings.py docker/urls.py /opt/nmapdashboard/nmapdashboard/

WORKDIR /opt/nmapdashboard
RUN DJANGO_SECRET_KEY=build-only python manage.py migrate --noinput && \
    useradd --system --no-create-home --home-dir /opt/nmapdashboard webmap && \
    chown webmap /opt/nmapdashboard /opt/nmapdashboard/db.sqlite3 /opt/notes /opt/nmapdashboard/nmapreport/static

USER webmap
EXPOSE 8000

# One process so the per-process fallback SECRET_KEY stays consistent;
# threads are needed because PDF generation calls back into the app.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--timeout", "60", "nmapdashboard.wsgi:application"]
