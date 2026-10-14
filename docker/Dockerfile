# WebMap
# -
# https://github.com/Rev3rseSecurity/WebMap
# Rev3rse Security: https://www.youtube.com/rev3rsesecurity
# Author: theMiddle
# -
# Usage (build context is the repository root):
#   $ git clone https://github.com/mkilijanek/WebMap.git /opt/WebMap
#   $ cd /opt/WebMap
#   $ docker build -f docker/Dockerfile -t webmap:latest .
#   $ docker run -d -v /opt/WebMap/docker/xml:/opt/xml -p 8000:8000 webmap:latest
#
# Production: pass a stable secret so sessions survive restarts
#   $ docker run ... -e DJANGO_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')" webmap:latest
#
# Nmap Example:
#   $ nmap -sT -A -oX /tmp/myscan.xml 192.168.1.0/24
#   $ mv /tmp/myscan.xml /opt/WebMap/docker/xml
#
# Now you can point your browser to http://localhost:8000

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv wkhtmltopdf ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# api.py expects wkhtmltopdf under /opt/wkhtmltox/bin
RUN mkdir -p /opt/xml /opt/notes /opt/wkhtmltox/bin && \
    ln -s /usr/bin/wkhtmltopdf /opt/wkhtmltox/bin/wkhtmltopdf

# Pinned, reproducible dependencies
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Django project + this repository as the "nmapreport" app
RUN cd /opt && django-admin startproject nmapdashboard
COPY . /opt/nmapdashboard/nmapreport/
COPY docker/settings.py /opt/nmapdashboard/nmapdashboard/settings.py
COPY docker/urls.py /opt/nmapdashboard/nmapdashboard/urls.py

RUN cd /opt/nmapdashboard && python manage.py migrate

EXPOSE 8000

ENTRYPOINT ["python", "/opt/nmapdashboard/manage.py", "runserver", "0:8000"]
