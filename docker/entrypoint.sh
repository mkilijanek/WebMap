#!/bin/sh
set -e

# Create or update the login user on every start, so changing
# WEBMAP_PASSWORD and restarting the container rotates the password.
if [ -n "$WEBMAP_PASSWORD" ] || [ -n "$WEBMAP_PASSWORD_FILE" ]; then
	python manage.py webmap_user
else
	echo "WARNING: WEBMAP_PASSWORD not set; no login user was created or updated." >&2
fi
unset WEBMAP_PASSWORD

exec gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 4 --timeout 90 nmapdashboard.wsgi:application
