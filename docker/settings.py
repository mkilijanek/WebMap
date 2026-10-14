import os
import secrets

from django.utils.csp import CSP


def env_bool(name, default=False):
    return os.environ.get(name, str(default)).strip().lower() in ('true', '1', 'yes', 'on')


def env_list(name, default=''):
    return [v.strip() for v in os.environ.get(name, default).split(',') if v.strip()]

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Every security-relevant setting comes from the environment; see .env.example
# and docs/configuration.md for the full list.

# Generate a key with: python3 -c "import secrets; print(secrets.token_urlsafe(50))"
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')
if not SECRET_KEY:
    # For development only - generate random key
    # In production, ALWAYS set DJANGO_SECRET_KEY environment variable
    import warnings
    warnings.warn(
        'DJANGO_SECRET_KEY not set in environment. Using auto-generated key. '
        'This is INSECURE for production! Set DJANGO_SECRET_KEY environment variable.',
        RuntimeWarning
    )
    SECRET_KEY = secrets.token_urlsafe(50)


# Never enable DEBUG on an instance anyone else can reach.
DEBUG = env_bool('DEBUG')

# Host names this instance answers to. Default: localhost only.
ALLOWED_HOSTS = env_list('ALLOWED_HOSTS', 'localhost,127.0.0.1,[::1]')

# Origins allowed to send POST requests when WebMap is reached through a
# TLS reverse proxy, e.g. "https://webmap.example.internal".
CSRF_TRUSTED_ORIGINS = env_list('CSRF_TRUSTED_ORIGINS')

# WebMap is meant for localhost or a trusted internal network, never the
# internet. The container itself speaks plain HTTP.

# Authentication: the login user is created at container start from
# WEBMAP_USER / WEBMAP_PASSWORD (manage.py webmap_user).
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'

# Application definition

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'nmapreport',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.csp.ContentSecurityPolicyMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    # Every view needs a logged-in user unless marked @login_not_required
    'django.contrib.auth.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'nmapdashboard.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'nmapdashboard.wsgi.application'


# Database
# https://docs.djangoproject.com/en/stable/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        # Kept outside the code directory, which the app user cannot write.
        'NAME': os.environ.get('WEBMAP_DB_PATH', '/opt/webmap-data/db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/stable/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/stable/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

# USE_L10N removed in Django 5.0 - localized formatting is always enabled
# USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/stable/howto/static-files/

STATIC_URL = '/static/'

# Security Settings
# https://docs.djangoproject.com/en/stable/topics/security/

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'same-origin'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'

# Content Security Policy (Django's built-in middleware). Pages load scripts,
# styles and fonts from this app only and carry no inline JavaScript.
# 'unsafe-inline' for styles is needed for the style="" attributes in the
# generated markup; it does not allow script execution.
SECURE_CSP = {
    'default-src': [CSP.NONE],
    'script-src': [CSP.SELF],
    'style-src': [CSP.SELF, CSP.UNSAFE_INLINE],
    'img-src': [CSP.SELF, 'data:'],
    'font-src': [CSP.SELF],
    'connect-src': [CSP.SELF],
    'form-action': [CSP.SELF],
    'frame-ancestors': [CSP.NONE],
    'base-uri': [CSP.SELF],
}

# Session security
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_AGE = 3600  # 1 hour

# CSRF protection
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# HTTPS. The container has no TLS of its own; put a TLS reverse proxy in
# front of it and set WEBMAP_HTTPS=true so cookies are only sent over HTTPS.
# WEBMAP_TRUSTED_PROXY=true makes Django trust X-Forwarded-Proto from that
# proxy: only set it if the proxy overwrites the header on every request.
WEBMAP_HTTPS = env_bool('WEBMAP_HTTPS')
SESSION_COOKIE_SECURE = WEBMAP_HTTPS
CSRF_COOKIE_SECURE = WEBMAP_HTTPS
if env_bool('WEBMAP_TRUSTED_PROXY'):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
SECURE_SSL_REDIRECT = env_bool('WEBMAP_SSL_REDIRECT')
# HSTS is opt-in: once a browser has seen it, plain HTTP stops working for
# that host name for the whole period.
SECURE_HSTS_SECONDS = int(os.environ.get('WEBMAP_HSTS_SECONDS', '0'))
SECURE_HSTS_INCLUDE_SUBDOMAINS = env_bool('WEBMAP_HSTS_INCLUDE_SUBDOMAINS')

# Request size limits
FILE_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 10485760  # 10MB

# Logging to stdout/stderr (docker logs). Failed and refused logins are
# logged by nmapreport.auth, suspicious requests by django.security.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'plain': {'format': '%(asctime)s %(levelname)s %(name)s: %(message)s'},
    },
    'handlers': {
        'console': {'class': 'logging.StreamHandler', 'formatter': 'plain'},
    },
    'root': {'handlers': ['console'], 'level': 'WARNING'},
    'loggers': {
        'nmapreport': {'level': os.environ.get('WEBMAP_LOG_LEVEL', 'INFO'), 'propagate': True},
        'django.security': {'level': 'WARNING', 'propagate': True},
    },
}
