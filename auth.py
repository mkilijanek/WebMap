import hashlib, logging, os
from django.contrib.auth.views import LoginView
from django.core.cache import cache

logger = logging.getLogger('nmapreport.auth')

# Failed logins allowed per user name and per client address before further
# attempts are refused for LOCKOUT seconds. The counters live in the Django
# cache (per process with the default LocMemCache; the container runs one
# gunicorn worker).
MAX_FAILURES = int(os.environ.get('WEBMAP_LOGIN_MAX_FAILURES', '5'))
LOCKOUT = int(os.environ.get('WEBMAP_LOGIN_LOCKOUT_SECONDS', '900'))


def _key(kind, value):
	return 'webmap-login:%s:%s' % (kind, hashlib.sha256(value.encode('utf-8')).hexdigest())


def _oneline(value):
	# Values from the request go into log lines: no line breaks.
	return str(value).replace('\r', '').replace('\n', '')


def _client(request):
	# REMOTE_ADDR only: X-Forwarded-For can be set by anyone.
	return _oneline(request.META.get('REMOTE_ADDR', ''))


def _username(request):
	return _oneline(request.POST.get('username', '').strip().lower()[:150])


class ThrottledLoginView(LoginView):
	"""Django's LoginView with a failed-login limit and audit logging."""

	def _keys(self):
		return [_key('user', _username(self.request)), _key('addr', _client(self.request))]

	def post(self, request, *args, **kwargs):
		if MAX_FAILURES > 0 and any(cache.get(k, 0) >= MAX_FAILURES for k in self._keys()):
			# Refuse without checking the password, so a locked-out guesser
			# learns nothing.
			logger.warning('login refused (too many failures) user=%r addr=%s', _username(request), _client(request))
			# unbound form: validating the posted one would authenticate
			form = self.get_form_class()(request=request)
			context = self.get_context_data(form=form, locked=True)
			return self.render_to_response(context, status=429)
		return super().post(request, *args, **kwargs)

	def form_invalid(self, form):
		for k in self._keys():
			cache.add(k, 0, LOCKOUT)
			try:
				cache.incr(k)
			except ValueError:
				cache.set(k, 1, LOCKOUT)
		logger.warning('login failed user=%r addr=%s', _username(self.request), _client(self.request))
		return super().form_invalid(form)

	def form_valid(self, form):
		cache.delete_many(self._keys())
		logger.info('login succeeded user=%r addr=%s', _oneline(form.get_user().get_username()), _client(self.request))
		return super().form_valid(form)
