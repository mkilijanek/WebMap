import os
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
	help = 'Create or update the WebMap login user from WEBMAP_USER and WEBMAP_PASSWORD (or WEBMAP_PASSWORD_FILE).'

	def handle(self, *args, **options):
		username = os.environ.get('WEBMAP_USER', 'webmap')
		password = os.environ.get('WEBMAP_PASSWORD', '')
		pwfile = os.environ.get('WEBMAP_PASSWORD_FILE', '')
		if pwfile:
			with open(pwfile, 'r', encoding='utf-8') as f:
				password = f.read().rstrip('\n')
		if not password:
			raise CommandError('WEBMAP_PASSWORD or WEBMAP_PASSWORD_FILE is not set')

		User = get_user_model()
		user = User.objects.filter(username=username).first() or User(username=username)
		try:
			validate_password(password, user)
		except ValidationError as e:
			raise CommandError('WEBMAP_PASSWORD rejected: ' + ' '.join(e.messages))

		user.is_active = True
		user.set_password(password)
		user.save()
		self.stdout.write('WebMap user "%s" is ready.' % username)
