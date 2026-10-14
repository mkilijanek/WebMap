import hashlib, os
from django.core.management.base import BaseCommand
from nmapreport.scan import NOTES_DIR, ScanError, list_scan_files, load_scan


class Command(BaseCommand):
	help = ('Attach labels, notes and CVE results saved by older WebMap versions '
		'(keyed by file name only) to the scan files currently in /opt/xml. '
		'Run once after upgrading, only if those files are still the scans '
		'the annotations were made on.')

	def add_arguments(self, parser):
		parser.add_argument('--dry-run', action='store_true')

	def handle(self, *args, **options):
		try:
			files = os.listdir(NOTES_DIR)
		except OSError:
			files = []

		moved = 0
		for name in list_scan_files():
			try:
				newkey = load_scan(name).key
			except ScanError as e:
				self.stderr.write('%s: skipped (%s)' % (name, e))
				continue

			oldkey = hashlib.md5(name.encode('utf-8'), usedforsecurity=False).hexdigest()
			for fn in files:
				if not fn.startswith(oldkey + '_'):
					continue
				dst = newkey + fn[len(oldkey):]
				if os.path.exists(os.path.join(NOTES_DIR, dst)):
					continue
				self.stdout.write('%s: %s -> %s' % (name, fn, dst))
				if not options['dry_run']:
					os.rename(os.path.join(NOTES_DIR, fn), os.path.join(NOTES_DIR, dst))
				moved += 1

		self.stdout.write('%d file(s) %s.' % (moved, 'would be moved' if options['dry_run'] else 'moved'))
