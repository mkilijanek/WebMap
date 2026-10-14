import hashlib, json, os, re, threading
import xmltodict
from xml.parsers.expat import ExpatError
from django.core.exceptions import ValidationError
from .security_utils import safe_join, validate_filename, validate_host_address

XML_DIR = '/opt/xml'
NOTES_DIR = '/opt/notes'
MAX_XML_BYTES = int(os.environ.get('WEBMAP_MAX_XML_MB', '100')) * 1024 * 1024

# Elements that nmap may emit once or many times. Forcing them to lists means
# callers never have to guess whether they got a dict or a list.
FORCE_LIST = ('host', 'port', 'scaninfo', 'address', 'hostname', 'script', 'cpe')


class ScanError(Exception):
	pass


class Scan:
	def __init__(self, name, data, key):
		self.name = name
		# nmaprun element
		self.data = data
		# md5 of file name + content hash; prefixes annotation files so labels,
		# notes and CVE results do not carry over to a different scan that
		# reuses the same file name.
		self.key = key

	@property
	def hosts(self):
		return self.data.get('host') or []


_cache = {}
_cache_lock = threading.Lock()


def _normalize(nmaprun):
	if not isinstance(nmaprun, dict):
		raise ScanError('not an nmap XML file')

	for k in ('@startstr', '@args', '@version', '@xmloutputversion', '@start'):
		nmaprun.setdefault(k, '')
	nmaprun['scaninfo'] = [s for s in (nmaprun.get('scaninfo') or []) if isinstance(s, dict)]
	nmaprun['host'] = [h for h in (nmaprun.get('host') or []) if isinstance(h, dict)]

	for h in nmaprun['host']:
		if not isinstance(h.get('status'), dict):
			h['status'] = {}
		for k in ('@state', '@reason', '@reason_ttl'):
			h['status'].setdefault(k, '')

		h['address'] = [a for a in (h.get('address') or []) if isinstance(a, dict)]

		hn = h.get('hostnames')
		h['hostnames'] = [x for x in (hn.get('hostname') or []) if isinstance(x, dict)] if isinstance(hn, dict) else []

		ports = h.get('ports')
		plist = [p for p in (ports.get('port') or []) if isinstance(p, dict)] if isinstance(ports, dict) else []
		h['ports'] = plist
		for p in plist:
			p.setdefault('@protocol', '')
			p.setdefault('@portid', '')
			if not isinstance(p.get('state'), dict):
				p['state'] = {}
			p['state'].setdefault('@state', '')
			p['state'].setdefault('@reason', '')
			if not isinstance(p.get('service'), dict):
				p['service'] = {}
			p['service'].setdefault('@name', '')
			p['service']['cpe'] = [c for c in (p['service'].get('cpe') or []) if isinstance(c, str)]
			p['script'] = [s for s in (p.get('script') or []) if isinstance(s, dict)]
			for s in p['script']:
				s.setdefault('@id', '')
				s['@output'] = s.get('@output') or ''

	return nmaprun


def load_scan(filename):
	"""Parse /opt/xml/<filename>; raises ScanError, ValidationError or
	SuspiciousFileOperation. Results are cached by (mtime, size)."""
	filename = validate_filename(filename)
	path = safe_join(XML_DIR, filename)

	try:
		st = os.stat(path)
	except OSError:
		raise ScanError('scan file not found')

	if st.st_size > MAX_XML_BYTES:
		raise ScanError('scan file too large')

	stamp = (st.st_mtime_ns, st.st_size, st.st_ino)
	with _cache_lock:
		hit = _cache.get(path)
	if hit is not None and hit[0] == stamp:
		return hit[1]

	try:
		with open(path, 'rb') as f:
			raw = f.read(MAX_XML_BYTES + 1)
	except OSError:
		raise ScanError('scan file not readable')

	if len(raw) > MAX_XML_BYTES:
		raise ScanError('scan file too large')

	try:
		parsed = xmltodict.parse(raw, disable_entities=True, force_list=FORCE_LIST)
	except (ExpatError, ValueError):
		raise ScanError('scan file is not valid XML (incomplete scan?)')

	if not isinstance(parsed, dict) or not isinstance(parsed.get('nmaprun'), dict):
		raise ScanError('not an nmap XML file')

	key = hashlib.md5((filename + '\0' + hashlib.sha256(raw).hexdigest()).encode('utf-8'), usedforsecurity=False).hexdigest()
	scan = Scan(filename, _normalize(parsed['nmaprun']), key)

	with _cache_lock:
		_cache[path] = (stamp, scan)
	return scan


def session_scan(request):
	"""Scan selected in the session, or None if none is selected."""
	if 'scanfile' not in request.session:
		return None
	return load_scan(request.session['scanfile'])


def list_scan_files():
	try:
		names = os.listdir(XML_DIR)
	except OSError:
		return []
	out = []
	for n in sorted(names):
		if not n.endswith('.xml'):
			continue
		try:
			validate_filename(n)
		except ValidationError:
			continue
		out.append(n)
	return out


def host_address(host):
	"""ipv4, then ipv6, then mac; None when the host has no usable address.
	Values that are not a valid address are ignored, so callers can put the
	result into URLs and markup."""
	addrs = host.get('address') or []
	for t in ('ipv4', 'ipv6', 'mac'):
		for a in addrs:
			if a.get('@addrtype') == t and a.get('@addr'):
				try:
					return validate_host_address(str(a['@addr']))
				except ValidationError:
					pass
	return None


def scaninfo_field(nmaprun, field):
	return ', '.join(str(s.get(field, '')) for s in nmaprun.get('scaninfo', []))


def unique_ports(host):
	seen = set()
	for p in host.get('ports', []):
		k = (p['@protocol'], p['@portid'])
		if k in seen:
			continue
		seen.add(k)
		yield p


def find_host(scan, address):
	for h in scan.hosts:
		if host_address(h) == address:
			return h
	return None


def md5(value):
	return hashlib.md5(str(value).encode('utf-8'), usedforsecurity=False).hexdigest()


def filter_cves(data):
	"""Only a list of dicts with a string id is accepted; anything else is
	dropped instead of breaking page rendering later."""
	if not isinstance(data, list):
		return []
	return [c for c in data if isinstance(c, dict) and isinstance(c.get('id'), str)]


def parse_cve_json(text):
	try:
		return filter_cves(json.loads(text))
	except (ValueError, TypeError):
		return []


def read_annotations(scankey):
	"""Return (labels, notes, cves) for a scan, keyed by md5(address).
	cves maps md5(address) to a list of CVE dicts."""
	labels, notes, cves = {}, {}, {}
	try:
		files = sorted(os.listdir(NOTES_DIR))
	except OSError:
		return labels, notes, cves

	label_re = re.compile('^' + scankey + r'_([a-f0-9]{32})\.host\.label$')
	notes_re = re.compile('^' + scankey + r'_([a-f0-9]{32})\.notes$')
	# <host>.<port>.<md5(cpe)>.cve; files without the CPE part come from
	# older versions (one file per port)
	cve_re = re.compile('^' + scankey + r'_([a-f0-9]{32})\.([0-9]+)(\.[a-f0-9]{32})?\.cve$')

	for fn in files:
		m = label_re.match(fn) or notes_re.match(fn) or cve_re.match(fn)
		if m is None:
			continue
		try:
			with open(os.path.join(NOTES_DIR, fn), 'r', encoding='utf-8') as f:
				content = f.read()
		except (OSError, UnicodeDecodeError):
			continue
		if m.re is label_re:
			labels[m.group(1)] = content
		elif m.re is notes_re:
			notes[m.group(1)] = content
		else:
			cves.setdefault(m.group(1), []).extend(parse_cve_json(content))

	# the same CVE can be returned for several CPEs of one host
	for h in cves:
		seen, uniq = set(), []
		for c in cves[h]:
			if c['id'] not in seen:
				seen.add(c['id'])
				uniq.append(c)
		cves[h] = uniq

	return labels, notes, cves
