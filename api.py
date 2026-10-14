from django.http import HttpResponse
from django.core.exceptions import SuspiciousFileOperation, ValidationError
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.csp import csp_override
from django.views.decorators.http import require_GET, require_POST
import functools, json, logging, os, requests, subprocess, shutil, threading, urllib.parse
from . import scan as scandata
from .scan import ScanError, session_scan, find_host, unique_ports, md5, filter_cves, host_keys
from .pdf import render_report
from .security_utils import (
    safe_join, validate_md5_hash,
    validate_port_number, validate_cpe_string,
    validate_host_address, validate_label, validate_object_type,
    validate_notes_b64
)

logger = logging.getLogger('nmapreport')

WKHTMLTOPDF = os.environ.get('WKHTMLTOPDF_PATH') or shutil.which('wkhtmltopdf') or '/opt/wkhtmltox/bin/wkhtmltopdf'
PDF_TIMEOUT = 60
CVE_API = os.environ.get('WEBMAP_CVE_API', 'https://cve.circl.lu/api/cvefor/')

# One wkhtmltopdf at a time; further requests get 429 instead of queueing up
# on the server threads.
_pdf_lock = threading.Lock()

def jsonresponse(data, status=200):
	return HttpResponse(json.dumps(data), content_type="application/json", status=status)

def jsonerror(msg, status):
	return jsonresponse({'error': msg}, status)

def jsonapi(view):
	"""Map the expected failures of an API view to JSON errors with a 4xx
	status; anything else is logged and answered with a generic 500."""
	@functools.wraps(view)
	def wrapper(request, *args, **kwargs):
		try:
			return view(request, *args, **kwargs)
		except ValidationError as e:
			return jsonerror(' '.join(e.messages), 400)
		except ScanError:
			return jsonerror('scan file not readable', 400)
		except SuspiciousFileOperation:
			return jsonerror('invalid path', 400)
		except Exception:
			logger.exception('%s failed', view.__name__)
			return jsonerror('operation failed', 500)
	return wrapper

def current_scan(request):
	scan = session_scan(request)
	if scan is None:
		raise ValidationError('No scan file selected')
	return scan

def host_hash(scan, hashstr):
	# Annotations can only be stored for hosts of the selected scan, so the
	# API cannot be used to create an unbounded number of files.
	hashstr = validate_md5_hash(hashstr)
	if hashstr not in host_keys(scan):
		raise ValidationError('Host not found in the selected scan')
	return hashstr

def annotation_path(scan, name):
	return safe_join(scandata.NOTES_DIR, scan.key + '_' + name)

def remove_file(path, okmsg):
	try:
		os.remove(path)
	except FileNotFoundError:
		return jsonerror('file not found', 404)
	return jsonresponse({'ok': okmsg})

def write_file(path, content):
	# Write to a temporary file and rename it into place, so a reader never
	# sees a half-written annotation.
	tmp = path + '.tmp'
	with open(tmp, 'w', encoding='utf-8') as f:
		f.write(content)
	os.replace(tmp, path)

@csrf_protect
@require_POST
@jsonapi
def rmNotes(request, hashstr):
	scan = current_scan(request)
	hashstr = host_hash(scan, hashstr)
	return remove_file(annotation_path(scan, hashstr + '.notes'), 'notes removed')

@csrf_protect
@require_POST
@jsonapi
def saveNotes(request):
	scan = current_scan(request)
	hashstr = host_hash(scan, request.POST.get('hashstr', ''))
	# urlencoded base64 of UTF-8 text, max 10 KB
	notes = validate_notes_b64(request.POST.get('notes', ''))
	write_file(annotation_path(scan, hashstr + '.notes'), notes)
	return jsonresponse({'ok': 'notes saved'})

@csrf_protect
@require_POST
@jsonapi
def rmlabel(request, objtype, hashstr):
	objtype = validate_object_type(objtype)
	scan = current_scan(request)
	hashstr = host_hash(scan, hashstr)
	return remove_file(annotation_path(scan, hashstr + '.' + objtype + '.label'), 'label removed')

@csrf_protect
@require_POST
@jsonapi
def label(request, objtype, label, hashstr):
	label = validate_label(label)
	objtype = validate_object_type(objtype)
	scan = current_scan(request)
	hashstr = host_hash(scan, hashstr)
	write_file(annotation_path(scan, hashstr + '.' + objtype + '.label'), label)
	return jsonresponse({'ok': 'label set', 'label': label})

@require_GET
@jsonapi
def port_details(request, address, portid):
	address = validate_host_address(address)
	portid = str(validate_port_number(portid))
	scan = current_scan(request)

	host = find_host(scan, address)
	if host is not None:
		for p in unique_ports(host):
			if p['@portid'] == portid:
				return HttpResponse(json.dumps(p, indent=4), content_type="application/json")

	return jsonerror('not found', 404)

# The browser shows the PDF inline; a page CSP (object-src 'none') can stop
# its built-in viewer, and a PDF response has no HTML to protect.
@csp_override({})
@csrf_protect
@require_POST
def genPDF(request):
	try:
		scan = current_scan(request)
		report = render_report(scan)
	except ValidationError as e:
		return jsonerror(' '.join(e.messages), 400)
	except (ScanError, SuspiciousFileOperation):
		return jsonerror('scan file not readable', 400)

	if not _pdf_lock.acquire(blocking=False):
		return jsonerror('another PDF report is being generated, try again shortly', 429)

	try:
		# The HTML is rendered here and piped to wkhtmltopdf; the PDF comes
		# back on stdout. No HTTP callback into this server (no session id in
		# argv, no thread held waiting for another one), no JavaScript, no
		# file left in a web-served directory.
		cmd = [
			WKHTMLTOPDF,
			'--quiet',
			'--encoding', 'utf-8',
			'--disable-javascript',
			'--disable-local-file-access',
			'-', '-'
		]
		result = subprocess.run(
			cmd,
			shell=False,
			input=report.encode('utf-8'),
			timeout=PDF_TIMEOUT,
			capture_output=True
		)
	except subprocess.TimeoutExpired:
		logger.warning('wkhtmltopdf timed out after %ss', PDF_TIMEOUT)
		return jsonerror('PDF generation timeout', 504)
	except OSError:
		logger.exception('wkhtmltopdf could not be started')
		return jsonerror('PDF generation failed', 500)
	finally:
		_pdf_lock.release()

	# wkhtmltopdf can exit non-zero on warnings while still producing a PDF
	if not result.stdout.startswith(b'%PDF'):
		logger.error('wkhtmltopdf exited %s without a PDF: %s', result.returncode, result.stderr[-2000:].decode('utf-8', 'replace'))
		return jsonerror('PDF generation failed', 500)

	response = HttpResponse(result.stdout, content_type='application/pdf')
	response['Content-Disposition'] = 'inline; filename="'+scan.name[:-4]+'.pdf"'
	response['Cache-Control'] = 'no-store'
	return response

@csrf_protect
@require_POST
@jsonapi
def getCVE(request):
	scan = current_scan(request)

	host = validate_host_address(request.POST.get('host', ''))
	port = str(validate_port_number(request.POST.get('port', '')))
	cpe = validate_cpe_string(request.POST.get('cpe', ''))

	# Only look up CPEs that the selected scan reports for this host/port
	hostobj = find_host(scan, host)
	if hostobj is None or not any(p['@portid'] == port and cpe in p['service']['cpe'] for p in unique_ports(hostobj)):
		raise ValidationError('CPE not found for this host and port in the selected scan')

	try:
		r = requests.get(
			CVE_API + urllib.parse.quote(cpe, safe=':/'),
			timeout=10,
			headers={'User-Agent': 'WebMap/1.0'},
			allow_redirects=False
		)
		r.raise_for_status()
		cvejson = r.json()
	except (requests.RequestException, ValueError) as e:
		logger.warning('CVE lookup for %s failed: %s', cpe, e)
		return jsonerror('Failed to fetch CVE data from external API', 502)

	if not isinstance(cvejson, list):
		logger.warning('CVE lookup for %s: unexpected response type %s', cpe, type(cvejson).__name__)
		return jsonerror('Unexpected CVE API response', 502)

	# Keep only well-formed entries (dicts with a string id)
	cves = filter_cves(cvejson)

	# One file per CPE, so several CPEs on one port do not overwrite
	# each other's results.
	write_file(annotation_path(scan, md5(host) + '.' + port + '.' + md5(cpe) + '.cve'), json.dumps(cves))

	if len(cves) > 0:
		return jsonresponse({host: {port: {'id': cves[0]['id']}}})
	return jsonresponse({'info': 'No CVE data found'})
