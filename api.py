from django.http import HttpResponse
from django.core.exceptions import SuspiciousFileOperation, ValidationError
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
import json, os, requests, subprocess, shutil, threading, urllib.parse
from .scan import ScanError, session_scan, find_host, unique_ports, md5, filter_cves, NOTES_DIR
from .pdf import render_report
from .security_utils import (
    safe_join, validate_md5_hash,
    validate_port_number, validate_cpe_string,
    validate_host_address, validate_label, validate_object_type,
    validate_notes_b64
)

WKHTMLTOPDF = os.environ.get('WKHTMLTOPDF_PATH') or shutil.which('wkhtmltopdf') or '/opt/wkhtmltox/bin/wkhtmltopdf'
PDF_TIMEOUT = 60

# One wkhtmltopdf at a time; further requests get 429 instead of queueing up
# on the server threads.
_pdf_lock = threading.Lock()

def scan_key(request):
	# Annotation files are prefixed with the scan key (file name + content
	# hash), so they belong to this exact scan and not to any later file
	# saved under the same name.
	scan = session_scan(request)
	if scan is None:
		raise ValidationError('No scan file selected')
	return scan.key

@csrf_protect
@require_http_methods(['POST'])
def rmNotes(request, hashstr):
	try:
		# Validate inputs
		scankey = scan_key(request)
		hashstr = validate_md5_hash(hashstr)

		# Safe file path construction
		notes_dir = NOTES_DIR
		filename = f'{scankey}_{hashstr}.notes'
		filepath = safe_join(notes_dir, filename)

		# Check file exists before removing
		if os.path.exists(filepath):
			os.remove(filepath)
			res = {'ok': 'notes removed'}
		else:
			res = {'error': 'file not found'}

	except ValidationError as e:
		res = {'error': ' '.join(e.messages)}
	except ScanError as e:
		res = {'error': str(e)}
	except SuspiciousFileOperation:
		res = {'error': 'invalid path'}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

@csrf_protect
@require_http_methods(['POST'])
def saveNotes(request):
	try:
		# Validate inputs
		scankey = scan_key(request)
		hashstr = validate_md5_hash(request.POST.get('hashstr', ''))

		# Validate notes content (max 10KB)
		notes_content = validate_notes_b64(request.POST.get('notes', ''))

		# Safe file path construction
		notes_dir = NOTES_DIR
		filename = f'{scankey}_{hashstr}.notes'
		filepath = safe_join(notes_dir, filename)

		# Write notes securely
		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(notes_content)

		res = {'ok': 'notes saved'}

	except ValidationError as e:
		res = {'error': ' '.join(e.messages)}
	except ScanError as e:
		res = {'error': str(e)}
	except SuspiciousFileOperation:
		res = {'error': 'invalid path'}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

@csrf_protect
@require_http_methods(['POST'])
def rmlabel(request, objtype, hashstr):
	try:
		# Validate inputs
		objtype = validate_object_type(objtype)
		scankey = scan_key(request)
		hashstr = validate_md5_hash(hashstr)

		# Safe file path construction
		notes_dir = NOTES_DIR
		filename = f'{scankey}_{hashstr}.{objtype}.label'
		filepath = safe_join(notes_dir, filename)

		# Check file exists before removing
		if os.path.exists(filepath):
			os.remove(filepath)
			res = {'ok': 'label removed'}
		else:
			res = {'error': 'file not found'}

	except ValidationError as e:
		res = {'error': ' '.join(e.messages)}
	except ScanError as e:
		res = {'error': str(e)}
	except SuspiciousFileOperation:
		res = {'error': 'invalid path'}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

@csrf_protect
@require_http_methods(['POST'])
def label(request, objtype, label, hashstr):
	try:
		# Validate inputs
		label = validate_label(label)
		objtype = validate_object_type(objtype)
		scankey = scan_key(request)
		hashstr = validate_md5_hash(hashstr)

		# Safe file path construction
		notes_dir = NOTES_DIR
		filename = f'{scankey}_{hashstr}.{objtype}.label'
		filepath = safe_join(notes_dir, filename)

		# Write label securely
		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(label)

		res = {'ok': 'label set', 'label': label}

	except ValidationError as e:
		res = {'error': ' '.join(e.messages)}
	except ScanError as e:
		res = {'error': str(e)}
	except SuspiciousFileOperation:
		res = {'error': 'invalid path'}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

def port_details(request, address, portid):
	try:
		# Validate inputs
		address = validate_host_address(address)
		portid = str(validate_port_number(portid))
		scan = session_scan(request)
		if scan is None:
			raise ValidationError('No scan file selected')
	except ValidationError as e:
		return HttpResponse(json.dumps({'error': ' '.join(e.messages)}), content_type="application/json", status=400)
	except ScanError as e:
		return HttpResponse(json.dumps({'error': str(e)}), content_type="application/json", status=400)
	except SuspiciousFileOperation:
		return HttpResponse(json.dumps({'error': 'invalid path'}), content_type="application/json", status=400)

	host = find_host(scan, address)
	if host is not None:
		for p in unique_ports(host):
			if p['@portid'] == portid:
				return HttpResponse(json.dumps(p, indent=4), content_type="application/json")

	return HttpResponse(json.dumps({'error': 'not found'}), content_type="application/json", status=404)

def jsonerror(msg, status):
	return HttpResponse(json.dumps({'error': msg}), content_type="application/json", status=status)

@csrf_protect
@require_http_methods(['POST'])
def genPDF(request):
	try:
		scan = session_scan(request)
		if scan is None:
			raise ValidationError('No scan file selected')
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
		return jsonerror('PDF generation timeout', 504)
	except OSError:
		return jsonerror('PDF generation failed', 500)
	finally:
		_pdf_lock.release()

	# wkhtmltopdf can exit non-zero on warnings while still producing a PDF
	if not result.stdout.startswith(b'%PDF'):
		return jsonerror('PDF generation failed', 500)

	response = HttpResponse(result.stdout, content_type='application/pdf')
	response['Content-Disposition'] = 'inline; filename="'+scan.name[:-4]+'.pdf"'
	response['Cache-Control'] = 'no-store'
	return response

@csrf_protect
@require_http_methods(['POST'])
def getCVE(request):
	try:
		# Validate inputs
		scan = session_scan(request)
		if scan is None:
			raise ValidationError('No scan file selected')

		host = validate_host_address(request.POST.get('host', ''))
		hostmd5 = md5(host)

		port = str(validate_port_number(request.POST.get('port', '')))
		cpe = validate_cpe_string(request.POST.get('cpe', ''))

		# Only look up CPEs that the selected scan reports for this host/port
		hostobj = find_host(scan, host)
		if hostobj is None or not any(p['@portid'] == port and cpe in p['service']['cpe'] for p in unique_ports(hostobj)):
			raise ValidationError('CPE not found for this host and port in the selected scan')

		# Make external API call with timeout and error handling
		try:
			r = requests.get(
				'https://cve.circl.lu/api/cvefor/' + urllib.parse.quote(cpe, safe=':/'),
				timeout=10,  # 10 second timeout
				headers={'User-Agent': 'WebMap/1.0'},
				allow_redirects=False
			)
			r.raise_for_status()
			cvejson = r.json()
		except (requests.RequestException, ValueError) as e:
			raise ValidationError('Failed to fetch CVE data from external API')

		if not isinstance(cvejson, list):
			raise ValidationError('Unexpected CVE API response')

		# Keep only well-formed entries (dicts with a string id)
		cves = filter_cves(cvejson)

		# One file per CPE, so several CPEs on one port do not overwrite
		# each other's results.
		filename = f'{scan.key}_{hostmd5}.{port}.{md5(cpe)}.cve'
		filepath = safe_join(NOTES_DIR, filename)

		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(json.dumps(cves))

		if len(cves) > 0:
			res = {host: {port: {'id': cves[0]['id']}}}
		else:
			res = {'info': 'No CVE data found'}

	except ValidationError as e:
		res = {'error': ' '.join(e.messages)}
	except ScanError as e:
		res = {'error': str(e)}
	except SuspiciousFileOperation:
		res = {'error': 'invalid path'}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")
