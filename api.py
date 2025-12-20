from django.shortcuts import render
from django.http import HttpResponse
from django.core.exceptions import SuspiciousFileOperation, ValidationError
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
import xmltodict, json, html, os, hashlib, re, requests, subprocess
from collections import OrderedDict
from security_utils import (
    safe_join, validate_filename, validate_md5_hash,
    validate_port_number, validate_cpe_string
)

def rmNotes(request, hashstr):
	try:
		# Validate inputs
		scanfile = validate_filename(request.session.get('scanfile', ''))
		scanfilemd5 = hashlib.md5(scanfile.encode('utf-8')).hexdigest()
		hashstr = validate_md5_hash(hashstr)

		# Safe file path construction
		notes_dir = '/opt/notes'
		filename = f'{scanfilemd5}_{hashstr}.notes'
		filepath = safe_join(notes_dir, filename)

		# Check file exists before removing
		if os.path.exists(filepath):
			os.remove(filepath)
			res = {'ok': 'notes removed'}
		else:
			res = {'error': 'file not found'}

	except (ValidationError, SuspiciousFileOperation) as e:
		res = {'error': str(e)}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

@csrf_protect
@require_http_methods(['POST'])
def saveNotes(request):
	try:
		# Validate inputs
		scanfile = validate_filename(request.session.get('scanfile', ''))
		scanfilemd5 = hashlib.md5(scanfile.encode('utf-8')).hexdigest()
		hashstr = validate_md5_hash(request.POST.get('hashstr', ''))

		# Validate notes content (max 10KB)
		notes_content = request.POST.get('notes', '')
		if len(notes_content) > 10240:
			raise ValidationError('Notes content too large (max 10KB)')

		# Safe file path construction
		notes_dir = '/opt/notes'
		filename = f'{scanfilemd5}_{hashstr}.notes'
		filepath = safe_join(notes_dir, filename)

		# Write notes securely
		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(notes_content)

		res = {'ok': 'notes saved'}

	except (ValidationError, SuspiciousFileOperation) as e:
		res = {'error': str(e)}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

def rmlabel(request, objtype, hashstr):
	try:
		# Validate inputs
		from security_utils import validate_object_type
		objtype = validate_object_type(objtype)
		scanfile = validate_filename(request.session.get('scanfile', ''))
		scanfilemd5 = hashlib.md5(scanfile.encode('utf-8')).hexdigest()
		hashstr = validate_md5_hash(hashstr)

		# Safe file path construction
		notes_dir = '/opt/notes'
		filename = f'{scanfilemd5}_{hashstr}.{objtype}.label'
		filepath = safe_join(notes_dir, filename)

		# Check file exists before removing
		if os.path.exists(filepath):
			os.remove(filepath)
			res = {'ok': 'label removed'}
		else:
			res = {'error': 'file not found'}

	except (ValidationError, SuspiciousFileOperation) as e:
		res = {'error': str(e)}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

def label(request, objtype, label, hashstr):
	try:
		# Validate inputs
		from security_utils import validate_label, validate_object_type
		label = validate_label(label)
		objtype = validate_object_type(objtype)
		scanfile = validate_filename(request.session.get('scanfile', ''))
		scanfilemd5 = hashlib.md5(scanfile.encode('utf-8')).hexdigest()
		hashstr = validate_md5_hash(hashstr)

		# Safe file path construction
		notes_dir = '/opt/notes'
		filename = f'{scanfilemd5}_{hashstr}.{objtype}.label'
		filepath = safe_join(notes_dir, filename)

		# Write label securely
		with open(filepath, 'w', encoding='utf-8') as f:
			f.write(label)

		res = {'ok': 'label set', 'label': label}

	except (ValidationError, SuspiciousFileOperation) as e:
		res = {'error': str(e)}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

def port_details(request, address, portid):
	try:
		# Validate inputs
		from security_utils import validate_ip_address
		address = validate_ip_address(address)
		portid = str(validate_port_number(portid))
		scanfile = validate_filename(request.session.get('scanfile', ''))

		# Safe file path construction
		xml_dir = '/opt/xml'
		filepath = safe_join(xml_dir, scanfile)

		# Parse XML securely (XXE protection via xmltodict defaults)
		with open(filepath, 'r', encoding='utf-8') as f:
			xml_content = f.read()

		oo = xmltodict.parse(xml_content, disable_entities=True)
		o = oo['nmaprun']
	except (ValidationError, SuspiciousFileOperation) as e:
		return HttpResponse(json.dumps({'error': str(e)}), content_type="application/json", status=400)
	except Exception as e:
		return HttpResponse(json.dumps({'error': 'operation failed'}), content_type="application/json", status=500)

	r = {}
	r['out'] = json.dumps(o, indent=4)

	for ik in o['host']:

		# this fix single host report
		if type(ik) is dict:
			i = ik
		else:
			i = o['host']

		if '@addr' in i['address']:
			saddress = i['address']['@addr']
		elif type(i['address']) is list:
			for ai in i['address']:
				if ai['@addrtype'] == 'ipv4':
					saddress = ai['@addr'] 

		if str(saddress) == address:
			for pobj in i['ports']['port']:
				if type(pobj) is dict:
					p = pobj
				else:
					p = i['ports']['port']

				if p['@portid'] == portid:
					return HttpResponse(json.dumps(p, indent=4), content_type="application/json")

def genPDF(request):
	try:
		if 'scanfile' not in request.session:
			raise ValidationError('No scan file selected')

		# Validate scanfile
		scanfile = validate_filename(request.session['scanfile'])
		pdffile = hashlib.md5(scanfile.encode('utf-8')).hexdigest()

		# Safe PDF path construction
		static_dir = '/opt/nmapdashboard/nmapreport/static'
		pdf_filename = f'{pdffile}.pdf'
		pdf_path = safe_join(static_dir, pdf_filename)

		# Remove existing PDF if present
		if os.path.exists(pdf_path):
			os.remove(pdf_path)

		# CRITICAL FIX: Use subprocess instead of os.popen to prevent command injection
		# Build command as list to avoid shell interpretation
		cmd = [
			'/opt/wkhtmltox/bin/wkhtmltopdf',
			'--cookie', 'sessionid', request.session._session_key,
			'--enable-javascript',
			'--javascript-delay', '6000',
			'http://127.0.0.1:8000/view/pdf/',
			pdf_path
		]

		# Execute command safely without shell
		result = subprocess.run(
			cmd,
			shell=False,  # Critical: Never use shell=True with user input
			check=True,
			timeout=30,  # Prevent indefinite execution
			capture_output=True,
			text=True
		)

		res = {'ok': 'PDF created', 'file': f'/static/{pdf_filename}'}

	except ValidationError as e:
		res = {'error': str(e)}
	except subprocess.TimeoutExpired:
		res = {'error': 'PDF generation timeout'}
	except subprocess.CalledProcessError as e:
		res = {'error': 'PDF generation failed'}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")

@csrf_protect
@require_http_methods(['POST'])
def getCVE(request):
	try:
		# Validate inputs
		from security_utils import validate_ip_address
		scanfile = validate_filename(request.session.get('scanfile', ''))
		scanfilemd5 = hashlib.md5(scanfile.encode('utf-8')).hexdigest()

		host = validate_ip_address(request.POST.get('host', ''))
		hostmd5 = hashlib.md5(host.encode('utf-8')).hexdigest()

		port = str(validate_port_number(request.POST.get('port', '')))
		cpe = validate_cpe_string(request.POST.get('cpe', ''))

		# Make external API call with timeout and error handling
		try:
			r = requests.get(
				f'http://cve.circl.lu/api/cvefor/{cpe}',
				timeout=10,  # 10 second timeout
				headers={'User-Agent': 'WebMap/1.0'}
			)
			r.raise_for_status()
			cvejson = r.json()
		except requests.RequestException as e:
			raise ValidationError('Failed to fetch CVE data from external API')

		res = {}
		if isinstance(cvejson, list) and len(cvejson) > 0:
			res[host] = {port: cvejson[0]}

			# Safe file path construction
			notes_dir = '/opt/notes'
			filename = f'{scanfilemd5}_{hostmd5}.{port}.cve'
			filepath = safe_join(notes_dir, filename)

			# Write CVE data
			with open(filepath, 'w', encoding='utf-8') as f:
				f.write(json.dumps(cvejson))
		else:
			res = {'info': 'No CVE data found'}

	except (ValidationError, SuspiciousFileOperation) as e:
		res = {'error': str(e)}
	except Exception as e:
		res = {'error': 'operation failed'}

	return HttpResponse(json.dumps(res), content_type="application/json")
