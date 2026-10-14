import html, json, re, base64, ipaddress, shlex, urllib.parse

def labelToMargin(label):
	labels = {
		'Vulnerable':'10px',
		'Critical':'22px',
		'Warning':'28px',
		'Checked':'28px'
	}

	return labels.get(label, '10px')

def labelToColor(label):
	labels = {
		'Vulnerable':'red',
		'Critical':'black',
		'Warning':'orange',
		'Checked':'blue'
	}

	return labels.get(label, 'grey')

def fromOSTypeToFontAwesome(ostype):
	icons = {
		'windows':'fab fa-windows',
		'solaris':'fab fa-linux',	# there isn't a better icon on fontawesome :(
		'unix':'fab fa-linux',		# same here...
		'linux':'fab fa-linux',
	}

	if ostype.lower() in icons:
		return str(icons[ostype.lower()])
	else:
		return 'fas fa-question'

def esc(value):
	# HTML-escape any value taken from Nmap XML, notes or CVE data before
	# it is concatenated into markup rendered with |safe.
	return html.escape(str(value))

def jsstr(value):
	# Quoted JS string literal that is safe inside an inline <script> block.
	return json.dumps(str(value)).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')

def safeurl(value):
	# Only http(s) links from external CVE data become clickable.
	value = str(value)
	if re.match(r'^https?://', value, re.IGNORECASE):
		return html.escape(value)
	return '#'

def safenotesb64(value):
	# Notes are stored as urlencoded base64; anything else is dropped so it
	# cannot break out of the JS string it is embedded in.
	if re.match(r'^[A-Za-z0-9%+/=]*$', value):
		return value
	return ''

def notestohtml(value):
	try:
		text = base64.b64decode(urllib.parse.unquote(safenotesb64(value))).decode('utf-8')
	except (ValueError, UnicodeDecodeError):
		return ''
	return html.escape(text).replace('\n', '<br>')

def urlhost(address):
	# Host part of a URL; IPv6 literals need brackets.
	if ':' in address:
		return '['+address+']'
	return address

def is_ip(address):
	try:
		ipaddress.ip_address(address)
		return True
	except ValueError:
		return False

def is_portid(value):
	return re.fullmatch(r'[0-9]{1,5}', str(value)) is not None and 0 < int(value) <= 65535

def shellcmd(*args):
	# Command line for the clipboard; each argument is shell-quoted. The result
	# still has to be HTML-escaped when it goes into an attribute.
	return ' '.join(shlex.quote(str(a)) for a in args)

def cvetohtml(cveobj, opendiv):
	cverefout = ''
	refs = cveobj.get('references', [])
	for cveref in (refs if isinstance(refs, list) else []):
		cverefout += '<a href="'+safeurl(cveref)+'">'+esc(cveref)+'</a><br>'

	cveexdbout = ''
	exdb = cveobj.get('exploit-db')
	if isinstance(exdb, list):
		cveexdbout = '<br><div class="small" style="line-height:20px;"><b>Exploit DB:</b><br>'
		for cveexdb in exdb:
			if isinstance(cveexdb, dict) and 'title' in cveexdb:
				cveexdbout += '<a href="'+safeurl(cveexdb.get('source', ''))+'">'+esc(cveexdb['title'])+'</a><br>'
		cveexdbout += '</div>'

	return opendiv+\
	'	<span class="label red">'+esc(cveobj.get('id', ''))+'</span> '+esc(cveobj.get('summary', ''))+'<br><br>'+\
	'	<div class="small" style="line-height:20px;"><b>References:</b><br>'+cverefout+'</div>'+\
	cveexdbout+\
	'</div>'
