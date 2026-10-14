import html, json, re, base64, urllib.parse

def labelToMargin(label):
	labels = {
		'Vulnerable':'10px',
		'Critical':'22px',
		'Warning':'28px',
		'Checked':'28px'
	}

	if label in labels:
		return labels[label]

def labelToColor(label):
	labels = {
		'Vulnerable':'red',
		'Critical':'black',
		'Warning':'orange',
		'Checked':'blue'
	}

	if label in labels:
		return labels[label]

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
