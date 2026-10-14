from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe
import base64, html, os
from nmapreport.functions import *
from nmapreport.scan import session_scan, read_annotations, host_address, scaninfo_field, unique_ports, md5

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')

_assets = {}

def _asset(name, binary=False):
	# The report is rendered from a string (stdin of wkhtmltopdf), so CSS and
	# images are inlined instead of being fetched from this server or a CDN.
	if name not in _assets:
		with open(os.path.join(STATIC_DIR, name), 'rb') as f:
			data = f.read()
		_assets[name] = base64.b64encode(data).decode() if binary else data.decode('utf-8')
	return _assets[name]

def bars(title, items):
	# Server-side replacement for the Google Charts pies; no JavaScript needed.
	total = sum(c for _, c in items) or 1
	out = '<div class="chart"><b>'+esc(title)+'</b><table class="bars">'
	for label, count in items:
		out += '<tr><td class="barlabel">'+esc(label)+'</td>'+\
		'<td class="barcell"><div class="bar" style="width:'+str(round(count * 100 / total, 1))+'%;"></div></td>'+\
		'<td class="barcount">'+str(count)+'</td></tr>'
	return out + '</table></div>'

def render_report(scan):
	r = { 'out':'' }
	filterscriptid = {
	}
	o = scan.data

	r['html'] = ''
	hostdetails = ''
	counters = {'po':0,'pc':0,'pf':0,'hostsup':0,'ostype':{},'pi':{},'ss':{}}

	labelhost, noteshost, cvehost = read_annotations(scan.key)

	for i in scan.hosts:
		saddress = host_address(i)
		if saddress is None:
			continue

		hostcounters = {'po':0,'pc':0,'pf':0,'ostype':{},'pi':{},'ss':{}}
		hostdetails_html = ''
		portsfound = False

		addressmd5 = md5(saddress)

		if i['status']['@state'] == 'up':
			labelout = ''
			if addressmd5 in labelhost:
				labelcolor = labelToColor(labelhost[addressmd5])
				labelout = '<span style="" class="label '+labelcolor+'">'+html.escape(labelhost[addressmd5])+'</span>'

			hostdetails_html += '<div style="page-break-before: always;">'
			hostdetails_html += '	<h2>'+html.escape(saddress)+' '+labelout+'</h2> '

			hostdetails_html += '	<span class="subtitle">Status: '+html.escape(i['status']['@state'])+', '
			hostdetails_html += 'Reason: '+html.escape(i['status']['@reason'])+', '
			hostdetails_html += 'TTL: '+html.escape(i['status']['@reason_ttl'])+'</span>'

			counters['hostsup'] = (counters['hostsup'] + 1)

		hostdetails_html_tr = ''
		portdetails_html_tr = ''
		for p in unique_ports(i):
			if p['state']['@state'] == 'closed':
				counters['pc'] = (counters['pc'] + 1)
				hostcounters['pc'] = (hostcounters['pc'] + 1)
			elif p['state']['@state'] == 'open':
				counters['po'] = (counters['po'] + 1)
				hostcounters['po'] = (hostcounters['po'] + 1)
			elif p['state']['@state'] == 'filtered':
				counters['pf'] = (counters['pf'] + 1)
				hostcounters['pf'] = (hostcounters['pf'] + 1)

			if '@ostype' in p['service']:
				counters['ostype'][p['service']['@ostype']] = counters['ostype'].get(p['service']['@ostype'], 0) + 1

			counters['ss'][p['service']['@name']] = counters['ss'].get(p['service']['@name'], 0) + 1
			counters['pi'][p['@portid']] = counters['pi'].get(p['@portid'], 0) + 1

			hdhtml_product = ''
			if '@product' in p['service']:
				hdhtml_product = html.escape(p['service']['@product'])
			else:
				hdhtml_product = '<i class="grey-text">No Product</i>'

			hdhtml_version = ''
			if '@version' in p['service']:
				hdhtml_version = html.escape(p['service']['@version'])
			else:
				hdhtml_version = '<i class="grey-text">No Version</i>'

			hdhtml_protocolor = 'grey'
			if p['@protocol'] == 'tcp':
				hdhtml_protocolor = 'blue'
			elif p['@protocol'] == 'udp':
				hdhtml_protocolor = 'red'

			hostdetails_html_tr += '<tr>'+\
			'	<td><span class="'+hdhtml_protocolor+'-text">'+esc(p['@protocol'])+'</span> / <span class=""><b>'+esc(p['@portid'])+'</b></span><br><span class="small">'+esc(p['service']['@name'])+'</span></td>'+\
			'	<td>'+esc(p['state']['@state'])+'</td>'+\
			'	<td>'+hdhtml_product+' / '+hdhtml_version+'</td>'+\
			'</tr>'

			lastscript = ''
			for script in p['script']:
				if lastscript != script['@id']:
					lastscript = script['@id']
				else:
					continue

				if script['@output'].replace('\n','') != '' and script['@id'] not in filterscriptid:
					portdetails_html_tr += '<div class="extratitle"><b class="red-text">'+html.escape(script['@id'])+'</b> - Address: <b>'+html.escape(saddress)+'</b> - Port: <b>'+esc(p['@portid'])+'</b></div>'+\
					'<div class="extrainfo">'+html.escape(script['@output']).replace('\n','<br>')+'</div>'

			portsfound = True

		notesout = ''
		if addressmd5 in noteshost:
			notesout = '<div style="page-break-before: always;">'+\
			'	<h3>Notes for host '+esc(saddress)+'</h3>'+\
			'	'+notestohtml(noteshost[addressmd5])+\
			'</div>'

		cveout,cveout_html = '',''
		if addressmd5 in cvehost:
			for cveobj in cvehost[addressmd5]:
				cveout += cvetohtml(cveobj, '<div style="line-height:28px;padding:10px;margin-top:10px;border-bottom:solid #ccc 1px;">')

			cveout_html = '<div style="page-break-before: always;">'+\
			'	<h3>CVE List for '+esc(saddress)+':</h3>'+\
			cveout+\
			'</div>'

		if i['status']['@state'] == 'up':
			hostdetails_html += '<div class="row margintb">'+\
			'		<div class="col s3"><center><h3>'+str(hostcounters['po']+hostcounters['pc']+hostcounters['pf'])+'</h3>TOTAL PORT</center></div>'+\
			'		<div class="col s3 bleft"><center><h3 class="green-text">'+str(hostcounters['po'])+'</h3>OPEN PORT</center></div>'+\
			'		<div class="col s3 bleft"><center><h3 class="red-text">'+str(hostcounters['pc'])+'</h3>CLOSED PORT</center></div>'+\
			'		<div class="col s3 bleft"><center><h3 class="grey-text">'+str(hostcounters['pf'])+'</h3>FILTERED PORT</center></div>'+\
			'	</div>'+\
			'	<table><thead><tr><th>Protocol / Port</th><th>Port State</th><th>Product / Version</th></tr></thead><tbody>'+\
			hostdetails_html_tr+\
			'</tbody></table></div>'+\
			'<div style="page-break-before: always;"><h3>NSE Scripts for '+esc(saddress)+':</h3>'+portdetails_html_tr+'</div>'+\
			notesout+\
			cveout_html

		if portsfound is True:
			hostdetails += hostdetails_html

	html_ports = ''
	for ii in counters['pi']:
		html_ports += '<b>'+esc(ii)+'</b> <span class="grey-text">('+str(counters['pi'][ii])+')</span>, '

	html_services = ''
	for ii in counters['ss']:
		html_services += '<b>'+esc(ii)+'</b> <span class="grey-text">('+str(counters['ss'][ii])+')</span>, '

	top_ports = sorted(counters['pi'].items(), key=lambda x: x[1], reverse=True)[:20]
	top_services = sorted(counters['ss'].items(), key=lambda x: x[1], reverse=True)[:20]

	logo = '<img src="data:image/png;base64,'+_asset('logoblack.png', binary=True)+'" style="height:60px;" />'

	r['html'] += '<div class="container"><div style="text-align:center;width:100%;">'+\
	'	'+logo+\
	'	<h1 style="margin-top:300px;">Port Scan Report</h1>'+\
	'	<span class="subtitle">'+html.escape(scan.name.replace('.xml','').replace('_',' '))+'</span><br>'+\
	'	<div style="margin-top:200px;font-size:18px;padding:20px;"><table class="striped">'+\
	'	<thead>'+\
	'		<tr><th style="min-width:200px;">&nbsp;</th><th></th></tr>'+\
	'	</thead>'+\
	'	<tbody>'+\
	'		<tr><td><b>Arguments:</b></td><td>'+html.escape(o['@args'])+'</td></tr>'+\
	'		<tr><td><b>Scan started at:</b></td><td>'+html.escape(o['@startstr'])+'</td></tr>'+\
	'		<tr><td><b>Scan type:</b></td><td>'+html.escape(scaninfo_field(o, '@type'))+'</td></tr>'+\
	'		<tr><td><b>Nmap version:</b></td><td>'+html.escape(o['@version'])+'</td></tr>'+\
	'	</tbody></table></div>'+\
	'	<div style="color:#999;margin-top:100px;font-size:18px;"><i>The information contained in these documents is confidential, privileged and only for the information of the intended recipient and may not be used, published or redistributed.</i></div>'+\
	'</div></div><br>'+\
	'<div style="page-break-before: always;">'+\
	'	<h2>Ports and Services</h2><div class="subtitle">Ports status and services type</div>'+\
	'	<div class="row" style="margin-top:30px;border-bottom:solid #ccc 1px;padding:10px;">'+\
	'		<div class="col s3"><b class="blue-text" style="font-size:24px;">HOSTS UP</b><br><span style="color:#999;font-size:32px;">'+str(counters['hostsup'])+'</span></div>'+\
	'		<div class="col s3" style="border-left:solid #ccc 1px;"><b class="blue-text" style="font-size:24px;">PORTS</b><br><span style="color:#999;font-size:32px;">'+str(counters['pc']+counters['po']+counters['pf'])+'</span></div>'+\
	'		<div class="col s3" style="border-left:solid #ccc 1px;"><b class="blue-text" style="font-size:24px;">SERVICES</b><br><span style="color:#999;font-size:32px;">'+str(len(counters['ss'].keys()))+'</span></div>'+\
	'		<div class="col s3" style="border-left:solid #ccc 1px;"><b class="blue-text" style="font-size:24px;">OS</b><br><span style="color:#999;font-size:32px;">'+str(len(counters['ostype'].keys()))+'</span></div>'+\
	'	</div>'+\
	'	<div class="row" style="margin-top:50px;">'+\
	'		<div class="col s8">'+\
	bars('Port Status', [('Open', counters['po']), ('Closed', counters['pc']), ('Filtered', counters['pf'])])+\
	bars('Ports list (top 20)', top_ports)+\
	bars('Services list (top 20)', top_services)+\
	'		</div>'+\
	'		<div class="col s4" style="border-left:solid #ccc 1px;padding-left:20px;min-height:300px;">'+\
	'			<b class="subtitle">Total Ports</b><br><span class="subtitle">'+str(counters['pc']+counters['po']+counters['pf'])+'</span><br><br>'+\
	'			<b class="subtitle green-text">Open Ports</b><br><span class="subtitle green-text">'+str(counters['po'])+'</span><br><br>'+\
	'			<b class="subtitle red-text">Closed Ports</b><br><span class="subtitle red-text">'+str(counters['pc'])+'</span><br><br>'+\
	'			<b class="subtitle orange-text">Filtered Ports</b><br><span class="subtitle orange-text">'+str(counters['pf'])+'</span><br><br>'+\
	'			<b>Ports</b>:<br><span style="font-family:monospace;font-size:11px;">'+html_ports[0:-2]+'</span><br><br>'+\
	'			<b>Services</b>:<br><span style="font-family:monospace;font-size:11px;">'+html_services[0:-2]+'</span>'+\
	'		</div>'+\
	'</div>'

	r['html'] += hostdetails

	r['html'] += ''+\
	'<div style="page-break-before: always;">'+\
	'	<div>'+\
	'		<div style="text-align:center;padding-top:600px;"><b>Generated by</b><br>'+\
	'			'+logo+'<br>'+\
	'			<a href="https://github.com/Rev3rseSecurity/WebMap">https://github.com/Rev3rseSecurity/WebMap</a>'+\
	'		</div>'+\
	'	</div>'+\
	'</div>'

	r['css'] = mark_safe(_asset('vendor/materialize-1.0.0.min.css') + '\n' + _asset('report.css'))

	return render_to_string('nmapreport/report.html', r)

def reportPDFView(request):
	# HTML preview of the PDF report. The PDF itself is rendered in-process
	# by api.genPDF, which no longer calls back into this view over HTTP.
	try:
		scan = session_scan(request)
	except Exception:
		return HttpResponse('error: scan file not readable', content_type="text/plain", status=400)
	if scan is None:
		return HttpResponse('error: scan file not loaded', content_type="text/plain")

	return HttpResponse(render_report(scan))
