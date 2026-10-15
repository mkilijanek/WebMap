from django.shortcuts import render, redirect
from django.core.exceptions import SuspiciousFileOperation, ValidationError
from django.middleware.csrf import get_token
from django.utils.html import json_script
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_POST
import json, html, urllib.parse, base64
from nmapreport.functions import *
from nmapreport.scan import (
	ScanError, session_scan, load_scan, list_scan_files, read_annotations,
	host_address, find_host, scaninfo_field, unique_ports, md5
)

def scan_error(request, err):
	# A broken or half-written XML file must not take the whole UI down.
	msg = str(err) if isinstance(err, ScanError) else 'invalid scan file'
	return render(request, 'nmapreport/index.html', { 'table': '', 'scaninfo': '<span class="card-title">Cannot load scan</span><p>'+esc(msg)+'</p>', 'scandetails': '', 'trhost': '' }, status=400)

def counter(icon, value, label):
	return '<center><h4><i class="'+icon+'"></i> '+str(value)+'</h4><span class="small grey-text">'+label+'</span></center>'

def postbutton(request, action, label, cls):
	# Session state changes go through POST + CSRF instead of plain links.
	return '<form method="post" action="'+esc(action)+'" style="display:inline;">'+\
	'<input type="hidden" name="csrfmiddlewaretoken" value="'+esc(get_token(request))+'">'+\
	'<button type="submit" class="'+cls+'">'+label+'</button></form>'

@csrf_protect
@require_POST
def setscanfile(request, scanfile):
	if scanfile in list_scan_files():
		request.session['scanfile'] = scanfile

	if scanfile == 'unset':
		if 'scanfile' in request.session:
			del(request.session['scanfile'])

	return redirect('/')


def details(request, address):
	r = {}
	try:
		scan = session_scan(request)
	except (ScanError, ValidationError, SuspiciousFileOperation) as err:
		return scan_error(request, err)
	if scan is None:
		return redirect('/')

	r['scantitle'] = scan.name
	r['trhost'] = ''
	pc,po,pf=0,0,0

	addressmd5 = md5(address)
	labelhost, noteshost, cvehost = read_annotations(scan.key)

	r['trhead'] = '<tr><th>Port</th><th style="width:300px;">Product / Version</th><th>Extra Info</th><th>&nbsp;</th></tr>'
	pel=0
	i = find_host(scan, address)
	if i is None:
		r['scaninfo'] = '<span class="card-title">Host not found in this scan</span>'
	else:
		h = '<span style="color:#999;font-size:12px;"><i>No Hostname</i></span>'
		if i['hostnames'] and '@name' in i['hostnames'][0]:
			h = '<span style="color:#999;font-size:12px;">'+esc(i['hostnames'][0]['@name'])+'</span>'

		labelout = '<span id="hostlabel"></span>'
		if addressmd5 in labelhost:
			labelcolor = labelToColor(labelhost[addressmd5])
			labelout = '<span id="hostlabel" style="margin-left:60px;margin-top:-24px;" class="rightlabel '+labelcolor+'">'+html.escape(labelhost[addressmd5])+'</span>'

		r['scaninfo'] = '<div class="row">'+\
		'	<div class="col s3"><span class="card-title">Host Details:</span><h6>'+html.escape(address)+'</h6>'+h+labelout+'</div>'+\
		'	<div class="col s3">{po}</div>'+\
		'	<div class="col s3">{pc}</div>'+\
		'	<div class="col s3">{pf}</div>'+\
		'</div>'

		for p in unique_ports(i):
			# portid ends up in URLs and data attributes; nmap only writes
			# integers here, anything else comes from a crafted file.
			if not is_portid(p['@portid']):
				continue

			if p['state']['@state'] == 'closed':
				pc = (pc + 1)
			elif p['state']['@state'] == 'open':
				po = (po + 1)
			elif p['state']['@state'] == 'filtered':
				pf = (pf + 1)

			pel = (pel + 1)
			portbtn = '<button data-address="'+esc(address)+'" data-portid="'+esc(p['@portid'])+'" class="btn blue right portdetails"><i class="material-icons">receipt</i></button>'

			v,z,e = '','','<i class="grey-text">N/A</i>'
			if p['state']['@state'] == 'open':
				if '@version' in p['service']:
					v = esc(p['service']['@version'])
				else:
					v = '<i class="grey-text">No Version</i>'

				if '@product' in p['service']:
					z = esc(p['service']['@product'])
				else:
					z = '<i class="grey-text">No Product</i>'

				if '@extrainfo' in p['service']:
					e = esc(p['service']['@extrainfo'])

				cpe = ''
				for cpei in p['service']['cpe']:
					cpe += '<span class="grey-text" style="font-family:monospace;font-size:12px;">'+html.escape(cpei)+'</span><br>'

				copycmds = ''
				if is_ip(address):
					url = 'http://'+urlhost(address)+':'+p['@portid']
					copycmds = ''+\
					'	<li><a href="#!" class="btncpy" data-clipboard-text="'+esc(shellcmd('curl', '-v', '-A', 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1', '-k', url))+'">Copy as curl command</a></li>'+\
					'	<li><a href="#!" class="btncpy" data-clipboard-text="'+esc(shellcmd('nikto', '-host', url))+'">Copy as nikto command</a></li>'+\
					'	<li><a href="#!" class="btncpy" data-clipboard-text="'+esc(shellcmd('telnet', address, p['@portid']))+'">Copy as telnet command</a></li>'

				r['trhost'] += '<tr><td style="vertical-align:top;">'+\
				'<span style="color:#999;font-size:12px;">'+esc(p['service']['@name'])+'</span><br>'+\
				'<span class="new badge blue" data-badge-caption="">'+esc(p['@protocol'])+' / '+esc(p['@portid'])+'</span>'+\
				'</td>'+\
				'<td>'+z+' / '+v+'<br><span style="font-size:12px;color:#999;">State: '+esc(p['state']['@state'])+'<br>Reason: '+esc(p['state']['@reason'])+'</span></td>'+\
				'<td style="vertical-align:top">'+e+'<br>'+cpe+'</td>'+\
				'<td><ul id="dropdown'+str(pel)+'" class="dropdown-content" style="min-width:300px;">'+\
				copycmds+\
				'</ul><a class="dropdown-trigger btn blue right" href="#!" data-target="dropdown'+str(pel)+'"><i class="material-icons">arrow_drop_down</i></a> '+\
				portbtn+'</td>'+\
				'</tr>'
			elif p['state']['@state'] == 'filtered':
				r['trhost'] += '<tr><td><span class="new badge grey" data-badge-caption="">'+esc(p['@protocol'])+' / '+esc(p['@portid'])+'</span><br>'+\
				'<span style="color:#999;font-size:12px;">'+esc(p['service']['@name'])+'</span></td>'+\
				'<td colspan="2" style="color:#999;font-size:12px;">State: filtered<br>Reason: '+esc(p['state']['@reason'])+'</td>'+\
				'<td>'+portbtn+'</td></tr>'
			else:
				r['trhost'] += '<tr><td><span class="new badge grey" data-badge-caption="">'+esc(p['@protocol'])+' / '+esc(p['@portid'])+'</span><br>'+\
				'<span style="color:#999;font-size:12px;">'+esc(p['service']['@name'])+'</span></td>'+\
				'<td colspan="2" style="color:#999;font-size:12px;">State: '+esc(p['state']['@state'])+'<br>Reason: '+esc(p['state']['@reason'])+'</td>'+\
				'<td>'+portbtn+'</td></tr>'

	r['table'] = ''
	if addressmd5 in noteshost:
		r['table'] += '<div class="card" style="background-color:#3e3e3e;">'+\
		'	<div class="card-content"><h5>Notes</h5>'+\
		'		'+notestohtml(noteshost[addressmd5])+\
		'	</div>'+\
		'</div>'

	cveout = ''
	if addressmd5 in cvehost:
		for cveobj in cvehost[addressmd5]:
			cveout += cvetohtml(cveobj, '<div style="line-height:28px;padding:10px;border:solid #333 1px;border-radius:4px;margin-top:10px;">')

		r['table'] += '<div class="card" style="background-color:#3e3e3e;">'+\
		'	<div class="card-content"><span class="card-title">CVE LIST:</span>'+\
		cveout+\
		'	</div>'+\
		'</div>'

	if i is not None:
		# filled in once the ports are counted; the page has no inline script
		r['scaninfo'] = r['scaninfo'].replace('{po}', counter('fas fa-door-open green-text', po, 'OPEN PORTS'), 1)\
			.replace('{pc}', counter('fas fa-door-closed red-text', pc, 'CLOSED PORTS'), 1)\
			.replace('{pf}', counter('fas fa-filter grey-text', pf, 'FILTERED PORTS'), 1)

	return render(request, 'nmapreport/index.html', r)

def index(request, filterservice="", filterportid=""):
	r = {}

	try:
		scan = session_scan(request)
	except (ScanError, ValidationError, SuspiciousFileOperation) as err:
		return scan_error(request, err)

	if scan is None:
		# no file selected
		r['table'] = '<div class="card" style="background-color:#3e3e3e;"><div class="card-content">'+\
		'		Put your Nmap XML files in <span class="tmlabel grey-text" style="background-color:transparent;">/opt/xml/</span> directory, example:<br><br>'+\
		'		<div class="tmlabel black grey-text" style="padding:10px;font-size:14px;">nmap -A -T4 -oX myscan.xml 192.168.1.0/24<br>'+\
		'		mv myscan.xml &lt;docker webmap xml dir&gt;<br><br>'+\
		'		# or you can copy myscan.xml to the webmap container:<br>'+\
		'		docker cp myscan.xml webmap:/opt/xml/</div>'+\
		'</div></div>'

		r['table'] += '<div class="row hide-on-med-and-down" style="margin-top:60px;padding:10px;border-top:solid #444 1px;">'+\
		'	<div class="col s4" style="text-align:center;">'+\
		'		<img src="/static/logo.png" style="width:320px;" /><br>'+\
		'		<span style="color:#999;">Made with <i class="fas fa-heart red-text"></i> by Andrea <b><a href="https://twitter.com/Menin_TheMiddle">theMiddle</a></b> Menin</span><br><br>'+\
		'	</div>'+\
		'	<div class="col s4" style="color:#999;text-align:center;">'+\
		'		<img src="/static/rev3rse_logo.png" style="width:180px;" /><br>'+\
		'		<span style="color:#999;">A Rev3rse Security Project</span>'+\
		'	</div>'+\
		'	<div class="col s4" style="color:#999;text-align:left;">'+\
		'		<div style="color:#999;margin-bottom:10px;">Support us &amp; Follow us</div>'+\
		'		<a href="https://github.com/Rev3rseSecurity/WebMap/" class="white-text"><i class="fab fa-github fa-1x white-text"></i> WebMap on GitHub</a><br>'+\
		'		<a href="https://twitter.com/rev3rsesecurity" class="white-text"><i class="fab fa-twitter fa-1x blue-text" style=""></i> <b>Rev3rse Security</b> on Twitter</a><br>'+\
		'		<a href="https://www.youtube.com/rev3rsesecurity" class="white-text"><i class="fab fa-youtube fa-1x red-text" style=""></i> <b>Rev3rse Security</b> on YouTube</a><br>'+\
		'	</div>'+\
		'</div>'


		r['trhost'] = ''
		r['trhead'] = '<tr><th>Filename</th><th>Scan Start Time</th><th>Hosts</th><th>&nbsp;</th></tr>'

		xmlfiles = list_scan_files()
		for i in xmlfiles:
			try:
				o = load_scan(i).data
			except (ScanError, ValidationError, SuspiciousFileOperation) as err:
				r['trhost'] += '<tr>'+\
				'	<td style="font-family:monospace">'+html.escape(i)+'</td>'+\
				'	<td colspan="3" class="grey-text">'+esc(err if isinstance(err, ScanError) else 'invalid scan file')+'</td>'+\
				'</tr>'
				continue

			hostnum = len(o['host'])

			if hostnum != 0:
				viewbtn = postbutton(request, '/setscanfile/'+urllib.parse.quote(i), 'view', 'btn blue right')
			else:
				viewbtn = '<a href="/" class="btn blue right" disabled="disabled">view</a>'

			r['trhost'] += '<tr>'+\
			'	<td style="font-family:monospace">'+html.escape(i)+'</td>'+\
			'	<td>'+html.escape(o['@startstr'])+'</td>'+\
			'	<td>'+str(hostnum)+'</td>'+\
			'	<td>'+viewbtn+'</td>'+\
			'</tr>'

		r['scaninfo'] = '<span class="card-title">Select a Nmap XML file</span><p>Nmap XML files: '+ str(len(xmlfiles)) +'</p>'

		return render(request, 'nmapreport/index.html', r)

	o = scan.data
	r['scantitle'] = scan.name

	r['topcontainer'] = '<div class="fixed-action-btn">'+\
	'	<a class="btn-floating btn-large red">'+\
	'		<i class="large material-icons">mode_edit</i>'+\
	'	</a>'+\
	'	<ul>'+\
	'		<li><a class="btn-floating red tooltipped" data-position="left" data-tooltip="PDF Report" data-action="genpdf"><i class="material-icons">insert_chart</i></a></li>'+\
	'		<li><a class="btn-floating blue darken-1 tooltipped" data-position="left" data-tooltip="Hide/Show hosts with no open ports" data-action="togglezero"><i class="material-icons">view_day</i></a></li>'+\
	'		<li><a class="btn-floating orange tooltipped" data-position="left" data-tooltip="Check for CVE and Exploits on all hosts" data-action="checkcve"><i class="fas fa-bolt"></i></a></li>'+\
	'	</ul>'+\
	'</div>'

	labelhost, noteshost, cvehost = read_annotations(scan.key)

	hostsup = 0
	hostindex = 1
	ports = { 'open': 0, 'closed': 0, 'filtered': 0 }
	allostypelist, sscount, picount, cpe = {}, {}, {}, {}

	r['trhost'] = ''
	r['trhead'] = '<tr><th width="260">Host</th><th>Port State</th><th width="160" style="text-align:center;">Tot Ports</th><th width="200">Services</th><th width="200">Ports</th><th>&nbsp;</th></tr>'

	for i in scan.hosts:
		address = host_address(i)
		if address is None:
			# no usable IPv4/IPv6/MAC address: nothing to key the row on
			continue

		hostname = ''

		if i['hostnames'] and '@name' in i['hostnames'][0]:
			hostname += '<br><span style="color:#999;font-size:10px;">'+esc(i['hostnames'][0]['@name'])+'</span>'

		if i['status']['@state'] == 'up':
			hostsup = (hostsup + 1)

		po,pc,pf = 0,0,0
		ss,pp,ost = {},{},{}

		addressmd5 = md5(address)

		# one CPE map per host, filled by every port (not reset per port)
		cpe[address] = {}

		striggered = False
		if i['ports']:
			for p in unique_ports(i):
				if filterservice != "" and p['service']['@name'] == filterservice:
					striggered = True

				if filterportid != "" and p['@portid'] == filterportid:
					striggered = True

				ss[p['service']['@name']] = p['service']['@name']
				pp[p['@portid']] = p['@portid']

				if p['service']['cpe'] and is_portid(p['@portid']):
					cpeport = cpe[address].setdefault(p['@portid'], {})
					for cpei in p['service']['cpe']:
						cpeport[cpei] = cpei

				if '@ostype' in p['service']:
					allostypelist[p['service']['@ostype']] = allostypelist.get(p['service']['@ostype'], 0) + 1
					ost[p['service']['@ostype']] = p['service']['@ostype']

				sscount[p['service']['@name']] = sscount.get(p['service']['@name'], 0) + 1
				picount[p['@portid']] = picount.get(p['@portid'], 0) + 1

				if p['state']['@state'] == 'closed':
					ports['closed'] = (ports['closed'] + 1)
					pc = (pc + 1)
				elif p['state']['@state'] == 'open':
					ports['open'] = (ports['open'] + 1)
					po = (po + 1)
				elif p['state']['@state'] == 'filtered':
					ports['filtered'] = (ports['filtered'] + 1)
					pf = (pf + 1)

			services = ''
			for s in ss:
				if filterservice != ss[s]:
					services += '<a href="/report/service/'+esc(urllib.parse.quote(ss[s], safe=''))+'/">'+esc(ss[s])+'</a>, '
				else:
					services += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">'+esc(ss[s])+'</span>, '

			ostype = ''
			for oty in ost:
				ostype += '<i class="'+fromOSTypeToFontAwesome(html.escape(ost[oty]))+'"></i> <span class="grey-text small">'+esc(ost[oty].lower())+'</span> '

			tdports = ''
			for kp in pp:
				if filterportid != pp[kp]:
					tdports += '<a href="/report/portid/'+esc(urllib.parse.quote(pp[kp], safe=''))+'/">'+esc(pp[kp])+'</a>, '
				else:
					tdports += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">'+esc(pp[kp])+'</span>, '

			poclass = ''
			if po == 0:
				poclass = 'zeroportopen'

			labelout = '<span id="hostlabel'+str(hostindex)+'"></span>'
			if addressmd5 in labelhost:
				labelcolor = labelToColor(labelhost[addressmd5])
				labelmargin = labelToMargin(labelhost[addressmd5])
				labelout = '<span id="hostlabel'+str(hostindex)+'" style="margin-left:'+labelmargin+'" class="rightlabel '+labelcolor+'">'+html.escape(labelhost[addressmd5])+'</span>'

			notesout,notesb64,removenotes = '','',''
			if addressmd5 in noteshost:
				notesb64 = noteshost[addressmd5]
				notesout = '<br><a id="noteshost'+str(hostindex)+'" href="#!" data-action="opennotes" data-hash="'+addressmd5+'" data-notes="'+esc(safenotesb64(notesb64))+'" class="small"><i class="fas fa-comment"></i> contains notes</a>'
				removenotes = '<li><a href="#!" data-action="rmnotes" data-hash="'+addressmd5+'" data-index="'+str(hostindex)+'">Remove notes</a></li>'

			cveout = ''
			if addressmd5 in cvehost:
				cveout = '<br><span class="small grey-text"><i class="fas fa-exclamation-triangle orange-text"></i> '+str(len(cvehost[addressmd5]))+' CVE found</span>'

			if (filterservice != "" and striggered is True) or (filterportid != "" and striggered is True) or (filterservice == "" and filterportid == ""):
				portstateout = '<td style="font-size:10px;color:#999;width:300px;"><div style="overflow:none;background-color:#666;" class="tooltipped" data-position="top" data-tooltip="'+str(po)+' open, '+str(pc)+' closed, '+str(pf)+' filtered">'+\
				'		<div class="perco" data-po="'+str(po)+'" style="padding-left:16px;padding-right:20px;">'+str(po)+'</div>'+\
				' </div></td>'

				if (filterservice != "" and striggered is True):
					portstateout = '<td style="font-size:10px;color:#999;width:300px;"><div style="overflow:none;background-color:#666;" class="tooltipped" data-position="top" data-tooltip="'+str(po)+' open, '+str(pc)+' closed, '+str(pf)+' filtered">'+\
					'		<div class="perco" data-po="'+str(po)+'" data-pt="'+str((po + pf + pc))+'" style="padding-left:16px;padding-right:20px;">'+str(po)+'</div>'+\
					'	</div></td>'

				r['trhost'] += '<tr class="'+poclass+'">'+\
				'	<td><span class="leftlabel" style="background-color:#4a4a4a;color:#999;">'+str(hostindex)+'</span>'+\
				'		'+ostype+'<br>'+\
				'		<b><a href="/report/'+esc(address)+'">'+esc(address)+'</a></b>'+hostname+''+\
				notesout+\
				cveout+\
				'	</td>'+\
				portstateout+\
				'	<td style="font-family:monospace;text-align:center;">'+str((po + pf + pc))+'</td>'+\
				'	<td style="font-size:12px;">'+str(services[0:-2])+'</td>'+\
				'	<td style="font-size:12px;">'+str(tdports[0:-2])+'</td>'+\
				'	<td>'+\
				'		<ul id="hostdd'+str(hostindex)+'" class="dropdown-content" style="min-width:200px;">'+\
				'			<li><a href="#!" data-action="setlabel" data-type="host" data-label="Vulnerable" data-hash="'+addressmd5+'" data-index="'+str(hostindex)+'"><span class="tmlabel red">Vulnerable</span></a></li>'+\
				'			<li><a href="#!" data-action="setlabel" data-type="host" data-label="Critical" data-hash="'+addressmd5+'" data-index="'+str(hostindex)+'"><span class="tmlabel black">Critical</span></a></li>'+\
				'			<li><a href="#!" data-action="setlabel" data-type="host" data-label="Warning" data-hash="'+addressmd5+'" data-index="'+str(hostindex)+'"><span class="tmlabel orange">Warning</span></a></li>'+\
				'			<li><a href="#!" data-action="setlabel" data-type="host" data-label="Checked" data-hash="'+addressmd5+'" data-index="'+str(hostindex)+'"><span class="tmlabel blue">Checked</span></a></li>'+\
				'			<li><a href="#!" data-action="rmlabel" data-type="host" data-hash="'+addressmd5+'" data-index="'+str(hostindex)+'">Remove label</a></li>'+\
				'			<li class="divider"></li>'+\
				'			<li><a href="#!" data-action="opennotes" data-hash="'+addressmd5+'" data-notes="'+esc(safenotesb64(notesb64))+'">Insert notes</a></li>'+\
				'			'+removenotes+\
				'		</ul>'+\
				labelout+\
				'		<button class="btn darken-2 grey right dropdown-trigger" data-target="hostdd'+str(hostindex)+'"><i class="material-icons">arrow_drop_down</i></button>'+\
				'	</td>'+\
				'</tr>'
				hostindex = (hostindex + 1)

	allss = ''
	ssclabels, sscdata = [], []
	allssc = 0
	for i in sorted(sscount, key=sscount.__getitem__, reverse=True):
		if allssc <= 30:
			if filterservice != i:
				allss += '<a href="/report/service/'+esc(urllib.parse.quote(i, safe=''))+'/">'+html.escape(i)+'('+str(sscount[i])+')</a>, '
			else:
				allss += '<span class="tmlabel" style="background-color:#ffcc00;color:#333;">'+html.escape(i)+'</span>, '

			ssclabels.append(i)
			sscdata.append(sscount[i])
			allssc = (allssc + 1)

	toppilabels, toppidata = [], []
	allpilinks = ''
	allpic = 1
	for i in sorted(picount, key=picount.__getitem__, reverse=True):
		if allpic <= 5:
			allpilinks += '<a href="/report/portid/'+esc(urllib.parse.quote(i, safe=''))+'/">'+esc(i)+'</a>, '
			toppilabels.append(i)
			toppidata.append(picount[i])
			allpic = (allpic + 1)
		elif allpic <= 10:
			allpilinks += '<a href="/report/portid/'+esc(urllib.parse.quote(i, safe=''))+'/">'+esc(i)+'</a>, '
			allpic = (allpic + 1)

	allostypelinks = ''
	for i in sorted(allostypelist, key=allostypelist.__getitem__, reverse=True):
		allostypelinks += '<a href="">'+esc(i)+'</a>, '


	totports = (ports['open']+ports['closed']+ports['filtered'])
	if filterservice == "" and filterportid == "":
		scaninfobox2 = '<canvas id="chart1"></canvas>'
		scaninfobox3 = '<canvas id="chart3" height="150"></canvas>'
	else:
		scaninfobox2 = ''+\
		'	Filter port / service: <b>'+html.escape(filterportid+filterservice)+'</b> <a href="/"><i class="fas fa-trash-alt"></i></a><br>'+\
		'	Total Ports: '+str(totports)+'<br>'+\
		'	Open Ports: '+str(ports['open'])+'<br>'+\
		'	Closed Ports: '+str(ports['closed'])+'<br>'+\
		'	Filtered Ports: '+str(ports['filtered'])+'<br>'
		scaninfobox3 = '<span class="small">'+allss[0:-2]+'</span>'

	r['scaninfo'] = ''+\
	'<div class="row">'+\
	'	<div class="col s4">Scan Information</div>'+\
	'	<div class="col s4">Ports Status</div>'+\
	'	<div class="col s4">Top Ports / Services</div>'+\
	'</div>'+\
	'<div class="row">'+\
	'	<div class="col s4">'+\
	'		<b class="orange-text">Start:</b> '+esc(o['@startstr'])+'<br>'+\
	'		<b class="orange-text">Scan Type:</b> '+esc(scaninfo_field(o, '@type'))+'<br>'+\
	'		<b class="orange-text">Scan Protocol:</b> '+esc(scaninfo_field(o, '@protocol'))+'<br>'+\
	'		<b class="orange-text">Nmap Command:</b> <a class="activator" href="#!">view details</a>'+\
	'	</div>'+\
	'	<div class="col s4" style="border-left:solid #999 1px;">'+\
	scaninfobox2+\
	'	</div>'+\
	'	<div class="col s4" style="border-left:solid #999 1px;">'+\
	scaninfobox3+\
	'	</div>'+\
	'</div>'

	r['scandetails'] = '<div class="code" style="word-wrap: break-word;overflow-wrap: break-word;">'+\
	'	<p>'+esc(o['@args'])+'</p>'+\
	'	<p>'+\
	'		version: '+esc(o['@version'])+'<br>'+\
	'		xmloutputversion: '+esc(o['@xmloutputversion'])+'<br>'+\
	'	</p>'+\
	'</div>'


	r['pretable'] = ''
	if filterservice == "" and filterportid == "":
		r['pretable'] += '<div class="row">'+\
		'	<div class="col s3" style="padding:1px;"><div class="card" style="text-align:center;padding:6px;background-color:#3e3e3e;"><h4><i class="fab fa-creative-commons-sampling"></i> <span class="blue-text">'+str(hostsup)+'</span></h4><span class="small grey-text">HOSTS UP</span></div></div>'+\
		'	<div class="col s3" style="padding:1px;"><div class="card" style="text-align:center;padding:6px;background-color:#3e3e3e;"><h4><i class="fas fa-door-open"></i> <span class="green-text">'+str(ports['open'])+'</span></h4><span class="small grey-text">OPEN PORTS</span></div></div>'+\
		'	<div class="col s3" style="padding:1px;"><div class="card" style="text-align:center;padding:6px;background-color:#3e3e3e;"><h4><i class="fas fa-door-closed"></i> <span class="red-text">'+str(ports['closed'])+'</span></h4><span class="small grey-text">CLOSED PORTS</span></div></div>'+\
		'	<div class="col s3" style="padding:1px;"><div class="card" style="text-align:center;padding:6px;background-color:#3e3e3e;"><h4><i class="fas fa-filter"></i> <span class="orange-text">'+str(ports['filtered'])+'</span></h4><span class="small grey-text">FILTERED PORTS</span></div></div>'+\
		'</div>'+\
		'<div class="card" style="background-color:#3e3e3e;">'+\
		'	<div class="card-content">'+\
		'		<div class="row">'+\
		'			<div class="col s4"><b>Services:</b></div><div class="col s8"><b>Services:</b></div>'+\
		'			<div class="col s4" style="border-right:solid #999 1px;margin-top:10px;min-height:410px;">'+\
		'				<span style="font-family:monospace;font-size:12px;">'+allss[0:-2]+'</span><br><br>'+\
		'				<b>Top 10 Ports:</b><br><span style="font-family:monospace;font-size:12px;">'+allpilinks[0:-2]+'</span><br><br>'+\
		'				<b>OS Type List:</b><br><span style="font-family:monospace;font-size:12px;">'+allostypelinks[0:-2]+'</span>'+\
		'			</div>'+\
		'			<div class="col s8" style="margin-top:10px;"><canvas id="chart2" height="200"></canvas></div>'+\
		'		</div>'+\
		'	</div>'+\
		'</div>'

		# Chart data travels as JSON (not executed); static/async.js draws the
		# charts, so the page needs no inline script.
		r['pretable'] += json_script({
			'ports': [ports['open'], ports['filtered'], ports['closed']],
			'toplabels': toppilabels, 'topdata': toppidata,
			'servicelabels': ssclabels, 'servicedata': sscdata,
		}, 'chartdata')

	r['pretable'] += '<span id="percototal" data-total="'+str(totports or 1)+'" hidden></span>'

	r['pretable'] += ' <input type="hidden" id="cpestring" value="'+urllib.parse.quote_plus(base64.b64encode(json.dumps(cpe).encode()))+'" /> '

	return render(request, 'nmapreport/index.html', r)
