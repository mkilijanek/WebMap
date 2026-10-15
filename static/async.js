// WebMap front-end. The pages carry no inline JavaScript (the
// Content-Security-Policy only allows scripts from this app): elements say
// what they do in data-action / data-* attributes, chart data comes in a
// <script type="application/json" id="chartdata"> block, and everything is
// wired up here.

function getCSRFToken() {
	return $('input[name="csrfmiddlewaretoken"]').val();
}

function escHTML(s) {
	return $('<span/>').text(String(s)).html();
}

// Notes are stored as urlencoded base64 of UTF-8 text. btoa()/atob() work on
// Latin-1 only, so convert through bytes (non-ASCII notes used to fail).
function utf8ToB64(text) {
	var bytes = new TextEncoder().encode(text);
	var bin = '';
	for(var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
	return btoa(bin);
}

function b64ToUtf8(b64) {
	var bin = atob(b64);
	var bytes = new Uint8Array(bin.length);
	for(var i = 0; i < bin.length; i++) { bytes[i] = bin.charCodeAt(i); }
	return new TextDecoder().decode(bytes);
}

function isHash(s) {
	return /^[a-f0-9]{32}$/.test(String(s));
}

function reloadButton() {
	return '<button class="btn blue" data-action="reload">Reload</button>';
}

var actions = {
	'genpdf': function() { genPDF(); },
	'checkcve': function() { checkCVE(); },
	'togglezero': function() { $('.zeroportopen').fadeToggle(); },
	'reload': function() { location.reload(); },
	'savenotes': function() { saveNotes(); },
	'opennotes': function(el) { openNotes(el.attr('data-hash'), el.attr('data-notes') || ''); },
	'rmnotes': function(el) { removeNotes(el.attr('data-hash'), el.attr('data-index')); },
	'setlabel': function(el) { setLabel(el.attr('data-type'), el.attr('data-label'), el.attr('data-hash'), el.attr('data-index')); },
	'rmlabel': function(el) { removeLabel(el.attr('data-type'), el.attr('data-hash'), el.attr('data-index')); }
};

$(document).on('click', '[data-action]', function(e) {
	var fn = actions[$(this).attr('data-action')];
	if(fn) {
		e.preventDefault();
		fn($(this));
	}
});

// Port details buttons carry their values in data-* attributes.
$(document).on('click', '.portdetails', function() {
	apiPortDetails($(this).attr('data-address'), $(this).attr('data-portid'));
});

$(document).ready(function() {
	$('.sidenav').sidenav();
	$('.modal').modal();
	$('.dropdown-trigger').dropdown();
	$('.tooltipped').tooltip();
	M.FloatingActionButton.init(document.querySelectorAll('.fixed-action-btn'), { direction: 'top' });

	if($('.btncpy').length) {
		var clipboard = new ClipboardJS('.btncpy');
		clipboard.on('success', function() { M.toast({html: 'Copied to clipboard'}); });
	}

	// open-port bars on the scan page, relative to all ports of the scan
	var total = parseInt($('#percototal').attr('data-total'), 10) || 1;
	$('.perco').each(function() {
		var po = parseInt($(this).attr('data-po'), 10) || 0;
		$(this).css('width', ((po * 100) / total)+'%');
		if(po < 1) { $(this).html('&nbsp;'); $(this).css('background-color', '#666'); }
	});

	drawCharts();
});

function drawCharts() {
	var el = document.getElementById('chartdata');
	if(!el) { return; }
	var d = JSON.parse(el.textContent);
	var legend = { position: 'right', labels: { fontColor: '#cccccc' } };

	new Chart(document.getElementById('chart1').getContext('2d'), {
		type: 'doughnut',
		data: { labels: ['Open', 'Filtered', 'Closed'], datasets: [{ data: d.ports, backgroundColor: ['rgba(0,200,0,0.8)', 'rgba(255,200,0,0.8)', 'rgba(255,0,0,0.8)'], borderColor: '#3e3e3e' }] },
		options: { legend: legend }
	});
	new Chart(document.getElementById('chart3').getContext('2d'), {
		type: 'doughnut',
		data: { labels: d.toplabels, datasets: [{ data: d.topdata, borderColor: '#3e3e3e', backgroundColor: ['#e6194b', '#3cb44b', '#ffe119', '#4363d8', '#f58231', '#911eb4', '#46f0f0', '#f032e6', '#bcf60c', '#fabebe', '#008080', '#e6beff', '#9a6324', '#fffac8', '#800000', '#aaffc3', '#808000', '#ffd8b1', '#000075', '#808080', '#ffffff', '#000000'] }] },
		options: { legend: legend }
	});
	new Chart(document.getElementById('chart2').getContext('2d'), {
		type: 'horizontalBar',
		data: { labels: d.servicelabels, datasets: [{ data: d.servicedata, backgroundColor: 'rgba(0,140,220,0.8)' }] },
		options: { legend: { display: false }, scales: { xAxes: [{ ticks: { beginAtZero: true, fontColor: '#cccccc' } }], yAxes: [{ ticks: { fontColor: '#cccccc' } }] } }
	});
}

function openModal(title, body, footer) {
	$('#modal1').css('background-color', '#3e3e3e');
	$('#modaltitle').html(title);
	$('#modalbody').html(body);
	if(footer !== undefined) { $('#modalfooter').html(footer); }
	$('#modal1').modal('open');
}

var cpetot = 0;
var cpetimer;
function checkCVE() {
	var cpe = JSON.parse(atob(decodeURIComponent($('#cpestring').val())));
	var csrftoken = getCSRFToken();

	openModal('Looking for CVE and Exploits',
		'This process could take a while, please wait...'+
		'<div class="progress"><div class="indeterminate"></div></div>', '');

	// one request per CPE string, so count CPE strings (not hosts)
	var jobs = [];
	for(var host in cpe) {
		for(var port in cpe[host]) {
			for(var cpestr in cpe[host][port]) {
				if(/^cpe:.+:.+:.+:.*$/.test(cpestr)) {
					jobs.push([host, port, cpestr]);
				}
			}
		}
	}
	cpetot = jobs.length;

	jobs.forEach(function(job) {
		$.post('/report/api/getcve/', {
			'cpe': job[2],
			'host': job[0],
			'port': job[1],
			'csrfmiddlewaretoken': csrftoken
		}).done(function(d) {
			for(var rhost in d) {
				if(typeof(d[rhost]) !== 'object') { continue; }
				for(var rport in d[rhost]) {
					$('#modalbody').append('<div class="small"><i>Received: '+escHTML(d[rhost][rport]['id'])+' host:'+escHTML(rhost)+' port:'+escHTML(rport)+'</i></div>');
				}
			}
		}).fail(function(xhr) {
			var msg = (xhr.responseJSON && xhr.responseJSON.error) || 'request failed';
			$('#modalbody').append('<div class="small red-text"><i>'+escHTML(job[2])+': '+escHTML(msg)+'</i></div>');
		}).always(function() { cpetot = (cpetot - 1); });
	});

	cpetimer = setInterval(function() {
		if(cpetot <= 0) {
			window.clearInterval(cpetimer);
			$('#modalbody').append('<br>Done. Please, reload this page by clicking on Reload button.');
			$('#modalfooter').html(reloadButton());
		}
	}, 2000);
}

function genPDF() {
	// The server returns the PDF in the response to this POST; a normal form
	// submission lets the browser show or save it. No file is left on the
	// server and nothing has to be polled.
	openModal('Generating PDF Report',
		'Please wait a few seconds, the PDF will open when it is ready.<br>'+
		'<div class="progress"><div class="indeterminate"></div></div>');

	var form = $('<form method="post" action="/report/api/pdf/"></form>');
	form.append($('<input type="hidden" name="csrfmiddlewaretoken">').val(getCSRFToken()));
	$('body').append(form);
	form.submit();
}

function removeNotes(hashstr, i) {
	if(!isHash(hashstr)) { return; }
	$.post('/report/api/rmnotes/'+hashstr+'/', {'csrfmiddlewaretoken': getCSRFToken()}).done(function(data) {
		if(data['ok'] == 'notes removed') {
			$('#noteshost'+parseInt(i, 10)).remove();
		}
	});
}

function saveNotes() {
	var hashstr = $('#hashstr').val();
	if(!isHash(hashstr)) { return; }
	$.post('/report/api/savenotes/', {
		'notes': encodeURIComponent(utf8ToB64($('#notes').val())),
		'csrfmiddlewaretoken': getCSRFToken(),
		'hashstr': hashstr
	}).done(function(d) {
		if(d['ok'] == 'notes saved') {
			$('#modalbody').html('<span class="green-text">Notes successfully saved!</span><br> Now this page needs a reload. Please, click on the &quot;Reload&quot; button.');
			$('#modalfooter').html(reloadButton());
		}
	}).fail(function(xhr) {
		var msg = (xhr.responseJSON && xhr.responseJSON.error) || 'request failed';
		M.toast({html: escHTML('Notes not saved: '+msg)});
	});
}

function openNotes(hashstr, notesb64) {
	if(!isHash(hashstr)) { return; }
	var savednotes = '';
	if(notesb64 != '') {
		try { savednotes = b64ToUtf8(decodeURIComponent(notesb64)); } catch(e) { savednotes = ''; }
	}
	openModal('Save Notes',
		'In the text area below, you can insert notes that will appear on the PDF report. '+
		'Notes are shown as plain text: HTML markup is displayed literally, not rendered.<br><br>'+
		'<textarea id="notes" style="color:#fff;min-height:160px;">'+escHTML(savednotes)+'</textarea>'+
		'<input type="hidden" id="hashstr" value="'+hashstr+'" />',
		'<button data-action="savenotes" class="waves-effect waves-green btn grey white-text">Save</button>');
}

function apiPortDetails(address, portid) {
	$.get('/report/api/'+encodeURIComponent(address)+'/'+encodeURIComponent(portid)+'/').done(function(data) {
		var tbody = '';
		var ignorescriptid = { 'fingerprint-strings': true };
		var scripts = data['script'] || [];
		if(!Array.isArray(scripts)) { scripts = [scripts]; }

		scripts.forEach(function(s) {
			if(ignorescriptid[s['@id']]) { return; }
			tbody += '<tr><td class="orange-text">'+escHTML(s['@id'])+'</td><td style="font-family:monospace;font-size:12px;">'+escHTML(s['@output'])+'</td></tr>';
		});
		if(tbody == '') {
			tbody = '<tr><td><i>none</i></td><td><i>none</i></td></tr>';
		}

		openModal('Port Details: <span class="blue-text">'+escHTML(data['@portid'])+' / '+escHTML(data['@protocol'])+'</span>',
			'<table class="table"><thead><th style="min-width:200px;">Script ID</th><th>Output</th></thead><tbody>'+tbody+'</tbody></table>'+
			'<br><b>Raw Output:</b><br><pre>'+escHTML(JSON.stringify(data, null, 4))+'</pre>');
	});
}

function removeLabel(type, hashstr, i) {
	if(!isHash(hashstr)) { return; }
	$.post('/report/api/rmlabel/'+encodeURIComponent(type)+'/'+hashstr+'/', {'csrfmiddlewaretoken': getCSRFToken()}).done(function(data) {
		if(data['ok'] == 'label removed') {
			var el = $('#hostlabel'+parseInt(i, 10));
			el.attr('class', '');
			el.text('');
		}
	});
}

function setLabel(type, label, hashstr, i) {
	if(!isHash(hashstr)) { return; }
	$.post('/report/api/setlabel/'+encodeURIComponent(type)+'/'+encodeURIComponent(label)+'/'+hashstr+'/', {'csrfmiddlewaretoken': getCSRFToken()}).done(function(res) {
		var styles = {
			'Vulnerable': ['red', '10px'],
			'Critical': ['black', '22px'],
			'Warning': ['orange', '28px'],
			'Checked': ['blue', '28px']
		};
		if(res['ok'] == 'label set' && styles[res['label']]) {
			var el = $('#hostlabel'+parseInt(i, 10));
			el.css('margin-left', styles[res['label']][1]);
			el.attr('class', 'rightlabel '+styles[res['label']][0]);
			el.text(res['label']);
		}
	});
}
