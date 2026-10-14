function getCSRFToken() {
	return $('input[name="csrfmiddlewaretoken"]').val();
}

function escHTML(s) {
	return $('<span/>').text(String(s)).html();
}

$(document).ready(function() {
	// Port details buttons carry their values in data-* attributes instead
	// of inline JavaScript built on the server.
	$(document).on('click', '.portdetails', function() {
		apiPortDetails($(this).attr('data-address'), $(this).attr('data-portid'));
	});
});

var cpetot = 0;
var cpetimer;
function checkCVE() {
	var cpe = JSON.parse(atob(decodeURIComponent($('#cpestring').val())));
	var csrftoken = getCSRFToken();

	$('#modal1').css('background-color','#3e3e3e');
	$('#modaltitle').html('Looking for CVE and Exploits');
	$('#modalbody').html(
		'This process could take a while, please wait...'+
		'<div class="progress"><div class="indeterminate"></div></div>'
	);
	$('#modalfooter').html('');
	$('#modal1').modal('open');

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
		}).always(function() { cpetot = (cpetot - 1); });
	});

	cpetimer = setInterval(function() {
		if(checkCPETOT()) {
			console.log('END');
			window.clearInterval(cpetimer);
			$('#modalbody').html('Done. Please, reload this page by clicking on Reload button.');
			$('#modalfooter').html('<button class="btn blue" onclick="javascript:location.reload();">Reload</button>');
		}
	}, 2000);

}

function checkCPETOT() {
	if(cpetot <= 0) {
		return true;
	} else {
		return false;
	}
}

function genPDF() {
	// The server returns the PDF in the response to this POST; a normal form
	// submission lets the browser show or save it. No file is left on the
	// server and nothing has to be polled.
	$('#modal1').css('background-color','#3e3e3e');
	$('#modaltitle').html('Generating PDF Report');
	$('#modalbody').html('Please wait a few seconds, the PDF will open when it is ready.<br>'+
	'<div class="progress"><div class="indeterminate"></div></div>');
	$('#modal1').modal('open');

	var form = $('<form method="post" action="/report/api/pdf/"></form>');
	form.append($('<input type="hidden" name="csrfmiddlewaretoken">').val(getCSRFToken()));
	$('body').append(form);
	form.submit();
}

function removeNotes(hashstr, i) {
	$.post('/report/api/rmnotes/'+hashstr+'/', {'csrfmiddlewaretoken': getCSRFToken()}).done(function(data) {
		if(data['ok'] == 'notes removed') {
			$('#noteshost'+i).remove();
		}
	});
}

function saveNotes() {
	var nb64 = encodeURIComponent(btoa($('#notes').val()));
	var csrftoken = $('input[name="csrfmiddlewaretoken"]').val();
	var hashstr = $('#hashstr').val();
	console.log(hashstr);
	$.post('/report/api/savenotes/', {
		'notes': nb64,
		'csrfmiddlewaretoken': csrftoken,
		'hashstr': hashstr
	 }).done(function(d) {
		console.log(d);
		if(typeof(d['ok']) !== 'undefined' && d['ok'] == 'notes saved') {
			$('#modalbody').html('<span class="green-text">Notes successfully saved!</span><br> Now this page needs a reload. Please, click on the &quot;Reload&quot; button.');
			$('#modalfooter').html('<button class="btn blue" onclick="javascript:location.reload();">Reload</button>');
		}
	});
}

function openNotes(hashstr, notesb64) {
	if(/^[a-f0-9]{32,32}$/.test(hashstr)) {
		var savednotes = '';
		if(notesb64 != '') {
			savednotes = atob(decodeURIComponent(notesb64));
		}
		$('#modal1').css('background-color','#3e3e3e');
		$('#modaltitle').html('Save Notes');
		$('#modalbody').html(
			'In the text area below, you can insert notes that will appear on the PDF report. '+
			'Notes are shown as plain text: HTML markup is displayed literally, not rendered.<br><br>'+
			'<textarea id="notes" style="color:#fff;min-height:160px;">'+escHTML(savednotes)+'</textarea>'+
			'<input type="hidden" id="hashstr" value="'+hashstr+'" />'
		);
		$('#modalfooter').html('<button onclick="javascript:saveNotes();" class="waves-effect waves-green btn grey white-text">Save</button>');
		$('#modal1').modal('open');
	}
}

function apiPortDetails(address, portid) {
	$.get('/report/api/'+encodeURIComponent(address)+'/'+encodeURIComponent(portid)+'/').done(function(data) {
		console.log(data);

		$('#modaltitle').html('Port Details: <span class="blue-text">'+$('<span/>').text(data['@portid']).html()+' / '+$('<span/>').text(data['@protocol']).html()+'</span>');

		var tbody = '';
		var ingorescriptid = {
			'fingerprint-strings':true
		}

		console.log(typeof(data['script']));
		if(typeof(data['script']) !== 'undefined') {
			if(typeof(data['script']) === 'object' && typeof(data['script']['@id']) === 'undefined') {
				for(var sid in data['script']) {
					if(typeof(ingorescriptid[data['script'][sid]['@id']]) !== 'undefined') { continue; }
					tbody += '<tr><td class="orange-text">'+$('<span/>').text(data['script'][sid]['@id']).html()+'</td><td style="font-family:monospace;font-size:12px;">'+$('<span/>').text(data['script'][sid]['@output']).html()+'</td></tr>'
				}
			} else {
				if(typeof(ingorescriptid[data['script']['@id']]) === 'undefined') {
					tbody += '<tr><td class="orange-text">'+$('<span/>').text(data['script']['@id']).html()+'</td><td style="font-family:monospace;font-size:12px;">'+$('<span/>').text(data['script']['@output']).html()+'</td></tr>'
				}
			}
		} else {
			tbody += '<tr><td><i>none</i></td><td><i>none</i></td></tr>'
		}

		$('#modal1').css('background-color','#3e3e3e');

		$('#modalbody').html('<table class="table"><thead><th style="min-width:200px;">Script ID</th><th>Output</th></thead><tbody>'+tbody+'</tbody></table>');
		$('#modalbody').append('<br><b>Raw Output:</b><br><pre>'+$('<span/>').text(JSON.stringify(data, null, 4)).html()+'</pre>');
		$('#modal1').modal('open');
	});
}

function removeLabel(type, hashstr, i) {
	$.post('/report/api/rmlabel/'+type+'/'+hashstr+'/', {'csrfmiddlewaretoken': getCSRFToken()}).done(function(data) {
		if(data['ok'] == 'label removed') {
			$('#hostlabel'+i).attr("class","");
			$('#hostlabel'+i).text("");
		}
	});
}

function setLabel(type, label, hashstr, i) {
	$.post('/report/api/setlabel/'+type+'/'+label+'/'+hashstr+'/', {'csrfmiddlewaretoken': getCSRFToken()}).done(function(data) {
		console.log(data);
		var res = data;
		var color = 'grey'; var margin = '10px';
		if(res['ok'] == 'label set') {
			switch(res['label']) {
				case 'Vulnerable': color = 'red'; margin = '10px'; break;
				case 'Critical': color = 'black'; margin = '22px'; break;
				case 'Warning': color = 'orange'; margin = '28px'; break;
				case 'Checked': color = 'blue'; margin = '28px'; break;
			}
			$('#hostlabel'+i).css("margin-left", margin);
			$('#hostlabel'+i).attr("class","");
			$('#hostlabel'+i).addClass('rightlabel');
			$('#hostlabel'+i).addClass(color);
			$('#hostlabel'+i).text(res['label']);
		}
	});
}
