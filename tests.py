import base64, glob, json, os, stat, tempfile, urllib.parse, unittest
from unittest import mock
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, Client
from django.urls import resolve
from nmapreport import api
from nmapreport.functions import esc, jsstr, safeurl, safenotesb64, notestohtml, shellcmd
from nmapreport.scan import host_address, filter_cves, load_scan, md5
from nmapreport.security_utils import validate_notes_b64, validate_cpe_string, validate_ip_address, validate_host_address

EVIL_XML = '''<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV &lt;b&gt;" start="1" startstr="Mon" version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1" services="80"/>
<host><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="10.0.0.5" addrtype="ipv4"/>
<hostnames><hostname name="&lt;img src=x onerror=alert(1)&gt;" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="0"/>
<service name="&lt;img src=x onerror=alert(2)&gt;" product="&lt;svg onload=alert(3)&gt;" version="1" extrainfo="&lt;i&gt;" ostype="Linux" method="probed" conf="10"><cpe>cpe:/a:x:y:1</cpe></service></port></ports>
</host><runstats><finished time="2" timestr="Mon" elapsed="1" summary="x" exit="success"/><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
'''

def nmaprun(hosts, scaninfo='<scaninfo type="syn" protocol="tcp" numservices="1" services="22"/>', start='1'):
	return '<?xml version="1.0"?>\n<nmaprun scanner="nmap" args="nmap" start="'+start+'" startstr="Mon" version="7.94" xmloutputversion="1.05">'+\
	scaninfo+''.join(hosts)+'<runstats><finished time="2"/></runstats></nmaprun>\n'

def host(addresses, ports=''):
	return '<host><status state="up" reason="syn-ack" reason_ttl="0"/>'+addresses+'<hostnames/><ports>'+ports+'</ports></host>'

def port(portid, cpes=(), protocol='tcp', name='svc'):
	return '<port protocol="'+protocol+'" portid="'+portid+'"><state state="open" reason="syn-ack" reason_ttl="0"/>'+\
	'<service name="'+name+'" product="p" version="1">'+''.join('<cpe>'+c+'</cpe>' for c in cpes)+'</service></port>'

IPV4 = lambda a: '<address addr="'+a+'" addrtype="ipv4"/>'
IPV6 = lambda a: '<address addr="'+a+'" addrtype="ipv6"/>'
MAC = lambda a: '<address addr="'+a+'" addrtype="mac"/>'


def b64notes(text):
	return urllib.parse.quote(base64.b64encode(text.encode('utf-8')).decode())


class HelperTests(unittest.TestCase):
	def test_esc(self):
		self.assertEqual(esc('<a "x">'), '&lt;a &quot;x&quot;&gt;')

	def test_jsstr_cannot_close_script(self):
		self.assertNotIn('</script>', jsstr('</script><script>alert(1)'))
		self.assertEqual(jsstr('a"b'), '"a\\"b"')

	def test_safeurl(self):
		self.assertEqual(safeurl('javascript:alert(1)'), '#')
		self.assertEqual(safeurl('https://x/?a="b"'), 'https://x/?a=&quot;b&quot;')

	def test_notes(self):
		self.assertEqual(safenotesb64("x');alert(1);//"), '')
		self.assertEqual(notestohtml(b64notes('<script>ż')), '&lt;script&gt;ż')
		self.assertEqual(validate_notes_b64(b64notes('ok')), b64notes('ok'))
		with self.assertRaises(ValidationError):
			validate_notes_b64("x');alert(1);//")

	# N-04
	def test_shellcmd_quotes_arguments(self):
		self.assertEqual(shellcmd('telnet', "10.0.0.1'; id #", '80'), "telnet '10.0.0.1'\"'\"'; id #' 80")

	# N-05
	def test_cpe_cannot_traverse(self):
		self.assertEqual(validate_cpe_string('cpe:/a:openbsd:openssh:7.6p1'), 'cpe:/a:openbsd:openssh:7.6p1')
		for bad in ['cpe:/a:x:y:../../../../api/last', 'cpe:/a:x:y/../../z', 'cpe:/a:x:%2e%2e', 'cpe:/a:x:..']:
			with self.assertRaises(ValidationError, msg=bad):
				validate_cpe_string(bad)

	def test_filter_cves(self):
		self.assertEqual(filter_cves(['a', {'id': 1}, {'id': 'CVE-1'}]), [{'id': 'CVE-1'}])
		self.assertEqual(filter_cves({'id': 'CVE-1'}), [])

	# N-07
	def test_addresses(self):
		self.assertEqual(validate_ip_address('fe80::1'), 'fe80::1')
		self.assertEqual(validate_host_address('00:11:22:33:44:55'), '00:11:22:33:44:55')
		with self.assertRaises(ValidationError):
			validate_host_address("10.0.0.1');alert(1)//")
		self.assertEqual(host_address({'address': [{'@addrtype': 'mac', '@addr': '00:11:22:33:44:55'}, {'@addrtype': 'ipv6', '@addr': 'fe80::1'}]}), 'fe80::1')
		self.assertIsNone(host_address({'address': [{'@addrtype': 'ipv4', '@addr': 'x<y'}]}))
		self.assertIsNone(host_address({'address': []}))


@unittest.skipUnless(os.access('/opt/xml', os.W_OK) and os.access('/opt/notes', os.W_OK), 'needs writable /opt/xml and /opt/notes')
class ScanDataTests(TestCase):
	scanfile = 'webmap-test.xml'
	xml = EVIL_XML

	def setUp(self):
		self.created = []
		self.write(self.scanfile, self.xml)
		self.user = get_user_model().objects.create_user('tester', password='x-Test-Password-1')
		self.client = Client()
		self.client.force_login(self.user)
		self.select(self.scanfile)

	def tearDown(self):
		for f in self.created:
			if os.path.exists(f):
				os.remove(f)
		for f in glob.glob('/opt/notes/*'):
			if f.endswith(('.label', '.notes', '.cve')) and os.path.getmtime(f) >= self.started:
				os.remove(f)

	@classmethod
	def setUpClass(cls):
		super().setUpClass()
		import time
		cls.started = time.time() - 1

	def write(self, name, content):
		path = '/opt/xml/'+name
		with open(path, 'w') as f:
			f.write(content)
		self.created.append(path)

	def select(self, name):
		return self.client.post('/setscanfile/'+urllib.parse.quote(name))

	def get(self, url, status=200):
		resp = self.client.get(url)
		self.assertEqual(resp.status_code, status, url)
		return resp.content.decode()


class EscapingTests(ScanDataTests):
	def test_pages_escape_scan_data(self):
		for url in ['/', '/10.0.0.5/', '/view/pdf/']:
			body = self.get(url)
			for payload in ['<img src=x', '<svg onload']:
				self.assertNotIn(payload, body, url)

	def test_state_changes_require_post(self):
		self.assertEqual(self.client.get('/api/setlabel/host/Checked/'+'a'*32+'/').status_code, 405)
		self.assertEqual(self.client.get('/api/pdf/').status_code, 405)
		self.assertEqual(self.client.get('/setscanfile/'+self.scanfile).status_code, 405)


# K-01
class AuthTests(ScanDataTests):
	def test_anonymous_is_redirected_to_login(self):
		anon = Client()
		for url in ['/', '/10.0.0.5/', '/view/pdf/', '/api/10.0.0.5/80/', '/report/']:
			resp = anon.get(url)
			self.assertEqual(resp.status_code, 302, url)
			self.assertTrue(resp['Location'].startswith('/login/'), url)
		self.assertEqual(anon.post('/api/pdf/').status_code, 302)
		self.assertEqual(anon.get('/login/').status_code, 200)

	def test_admin_not_routed(self):
		self.assertEqual(resolve('/admin/').url_name, 'details')

	def test_login(self):
		c = Client()
		resp = c.post('/login/', {'username': 'tester', 'password': 'x-Test-Password-1'})
		self.assertEqual(resp.status_code, 302)
		self.assertEqual(c.get('/').status_code, 200)


# N-01
class FileNameTests(ScanDataTests):
	def test_js_escape_file_name_is_not_selectable(self):
		evil = '\\x3cimg src=x onerror=alert(1)\\x3e.xml'
		self.write(evil, EVIL_XML)
		self.select('unset')
		self.select(evil)
		self.assertNotIn('scanfile', self.client.session)
		body = self.get('/')
		self.assertNotIn('\\x3cimg', body)

	def test_title_rendered_as_text(self):
		body = self.get('/')
		self.assertIn('id="scantitle">webmap-test.xml</div>', body)
		self.assertNotIn('#scantitle").html', body)


# N-02
class ThirdPartyScriptTests(ScanDataTests):
	def test_no_external_scripts(self):
		for url in ['/', '/view/pdf/']:
			body = self.get(url)
			self.assertNotRegex(body, r'<script[^>]+src="(https?:)?//', url)
		self.assertNotIn('<script', self.get('/view/pdf/'))
		self.assertNotIn('buttons.github.io', self.get('/'))
		self.assertNotIn('google.com/jsapi', self.get('/view/pdf/'))


# N-03
class CPETests(ScanDataTests):
	xml = nmaprun([host(IPV4('10.0.0.2'),
		port('22', ['cpe:/a:openbsd:openssh:7.6', 'cpe:/o:linux:linux_kernel']) +
		port('80', ['cpe:/a:apache:http_server:2.4.29']) +
		port('443'))])

	def cpestring(self):
		body = self.get('/')
		value = body.split('id="cpestring" value="')[1].split('"')[0]
		return json.loads(base64.b64decode(urllib.parse.unquote_plus(value)))

	def test_all_ports_with_cpe_are_collected(self):
		self.assertEqual(self.cpestring(), {'10.0.0.2': {
			'22': {'cpe:/a:openbsd:openssh:7.6': 'cpe:/a:openbsd:openssh:7.6', 'cpe:/o:linux:linux_kernel': 'cpe:/o:linux:linux_kernel'},
			'80': {'cpe:/a:apache:http_server:2.4.29': 'cpe:/a:apache:http_server:2.4.29'},
		}})

	def fake_api(self, url, **kw):
		r = mock.Mock()
		r.raise_for_status.return_value = None
		r.json.return_value = [{'id': 'CVE-'+url.rsplit(':', 2)[-2], 'summary': 's'}]
		self.urls.append(url)
		return r

	def test_cpes_on_one_port_do_not_overwrite(self):
		self.urls = []
		with mock.patch('nmapreport.api.requests.get', side_effect=self.fake_api):
			for c in ['cpe:/a:openbsd:openssh:7.6', 'cpe:/o:linux:linux_kernel']:
				d = self.client.post('/api/getcve/', {'host': '10.0.0.2', 'port': '22', 'cpe': c}).json()
				self.assertIn('10.0.0.2', d, d)
		body = self.get('/10.0.0.2/')
		self.assertIn('CVE-openssh', body)
		self.assertIn('CVE-linux', body)
		self.assertIn('2 CVE found', self.get('/'))

	# N-05
	def test_getcve_only_for_cpes_in_scan(self):
		self.urls = []
		with mock.patch('nmapreport.api.requests.get', side_effect=self.fake_api):
			for data in [
				{'host': '10.0.0.2', 'port': '80', 'cpe': 'cpe:/a:openbsd:openssh:7.6'},
				{'host': '10.0.0.9', 'port': '22', 'cpe': 'cpe:/a:openbsd:openssh:7.6'},
				{'host': '10.0.0.2', 'port': '22', 'cpe': 'cpe:/a:x:y:../../../../api/last'},
			]:
				self.assertIn('error', self.client.post('/api/getcve/', data).json(), data)
		self.assertEqual(self.urls, [])

	def test_malformed_cve_file_does_not_break_pages(self):
		key = load_scan(self.scanfile).key
		with open('/opt/notes/'+key+'_'+md5('10.0.0.2')+'.22.'+md5('x')+'.cve', 'w') as f:
			f.write('["a", "b"]')
		with open('/opt/notes/'+key+'_'+md5('10.0.0.2')+'.80.cve', 'w') as f:
			f.write('{not json')
		for url in ['/', '/10.0.0.2/', '/view/pdf/']:
			self.get(url)


# N-04
class PortMarkupTests(ScanDataTests):
	xml = nmaprun([host(IPV4('10.0.0.6'), port('80') + port("81');alert(1);//"))])

	def test_no_inline_js_and_crafted_port_skipped(self):
		body = self.get('/10.0.0.6/')
		self.assertNotIn('alert(1)', body)
		self.assertNotIn('apiPortDetails(', body)
		self.assertIn('data-address="10.0.0.6" data-portid="80"', body)
		self.assertIn("data-clipboard-text=\"telnet 10.0.0.6 80\"", body)


# N-06
class ScanIdentityTests(ScanDataTests):
	xml = nmaprun([host(IPV4('10.0.0.7'), port('22'))], start='100')

	def test_label_does_not_carry_over_to_new_scan_with_same_name(self):
		h = md5('10.0.0.7')
		self.assertEqual(self.client.post('/api/setlabel/host/Checked/'+h+'/').json()['ok'], 'label set')
		self.assertIn('rightlabel blue">Checked</span>', self.get('/'))

		self.write(self.scanfile, nmaprun([host(IPV4('10.0.0.7'), port('22') + port('3389'))], start='200'))
		self.assertNotIn('rightlabel blue">Checked</span>', self.get('/'))


# N-07
class AddressTests(ScanDataTests):
	xml = nmaprun([
		host(IPV6('fe80::1') + MAC('00:11:22:33:44:55'), port('22')),
		host(IPV4('10.0.0.4'), port('22')),
		host(IPV6('fe80::2'), port('22')),
		host(MAC('00:11:22:33:44:66'), port('22')),
		host('', port('22')),
	])

	def test_hosts_without_ipv4(self):
		body = self.get('/')
		self.assertEqual(body.count('href="/report/10.0.0.4"'), 1)
		for a in ['fe80::1', 'fe80::2', '00:11:22:33:44:66']:
			self.assertIn('href="/report/'+a+'"', body)
		self.assertIn('data-address="fe80::1"', self.get('/fe80::1/'))
		self.assertIn("http://[fe80::1]:22", self.get('/fe80::1/'))
		self.assertEqual(self.client.get('/api/fe80::1/22/').json()['@portid'], '22')
		self.get('/view/pdf/')


# N-08
class ParserRobustnessTests(ScanDataTests):
	xml = nmaprun([host(IPV4('10.0.0.8'), port('53') + port('53', protocol='udp', name='domain'))],
		scaninfo='<scaninfo type="syn" protocol="tcp" numservices="1" services="53"/><scaninfo type="udp" protocol="udp" numservices="1" services="53"/>')

	def test_multiple_scaninfo(self):
		self.assertIn('syn, udp', self.get('/'))
		self.assertIn('syn, udp', self.get('/view/pdf/'))
		self.get('/10.0.0.8/')

	def test_partial_file_does_not_break_scan_list(self):
		self.write('webmap-test-running.xml', self.xml[:200])
		self.select('unset')
		body = self.get('/')
		self.assertIn('webmap-test-running.xml', body)
		self.assertIn('not valid XML', body)
		self.select('webmap-test-running.xml')
		self.get('/', status=400)
		self.get('/view/pdf/', status=400)

	def test_empty_scan(self):
		self.write('webmap-test-empty.xml', nmaprun([]))
		self.select('webmap-test-empty.xml')
		self.assertIn('HOSTS UP', self.get('/'))
		self.get('/view/pdf/')


# N-09, F-08
class PDFTests(ScanDataTests):
	def setUp(self):
		super().setUp()
		self.tmp = tempfile.mkdtemp()
		self.log = os.path.join(self.tmp, 'log')
		fake = os.path.join(self.tmp, 'wkhtmltopdf')
		with open(fake, 'w') as f:
			f.write('#!/bin/sh\nprintf "%s\\n" "$@" > '+self.log+'.argv\ncat > '+self.log+'.stdin\nprintf "%%PDF-1.4 fake"\n')
		os.chmod(fake, stat.S_IRWXU)
		self.patch = mock.patch.object(api, 'WKHTMLTOPDF', fake)
		self.patch.start()

	def tearDown(self):
		self.patch.stop()
		super().tearDown()

	def test_pdf_rendered_from_stdin_without_session_or_js(self):
		resp = self.client.post('/api/pdf/')
		self.assertEqual(resp.status_code, 200)
		self.assertEqual(resp['Content-Type'], 'application/pdf')
		self.assertEqual(resp.content, b'%PDF-1.4 fake')

		argv = open(self.log+'.argv').read().split('\n')
		self.assertNotIn('--cookie', argv)
		self.assertNotIn(self.client.session.session_key, argv)
		self.assertIn('--disable-javascript', argv)
		self.assertEqual(argv[-3:-1], ['-', '-'])
		self.assertFalse([a for a in argv if a.startswith('http')])

		html = open(self.log+'.stdin').read()
		self.assertIn('Port Scan Report', html)
		self.assertNotIn('<script', html)
		self.assertNotRegex(html, r'(src|href)="(https?:)?//[^"]*\.(js|css)')

	def test_concurrent_generation_is_refused(self):
		api._pdf_lock.acquire()
		try:
			self.assertEqual(self.client.post('/api/pdf/').status_code, 429)
		finally:
			api._pdf_lock.release()

	def test_no_pdf_written_to_static(self):
		self.client.post('/api/pdf/')
		self.assertEqual(glob.glob(os.path.join(os.path.dirname(api.__file__), 'static', '*.pdf')), [])
