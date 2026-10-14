import base64, os, urllib.parse, unittest
from django.core.exceptions import ValidationError
from django.test import TestCase, Client
from nmapreport.functions import esc, jsstr, safeurl, safenotesb64, notestohtml
from nmapreport.security_utils import validate_notes_b64

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


@unittest.skipUnless(os.access('/opt/xml', os.W_OK) and os.access('/opt/notes', os.W_OK), 'needs writable /opt/xml and /opt/notes')
class ScanDataEscapingTests(TestCase):
	scanfile = 'webmap-test-xss.xml'

	def setUp(self):
		with open('/opt/xml/'+self.scanfile, 'w') as f:
			f.write(EVIL_XML)
		self.client = Client()
		self.client.get('/setscanfile/'+self.scanfile)

	def tearDown(self):
		os.remove('/opt/xml/'+self.scanfile)

	def test_pages_escape_scan_data(self):
		for url in ['/', '/10.0.0.5/', '/view/pdf/']:
			body = self.client.get(url).content.decode()
			for payload in ['<img src=x', '<svg onload']:
				self.assertNotIn(payload, body, url)

	def test_state_changes_require_post(self):
		self.assertEqual(self.client.get('/api/setlabel/host/Checked/'+'a'*32+'/').status_code, 405)
		self.assertEqual(self.client.get('/api/pdf/').status_code, 405)
