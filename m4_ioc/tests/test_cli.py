import unittest
from m4_ioc.cli import defang_url, defang_ip, defang_domain

class TestDefang(unittest.TestCase):
    def test_defang_url(self):
        self.assertEqual(defang_url("http://c2.example/gate"), "hxxp://c2[.]example/gate")
        self.assertEqual(defang_url("https://malicious.com"), "hxxps://malicious[.]com")

    def test_defang_ip(self):
        self.assertEqual(defang_ip("192.168.1.1"), "192[.]168[.]1[.]1")

    def test_defang_domain(self):
        self.assertEqual(defang_domain("malware.c2.net"), "malware[.]c2[.]net")
