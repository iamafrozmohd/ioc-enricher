import unittest

from ioc_enricher.ioc import (
    DOMAIN,
    HASH,
    IP,
    URL,
    classify,
    is_private_ip,
    parse_lines,
    refang,
)


class RefangTests(unittest.TestCase):
    def test_common_defang_styles(self):
        self.assertEqual(refang("hxxp://evil[.]example/payload"), "http://evil.example/payload")
        self.assertEqual(refang("hxxps://bad(.)example"), "https://bad.example")
        self.assertEqual(refang("10[.]0[.]0[.]1"), "10.0.0.1")
        self.assertEqual(refang("evil[dot]example"), "evil.example")
        self.assertEqual(refang("  'example.com'  "), "example.com")


class ClassifyTests(unittest.TestCase):
    def test_ipv4_and_ipv6(self):
        self.assertEqual(classify("8.8.8.8").type, IP)
        self.assertEqual(classify("8.8.8.8").subtype, "v4")
        self.assertEqual(classify("2001:4860:4860::8888").subtype, "v6")

    def test_hashes(self):
        self.assertEqual(classify("44d88612fea8a8f36de82e1278abb02f").subtype, "md5")
        self.assertEqual(classify("3395856ce81f2b7382dee72602f798b642f14140").subtype, "sha1")
        sha256 = "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F"
        ioc = classify(sha256)
        self.assertEqual((ioc.type, ioc.subtype), (HASH, "sha256"))
        self.assertEqual(ioc.value, sha256.lower())

    def test_url_and_domain(self):
        self.assertEqual(classify("https://example.com/a?b=c").type, URL)
        self.assertEqual(classify("Sub.Example.COM").value, "sub.example.com")
        self.assertEqual(classify("example.com").type, DOMAIN)

    def test_rejects_garbage(self):
        for value in ["", "hello", "999.1.1.1", "abc123", "-bad-.com", "notahash12345"]:
            self.assertIsNone(classify(value), value)


class PrivateIpTests(unittest.TestCase):
    def test_private_ranges(self):
        for value in ["10.1.2.3", "192.168.1.10", "172.16.5.5", "127.0.0.1", "169.254.1.1", "::1"]:
            self.assertTrue(is_private_ip(classify(value)), value)
        self.assertFalse(is_private_ip(classify("8.8.8.8")))
        self.assertFalse(is_private_ip(classify("example.com")))


class ParseLinesTests(unittest.TestCase):
    def test_dedupes_skips_comments_and_reports_rejects(self):
        lines = [
            "# comment line",
            "",
            "8.8.8.8, 8.8.8.8 1.1.1.1",
            "hxxp://evil[.]example/x",
            "not_an_ioc",
            "EXAMPLE.com example.com",
        ]
        iocs, rejected = parse_lines(lines)
        self.assertEqual([i.value for i in iocs], ["8.8.8.8", "1.1.1.1", "http://evil.example/x", "example.com"])
        self.assertEqual(rejected, ["not_an_ioc"])

    def test_inline_comments_and_url_fragments(self):
        iocs, rejected = parse_lines(["192.168.1.10   # private, skipped", "https://example.com/page#top"])
        self.assertEqual([i.value for i in iocs], ["192.168.1.10", "https://example.com/page#top"])
        self.assertEqual(rejected, [])


if __name__ == "__main__":
    unittest.main()
