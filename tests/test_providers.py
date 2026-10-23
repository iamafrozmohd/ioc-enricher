import unittest

from ioc_enricher.ioc import classify
from ioc_enricher.providers import AbuseIPDB, ProviderError, RateLimiter, VirusTotal


class FakeHTTP:
    """Records requests and returns canned (status, body) responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, url, headers):
        self.calls.append((url, headers))
        return self.responses.pop(0)


class NoWait:
    def wait(self):
        pass


def vt_body(malicious=0, suspicious=0, harmless=60, undetected=10, **extra):
    attrs = {"last_analysis_stats": {"malicious": malicious, "suspicious": suspicious,
                                     "harmless": harmless, "undetected": undetected}, **extra}
    return {"data": {"attributes": attrs}}


class VirusTotalTests(unittest.TestCase):
    def make(self, responses):
        http = FakeHTTP(responses)
        return VirusTotal("test-key", http_get=http, limiter=NoWait()), http

    def test_requires_key(self):
        with self.assertRaises(ProviderError):
            VirusTotal("")

    def test_endpoints_per_type(self):
        vt, http = self.make([(200, vt_body())] * 4)
        vt.lookup(classify("8.8.8.8"))
        vt.lookup(classify("example.com"))
        vt.lookup(classify("44d88612fea8a8f36de82e1278abb02f"))
        vt.lookup(classify("http://example.com/"))
        urls = [c[0] for c in http.calls]
        self.assertTrue(urls[0].endswith("/ip_addresses/8.8.8.8"))
        self.assertTrue(urls[1].endswith("/domains/example.com"))
        self.assertTrue(urls[2].endswith("/files/44d88612fea8a8f36de82e1278abb02f"))
        self.assertTrue(urls[3].endswith("/urls/aHR0cDovL2V4YW1wbGUuY29tLw"))
        self.assertEqual(http.calls[0][1], {"x-apikey": "test-key"})

    def test_parses_stats_and_hash_details(self):
        vt, _ = self.make([(200, vt_body(malicious=60, meaningful_name="eicar.com", type_description="Text",
                                         popular_threat_classification={"suggested_threat_label": "eicar/test"}))])
        r = vt.lookup(classify("44d88612fea8a8f36de82e1278abb02f"))
        self.assertTrue(r.found)
        self.assertEqual(r.data["malicious"], 60)
        self.assertEqual(r.data["threat_label"], "eicar/test")
        self.assertIn("/gui/file/", r.link)

    def test_not_found_and_bad_key(self):
        vt, _ = self.make([(404, {}), (401, {})])
        self.assertFalse(vt.lookup(classify("example.com")).found)
        with self.assertRaises(ProviderError):
            vt.lookup(classify("example.com"))

    def test_other_errors_are_reported_not_raised(self):
        vt, _ = self.make([(500, {"error": {"message": "server sad"}})])
        r = vt.lookup(classify("example.com"))
        self.assertFalse(r.found)
        self.assertEqual(r.error, "server sad")


class AbuseIPDBTests(unittest.TestCase):
    def test_parses_response(self):
        body = {"data": {"abuseConfidenceScore": 100, "totalReports": 512, "countryCode": "NL",
                         "isp": "Example Hosting", "usageType": "Data Center/Web Hosting/Transit",
                         "isWhitelisted": False}}
        http = FakeHTTP([(200, body)])
        r = AbuseIPDB("k", http_get=http).lookup(classify("203.0.113.7"))
        self.assertEqual(r.data["abuse_score"], 100)
        self.assertEqual(r.data["country"], "NL")
        self.assertIn("ipAddress=203.0.113.7", http.calls[0][0])
        self.assertEqual(http.calls[0][1]["Key"], "k")

    def test_bad_key_raises(self):
        with self.assertRaises(ProviderError):
            AbuseIPDB("k", http_get=FakeHTTP([(401, {})])).lookup(classify("203.0.113.7"))


class RateLimiterTests(unittest.TestCase):
    def test_spaces_calls(self):
        now = [100.0]
        slept = []
        limiter = RateLimiter(4, sleep=lambda s: (slept.append(s), now.__setitem__(0, now[0] + s)), clock=lambda: now[0])
        limiter.wait()
        now[0] += 5
        limiter.wait()
        self.assertEqual(slept, [10.0])  # 15s interval minus 5s already elapsed


if __name__ == "__main__":
    unittest.main()
