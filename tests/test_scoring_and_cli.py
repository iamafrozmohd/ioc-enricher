import contextlib
import io
import json
import os
import tempfile
import unittest

from ioc_enricher.cli import main
from ioc_enricher.ioc import IP, classify
from ioc_enricher.providers import ProviderResult
from ioc_enricher.report import to_csv, to_json, to_markdown, to_table
from ioc_enricher.scoring import (
    CLEAN,
    MALICIOUS,
    SUSPICIOUS,
    UNKNOWN,
    Enrichment,
    score,
)


def vt(mal=0, sus=0, harmless=60, undetected=10):
    return ProviderResult("VirusTotal", True, {"malicious": mal, "suspicious": sus,
                                               "harmless": harmless, "undetected": undetected})


def abuse(s, reports=10, whitelisted=False):
    return ProviderResult("AbuseIPDB", True, {"abuse_score": s, "total_reports": reports, "whitelisted": whitelisted,
                                              "country": "US"})


class ScoringTests(unittest.TestCase):
    def verdict(self, *results):
        return score(Enrichment(classify("203.0.113.7"), list(results))).verdict

    def test_thresholds(self):
        self.assertEqual(self.verdict(vt(mal=5)), MALICIOUS)
        self.assertEqual(self.verdict(vt(mal=1)), SUSPICIOUS)
        self.assertEqual(self.verdict(vt(sus=2)), SUSPICIOUS)
        self.assertEqual(self.verdict(vt()), CLEAN)
        self.assertEqual(self.verdict(abuse(90)), MALICIOUS)
        self.assertEqual(self.verdict(abuse(40)), SUSPICIOUS)
        self.assertEqual(self.verdict(abuse(0)), CLEAN)

    def test_worst_signal_wins(self):
        self.assertEqual(self.verdict(vt(), abuse(100)), MALICIOUS)
        self.assertEqual(self.verdict(vt(mal=1), abuse(0)), SUSPICIOUS)

    def test_unknown_when_nothing_found(self):
        e = score(Enrichment(classify("example.com"), [ProviderResult("VirusTotal", False)]))
        self.assertEqual(e.verdict, UNKNOWN)
        self.assertIn("No provider has seen this indicator", e.reasons)


class FakeProvider:
    def __init__(self, name, supports, result_fn):
        self.name, self.supports, self.result_fn = name, supports, result_fn
        self.seen = []

    def lookup(self, ioc):
        self.seen.append(ioc.value)
        return self.result_fn(ioc)


class CLITests(unittest.TestCase):
    def run_cli(self, argv, providers):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv, providers=providers)
        return code, out.getvalue(), err.getvalue()

    def providers(self):
        def vt_result(ioc):
            return vt(mal=40) if ioc.value == "1.2.3.4" else vt()
        return [FakeProvider("VirusTotal", {"ip", "domain", "url", "hash"}, vt_result),
                FakeProvider("AbuseIPDB", {IP}, lambda ioc: abuse(0))]

    def test_exit_code_and_private_ip_skipped(self):
        providers = self.providers()
        code, out, _ = self.run_cli(["1.2.3.4", "example.com", "192.168.1.5"], providers)
        self.assertEqual(code, 2)  # malicious indicator present
        self.assertIn("MALICIOUS", out)
        self.assertIn("SKIPPED", out)
        self.assertNotIn("192.168.1.5", providers[0].seen)
        self.assertEqual(providers[1].seen, ["1.2.3.4"])  # AbuseIPDB only gets public IPs

    def test_clean_run_exits_zero(self):
        code, _, _ = self.run_cli(["example.com"], self.providers())
        self.assertEqual(code, 0)

    def test_no_valid_iocs(self):
        code, _, err = self.run_cli(["nonsense"], self.providers())
        self.assertEqual(code, 1)
        self.assertIn("skipping unrecognised value", err)

    def test_writes_report_with_inferred_format(self):
        with tempfile.TemporaryDirectory() as tmp:
            for ext in ("json", "csv", "md"):
                path = os.path.join(tmp, f"report.{ext}")
                self.run_cli(["1.2.3.4", "-o", path], self.providers())
                with open(path, encoding="utf-8") as fh:
                    content = fh.read()
                self.assertIn("1.2.3.4", content)
            with open(os.path.join(tmp, "report.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["results"][0]["verdict"], MALICIOUS)

    def test_missing_key_message(self):
        os.environ.pop("VT_API_KEY", None)
        code, _, err = self.run_cli(["8.8.8.8", "--no-abuseipdb"], None)
        self.assertEqual(code, 1)
        self.assertIn("VT_API_KEY", err)


class ReportTests(unittest.TestCase):
    def test_renderers_sort_worst_first(self):
        es = [score(Enrichment(classify("example.com"), [vt()])),
              score(Enrichment(classify("1.2.3.4"), [vt(mal=10)]))]
        for render in (to_table, to_csv, to_markdown):
            text = render(es)
            self.assertLess(text.index("1.2.3.4"), text.index("example.com"), render.__name__)
        self.assertEqual(json.loads(to_json(es))["results"][0]["verdict"], MALICIOUS)


if __name__ == "__main__":
    unittest.main()
