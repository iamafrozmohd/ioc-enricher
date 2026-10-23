# IOC Enricher

![CI](https://github.com/iamafrozmohd/ioc-enricher/actions/workflows/ci.yml/badge.svg)

A command-line tool for SOC analysts: paste in the IPs, domains, URLs and file hashes from an alert, and get back a single **MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN** verdict for each one, backed by **VirusTotal** and **AbuseIPDB** threat intelligence.

It turns ten minutes of copy-pasting into browser tabs during triage into one command, and writes a report you can attach to the ticket.

## Features
- **Auto-detects indicator type:** IPv4/IPv6, domains, URLs, and MD5 / SHA-1 / SHA-256 hashes
- **Refangs automatically:** accepts analyst-style defanged input like `hxxps://evil[.]example` and `10[.]0[.]0[.]1`
- **Skips private IPs** (RFC 1918, loopback, link-local, reserved) since public intel has nothing on them, and avoids leaking internal addressing to third parties
- **Deduplicates** input and accepts files, stdin, or arguments, with `#` comments
- **Respects API rate limits** (VirusTotal free tier: 4 requests/minute) and retries politely on HTTP 429
- **Reports in four formats:** colored console table, CSV, JSON, and Markdown (ready to paste into a ticket)
- **Pipeline-friendly exit codes:** `2` if anything is malicious, `0` otherwise
- **Zero dependencies:** Python standard library only

## Quick start
```bash
git clone https://github.com/iamafrozmohd/ioc-enricher.git
cd ioc-enricher

# Free API keys: virustotal.com (Profile > API Key) and abuseipdb.com (Account > API)
export VT_API_KEY="your-virustotal-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"

python -m ioc_enricher -f samples/iocs.txt
```
On Windows PowerShell, set keys with `$env:VT_API_KEY="..."`. Or install it as a command with `pip install .` and run `ioc-enricher`.

## Usage
```bash
# Check a few indicators directly
python -m ioc_enricher 8.8.8.8 example.com 44d88612fea8a8f36de82e1278abb02f

# Check a list and save a Markdown report for the ticket (format inferred from extension)
python -m ioc_enricher -f iocs.txt -o report.md

# Pipe indicators in, output JSON for another tool
cat alert_iocs.txt | python -m ioc_enricher -f - --format json

# Only have a VirusTotal key? Skip AbuseIPDB
python -m ioc_enricher -f iocs.txt --no-abuseipdb
```
Run `python -m ioc_enricher -h` for all options.

## Example output
A real run against [`samples/iocs.txt`](samples/iocs.txt) on Oct 23, 2026 (live results change over time):
```text
Verdict    Type         Indicator                                                         VT     Abuse%  Country
---------  -----------  ----------------------------------------------------------------  -----  ------  -------
MALICIOUS  hash/sha256  275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f  66/68  -       -
CLEAN      ip/v4        8.8.8.8                                                           0/92   0       US
CLEAN      ip/v4        1.1.1.1                                                           0/92   0       AU
CLEAN      domain       example.com                                                       0/92   -       -
CLEAN      url          https://example.com/login                                         0/93   -       -
SKIPPED    ip/v4        192.168.1.10                                                      -      -       -
```
The SHA-256 is the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/), a harmless string that antivirus engines flag on purpose, so it's a safe way to see a MALICIOUS result.

## How verdicts are decided
The worst signal from any provider wins. Thresholds live in [`scoring.py`](ioc_enricher/scoring.py) and are intentionally simple so an analyst can explain them:

| Verdict | Rule |
|---|---|
| **MALICIOUS** | 3+ VirusTotal engines flag it malicious, or AbuseIPDB confidence is 75% or higher |
| **SUSPICIOUS** | 1–2 VirusTotal malicious detections, 2+ suspicious detections, or AbuseIPDB confidence 25–74% |
| **CLEAN** | Seen by a provider with no meaningful detections (or on AbuseIPDB's whitelist) |
| **UNKNOWN** | No provider has data on it. Unknown is not the same as safe: brand-new infrastructure often has no reputation yet |
| **SKIPPED** | Private/reserved IP, not sent to public intel |

## Design notes
- **OPSEC:** only indicators are sent to the APIs. Private IPs are never sent unless you pass `--include-private`. Note that looking up a URL or domain on VirusTotal makes it visible to others with VT access, so don't submit sensitive internal URLs.
- **Secrets:** API keys come only from environment variables and are never logged or written to reports. CI fails if anything that looks like a hard-coded key is committed.
- **Testable by design:** HTTP calls are injectable, so the test suite runs fully offline with canned API responses.

## Project layout
```
ioc_enricher/
  ioc.py         parsing, refanging, type detection, private-IP filtering
  providers.py   VirusTotal v3 and AbuseIPDB v2 clients, rate limiting, retries
  scoring.py     verdict logic
  report.py      table / CSV / JSON / Markdown output
  cli.py         command-line interface
tests/           25 offline unit tests (unittest)
samples/         safe sample indicators
```

## CI pipeline
Every push runs: unit tests on Python 3.10, 3.12 and 3.13 · `ruff` lint · `bandit` security scan · a check for hard-coded API keys.

Run the tests locally:
```bash
python -m unittest discover -s tests -t . -v
```

## Roadmap
- [ ] Add more sources (AlienVault OTX, URLhaus, Shodan)
- [ ] Local cache so repeat lookups don't burn API quota
- [ ] Extract IOCs straight from an email (.eml) or alert JSON

## Disclaimer
Threat intel is a signal, not proof. A CLEAN result doesn't mean an indicator is safe, and a single detection can be a false positive. Use it to speed up triage, not to replace analyst judgment.

---
*Author: Afroz Mohammed · [LinkedIn](https://www.linkedin.com/in/iamafrozmohd)*
