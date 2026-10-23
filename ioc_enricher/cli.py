"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .ioc import is_private_ip, parse_lines
from .providers import AbuseIPDB, ProviderError, ProviderResult, VirusTotal
from .report import RENDERERS, to_table
from .scoring import MALICIOUS, SKIPPED, Enrichment, score

EPILOG = """examples:
  python -m ioc_enricher 8.8.8.8 example.com
  python -m ioc_enricher -f samples/iocs.txt -o report.md --format md
  echo "hxxp://evil[.]example/payload" | python -m ioc_enricher -f -

API keys are read from the VT_API_KEY and ABUSEIPDB_API_KEY environment variables.
Exit code is 2 if any indicator is MALICIOUS, so the tool can gate scripts and pipelines."""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ioc_enricher",
        description="Enrich IPs, domains, URLs and file hashes with VirusTotal and AbuseIPDB threat intel.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("iocs", nargs="*", help="indicators to check (defanged forms like 1.2.3[.]4 are accepted)")
    p.add_argument("-f", "--file", help="file with one or more indicators per line ('-' for stdin)")
    p.add_argument("-o", "--output", help="write the report to this file instead of the console")
    p.add_argument("--format", choices=sorted(RENDERERS), default=None,
                   help="report format (default: table on screen, or inferred from --output extension)")
    p.add_argument("--no-vt", action="store_true", help="skip VirusTotal")
    p.add_argument("--no-abuseipdb", action="store_true", help="skip AbuseIPDB")
    p.add_argument("--vt-rate", type=float, default=4.0,
                   help="max VirusTotal requests per minute (free tier: 4, default: %(default)s)")
    p.add_argument("--include-private", action="store_true",
                   help="also look up private/internal IPs (skipped by default; public intel has nothing on them)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _infer_format(output: str | None, explicit: str | None) -> str:
    if explicit:
        return explicit
    if output:
        ext = os.path.splitext(output)[1].lower().lstrip(".")
        return {"csv": "csv", "json": "json", "md": "md", "markdown": "md"}.get(ext, "table")
    return "table"


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def main(argv=None, providers=None) -> int:
    args = build_parser().parse_args(argv)

    lines = list(args.iocs)
    if args.file:
        if args.file == "-":
            lines += sys.stdin.read().splitlines()
        else:
            with open(args.file, encoding="utf-8") as fh:
                lines += fh.read().splitlines()
    iocs, rejected = parse_lines(lines)
    for token in rejected:
        _log(f"[!] skipping unrecognised value: {token}")
    if not iocs:
        _log("No valid indicators supplied. Run with -h for usage.")
        return 1

    if providers is None:
        providers = []
        try:
            if not args.no_vt:
                providers.append(VirusTotal(os.environ.get("VT_API_KEY", ""), per_minute=args.vt_rate))
            if not args.no_abuseipdb:
                providers.append(AbuseIPDB(os.environ.get("ABUSEIPDB_API_KEY", "")))
        except ProviderError as exc:
            _log(f"[x] {exc}. Use --no-vt / --no-abuseipdb to skip a provider.")
            return 1
    if not providers:
        _log("[x] All providers are disabled; nothing to do.")
        return 1

    enrichments: list[Enrichment] = []
    for i, ioc in enumerate(iocs, 1):
        e = Enrichment(ioc)
        if is_private_ip(ioc) and not args.include_private:
            e.verdict, e.reasons = SKIPPED, ["Private/reserved IP: not checked against public intel"]
            enrichments.append(e)
            continue
        _log(f"[{i}/{len(iocs)}] {ioc.label:<12} {ioc.value}")
        for provider in providers:
            if ioc.type not in provider.supports:
                continue
            try:
                e.results.append(provider.lookup(ioc))
            except ProviderError as exc:
                if "API key" in str(exc):
                    _log(f"[x] {exc}")
                    return 1
                e.results.append(ProviderResult(provider.name, found=False, error=str(exc)))
        enrichments.append(score(e))

    fmt = _infer_format(args.output, args.format)
    if args.output:
        report = RENDERERS[fmt](enrichments)
        with open(args.output, "w", encoding="utf-8", newline="") as fh:
            fh.write(report)
        _log(f"[+] Report written to {args.output}")
        _log(to_table(enrichments, color=sys.stderr.isatty()))
    elif fmt == "table":
        print(to_table(enrichments, color=sys.stdout.isatty()))
    else:
        print(RENDERERS[fmt](enrichments))

    return 2 if any(e.verdict == MALICIOUS for e in enrichments) else 0
