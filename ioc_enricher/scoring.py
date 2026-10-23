"""Turn raw provider results into a single analyst-friendly verdict."""

from __future__ import annotations

from dataclasses import dataclass, field

from .ioc import IOC
from .providers import ProviderResult

MALICIOUS = "MALICIOUS"
SUSPICIOUS = "SUSPICIOUS"
CLEAN = "CLEAN"
UNKNOWN = "UNKNOWN"
SKIPPED = "SKIPPED"

# Sort order for reports: worst first.
SEVERITY = {MALICIOUS: 0, SUSPICIOUS: 1, UNKNOWN: 2, CLEAN: 3, SKIPPED: 4}

# Thresholds are deliberately simple and documented so an analyst can reason about them.
VT_MALICIOUS_HIGH = 3     # >= 3 engines flag it malicious -> MALICIOUS
ABUSE_SCORE_HIGH = 75     # AbuseIPDB confidence >= 75% -> MALICIOUS
ABUSE_SCORE_MEDIUM = 25   # AbuseIPDB confidence >= 25% -> SUSPICIOUS


@dataclass
class Enrichment:
    ioc: IOC
    results: list[ProviderResult] = field(default_factory=list)
    verdict: str = UNKNOWN
    reasons: list[str] = field(default_factory=list)


def score(enrichment: Enrichment) -> Enrichment:
    reasons: list[str] = []
    level = None
    any_found = False

    def raise_to(new_level: str) -> None:
        nonlocal level
        if level is None or SEVERITY[new_level] < SEVERITY[level]:
            level = new_level

    for result in enrichment.results:
        if not result.found:
            continue
        any_found = True
        d = result.data
        if result.provider == "VirusTotal":
            mal, sus = d.get("malicious", 0), d.get("suspicious", 0)
            total = mal + sus + d.get("harmless", 0) + d.get("undetected", 0)
            if mal >= VT_MALICIOUS_HIGH:
                raise_to(MALICIOUS)
                reasons.append(f"VirusTotal: {mal}/{total} engines flag as malicious")
            elif mal >= 1 or sus >= 2:
                raise_to(SUSPICIOUS)
                reasons.append(f"VirusTotal: {mal} malicious, {sus} suspicious of {total} engines")
            else:
                raise_to(CLEAN)
            if d.get("threat_label"):
                reasons.append(f"VirusTotal threat label: {d['threat_label']}")
        elif result.provider == "AbuseIPDB":
            s = d.get("abuse_score", 0)
            if d.get("whitelisted"):
                raise_to(CLEAN)
                reasons.append("AbuseIPDB: on AbuseIPDB whitelist")
            elif s >= ABUSE_SCORE_HIGH:
                raise_to(MALICIOUS)
                reasons.append(f"AbuseIPDB: {s}% abuse confidence ({d.get('total_reports', 0)} reports)")
            elif s >= ABUSE_SCORE_MEDIUM:
                raise_to(SUSPICIOUS)
                reasons.append(f"AbuseIPDB: {s}% abuse confidence ({d.get('total_reports', 0)} reports)")
            else:
                raise_to(CLEAN)

    if not any_found:
        level = UNKNOWN
        errors = [f"{r.provider}: {r.error}" for r in enrichment.results if r.error]
        reasons.extend(errors or ["No provider has seen this indicator"])

    enrichment.verdict = level or UNKNOWN
    enrichment.reasons = reasons
    return enrichment
