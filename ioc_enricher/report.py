"""Render enrichment results as a console table, CSV, JSON or Markdown."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone

from .scoring import SEVERITY, Enrichment

COLORS = {"MALICIOUS": "\033[91m", "SUSPICIOUS": "\033[93m", "CLEAN": "\033[92m", "UNKNOWN": "\033[90m", "SKIPPED": "\033[90m"}
RESET = "\033[0m"


def _sorted(enrichments: list[Enrichment]) -> list[Enrichment]:
    return sorted(enrichments, key=lambda e: SEVERITY.get(e.verdict, 9))


def _summary_fields(e: Enrichment) -> dict:
    row = {"indicator": e.ioc.value, "type": e.ioc.label, "verdict": e.verdict,
           "vt_malicious": "", "vt_total": "", "abuse_score": "", "country": "", "details": "; ".join(e.reasons)}
    for r in e.results:
        if not r.found:
            continue
        d = r.data
        if r.provider == "VirusTotal":
            row["vt_malicious"] = d.get("malicious", 0)
            row["vt_total"] = sum(d.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
            row["country"] = row["country"] or d.get("country", "")
        elif r.provider == "AbuseIPDB":
            row["abuse_score"] = d.get("abuse_score", 0)
            row["country"] = d.get("country", "") or row["country"]
    return row


def to_table(enrichments: list[Enrichment], color: bool = False) -> str:
    rows = [_summary_fields(e) for e in _sorted(enrichments)]
    headers = ["Verdict", "Type", "Indicator", "VT", "Abuse%", "Country"]
    body = [[r["verdict"], r["type"], r["indicator"],
             f"{r['vt_malicious']}/{r['vt_total']}" if r["vt_total"] != "" else "-",
             str(r["abuse_score"]) if r["abuse_score"] != "" else "-",
             r["country"] or "-"] for r in rows]
    widths = [max(len(h), *(len(row[i]) for row in body)) if body else len(h) for i, h in enumerate(headers)]
    widths[2] = min(widths[2], 70)

    def fmt(cells, verdict=None):
        cells = [c if len(c) <= widths[i] else c[: widths[i] - 1] + "…" for i, c in enumerate(cells)]
        line = "  ".join(c.ljust(widths[i]) for i, c in enumerate(cells))
        if color and verdict:
            line = COLORS.get(verdict, "") + line + RESET
        return line

    out = [fmt(headers), "  ".join("-" * w for w in widths)]
    out += [fmt(cells, cells[0]) for cells in body]
    return "\n".join(out)


def to_csv(enrichments: list[Enrichment]) -> str:
    rows = [_summary_fields(e) for e in _sorted(enrichments)]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()) if rows else ["indicator"])
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def to_json(enrichments: list[Enrichment]) -> str:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "results": [
            {
                "indicator": e.ioc.value,
                "type": e.ioc.type,
                "subtype": e.ioc.subtype,
                "verdict": e.verdict,
                "reasons": e.reasons,
                "providers": {r.provider: {"found": r.found, "data": r.data, "error": r.error, "link": r.link}
                              for r in e.results},
            }
            for e in _sorted(enrichments)
        ],
    }
    return json.dumps(payload, indent=2)


def to_markdown(enrichments: list[Enrichment]) -> str:
    ordered = _sorted(enrichments)
    counts: dict[str, int] = {}
    for e in ordered:
        counts[e.verdict] = counts.get(e.verdict, 0) + 1
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# IOC Enrichment Report",
        "",
        f"Generated {generated} · {len(ordered)} indicators · "
        + ", ".join(f"{v}: {counts[v]}" for v in sorted(counts, key=lambda v: SEVERITY.get(v, 9))),
        "",
        "| Verdict | Type | Indicator | Evidence | Links |",
        "|---|---|---|---|---|",
    ]
    for e in ordered:
        links = " · ".join(f"[{r.provider}]({r.link})" for r in e.results if r.link)
        indicator = e.ioc.value.replace("|", "\\|")
        evidence = "<br>".join(e.reasons).replace("|", "\\|") or "-"
        lines.append(f"| **{e.verdict}** | {e.ioc.label} | `{indicator}` | {evidence} | {links or '-'} |")
    return "\n".join(lines) + "\n"


RENDERERS = {"table": to_table, "csv": to_csv, "json": to_json, "md": to_markdown}
