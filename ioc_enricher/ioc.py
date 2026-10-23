"""Parse, refang and classify indicators of compromise (IOCs)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

IP = "ip"
DOMAIN = "domain"
URL = "url"
HASH = "hash"

HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)([a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$"
)
URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)
INLINE_COMMENT = re.compile(r"\s+#.*$")

# Common "defanging" styles analysts use so IOCs aren't clickable in tickets/chat.
_REFANG_RULES = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"^hxxp", re.IGNORECASE), "http"),
    (re.compile(r"^fxp", re.IGNORECASE), "ftp"),
]


@dataclass(frozen=True)
class IOC:
    value: str
    type: str
    subtype: str = ""

    @property
    def label(self) -> str:
        return f"{self.type}/{self.subtype}" if self.subtype else self.type


def refang(value: str) -> str:
    """Turn a defanged indicator like hxxp://evil[.]com back into a usable value."""
    value = value.strip().strip("'\"<>")
    for pattern, replacement in _REFANG_RULES:
        value = pattern.sub(replacement, value)
    return value


def classify(raw: str) -> IOC | None:
    """Return an IOC for a raw string, or None if it isn't a recognisable indicator."""
    value = refang(raw)
    if not value:
        return None

    try:
        ip = ipaddress.ip_address(value)
        return IOC(str(ip), IP, f"v{ip.version}")
    except ValueError:
        pass

    for name, pattern in HASH_PATTERNS.items():
        if pattern.match(value):
            return IOC(value.lower(), HASH, name)

    if URL_PATTERN.match(value):
        return IOC(value, URL)

    if DOMAIN_PATTERN.match(value):
        return IOC(value.lower().rstrip("."), DOMAIN)

    return None


def is_private_ip(ioc: IOC) -> bool:
    """True for internal/reserved IPs, which public threat intel can't tell us anything about."""
    if ioc.type != IP:
        return False
    ip = ipaddress.ip_address(ioc.value)
    return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast


def parse_lines(lines) -> tuple[list[IOC], list[str]]:
    """Parse lines of text into unique IOCs (order preserved) plus a list of unrecognised entries.

    Blank lines and lines starting with '#' are ignored. Lines may contain several
    whitespace- or comma-separated indicators.
    """
    seen: set[tuple[str, str]] = set()
    iocs: list[IOC] = []
    rejected: list[str] = []
    for line in lines:
        # Drop full-line and trailing comments. A '#' only starts a comment after whitespace,
        # so URL fragments like https://x.example/#top are kept intact.
        line = INLINE_COMMENT.sub("", line).strip()
        if not line or line.startswith("#"):
            continue
        for token in re.split(r"[\s,]+", line):
            if not token:
                continue
            ioc = classify(token)
            if ioc is None:
                rejected.append(token)
                continue
            key = (ioc.type, ioc.value)
            if key not in seen:
                seen.add(key)
                iocs.append(ioc)
    return iocs, rejected
