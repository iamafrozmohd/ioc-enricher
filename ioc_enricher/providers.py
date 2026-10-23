"""Threat intelligence provider clients (VirusTotal v3 and AbuseIPDB v2).

Only the Python standard library is used, so the tool runs anywhere with Python 3.10+.
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .ioc import DOMAIN, HASH, IOC, IP, URL

USER_AGENT = "ioc-enricher/1.0 (+https://github.com/iamafrozmohd/ioc-enricher)"


class ProviderError(Exception):
    """Raised when a provider can't return a usable answer (bad key, network error, etc.)."""


@dataclass
class ProviderResult:
    provider: str
    found: bool
    data: dict = field(default_factory=dict)
    error: str = ""
    link: str = ""


class RateLimiter:
    """Enforces a minimum gap between calls (VirusTotal's free tier allows 4 requests/minute)."""

    def __init__(self, per_minute: float, sleep=time.sleep, clock=time.monotonic):
        self.interval = 60.0 / per_minute if per_minute > 0 else 0.0
        self._sleep = sleep
        self._clock = clock
        self._last = None

    def wait(self) -> None:
        if self._last is not None and self.interval:
            remaining = self.interval - (self._clock() - self._last)
            if remaining > 0:
                self._sleep(remaining)
        self._last = self._clock()


def _http_get_json(url: str, headers: dict, timeout: int = 20, retries: int = 2, sleep=time.sleep):
    """GET a JSON document. Returns (status, body); retries politely on HTTP 429."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **headers})
    for attempt in range(retries + 1):
        try:
            # URLs are always built from fixed https:// API bases below, never from user input schemes.
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < retries:
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                sleep(float(retry_after) if retry_after and retry_after.isdigit() else 20.0)
                continue
            body = {}
            try:
                body = json.loads(exc.read().decode("utf-8") or "{}")
            except (ValueError, OSError):
                pass
            return exc.code, body
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProviderError(f"network error: {exc}") from exc
    raise ProviderError("rate limited: too many retries")


class VirusTotal:
    name = "VirusTotal"
    base = "https://www.virustotal.com/api/v3"
    gui = "https://www.virustotal.com/gui"
    supports = frozenset({IP, DOMAIN, URL, HASH})

    def __init__(self, api_key: str, per_minute: float = 4, http_get=_http_get_json, limiter=None):
        if not api_key:
            raise ProviderError("VirusTotal API key is missing (set VT_API_KEY)")
        self.api_key = api_key
        self.http_get = http_get
        self.limiter = limiter or RateLimiter(per_minute)

    @staticmethod
    def url_id(url: str) -> str:
        """VirusTotal identifies URLs by unpadded URL-safe base64 of the URL."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _endpoint(self, ioc: IOC) -> tuple[str, str]:
        quote = urllib.parse.quote
        if ioc.type == IP:
            return f"{self.base}/ip_addresses/{quote(ioc.value)}", f"{self.gui}/ip-address/{ioc.value}"
        if ioc.type == DOMAIN:
            return f"{self.base}/domains/{quote(ioc.value)}", f"{self.gui}/domain/{ioc.value}"
        if ioc.type == HASH:
            return f"{self.base}/files/{quote(ioc.value)}", f"{self.gui}/file/{ioc.value}"
        url_id = self.url_id(ioc.value)
        return f"{self.base}/urls/{url_id}", f"{self.gui}/url/{url_id}"

    def lookup(self, ioc: IOC) -> ProviderResult:
        api_url, link = self._endpoint(ioc)
        self.limiter.wait()
        status, body = self.http_get(api_url, {"x-apikey": self.api_key})
        if status == 404:
            return ProviderResult(self.name, found=False, link=link)
        if status in (401, 403):
            raise ProviderError("VirusTotal rejected the API key")
        if status != 200:
            message = (body.get("error") or {}).get("message", f"HTTP {status}")
            return ProviderResult(self.name, found=False, error=message, link=link)

        attrs = (body.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        data = {
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": attrs.get("reputation"),
        }
        if ioc.type == IP:
            data["country"] = attrs.get("country", "")
            data["as_owner"] = attrs.get("as_owner", "")
        if ioc.type == HASH:
            data["file_name"] = attrs.get("meaningful_name", "")
            data["file_type"] = attrs.get("type_description", "")
            label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
            if label:
                data["threat_label"] = label
        return ProviderResult(self.name, found=True, data=data, link=link)


class AbuseIPDB:
    name = "AbuseIPDB"
    base = "https://api.abuseipdb.com/api/v2/check"
    supports = frozenset({IP})

    def __init__(self, api_key: str, max_age_days: int = 90, http_get=_http_get_json):
        if not api_key:
            raise ProviderError("AbuseIPDB API key is missing (set ABUSEIPDB_API_KEY)")
        self.api_key = api_key
        self.max_age_days = max_age_days
        self.http_get = http_get

    def lookup(self, ioc: IOC) -> ProviderResult:
        query = urllib.parse.urlencode({"ipAddress": ioc.value, "maxAgeInDays": self.max_age_days})
        link = f"https://www.abuseipdb.com/check/{ioc.value}"
        status, body = self.http_get(f"{self.base}?{query}", {"Key": self.api_key, "Accept": "application/json"})
        if status in (401, 403):
            raise ProviderError("AbuseIPDB rejected the API key")
        if status != 200:
            errors = body.get("errors") or [{}]
            return ProviderResult(self.name, found=False, error=errors[0].get("detail", f"HTTP {status}"), link=link)

        d = body.get("data") or {}
        data = {
            "abuse_score": int(d.get("abuseConfidenceScore", 0)),
            "total_reports": int(d.get("totalReports", 0)),
            "country": d.get("countryCode") or "",
            "isp": d.get("isp") or "",
            "usage_type": d.get("usageType") or "",
            "whitelisted": bool(d.get("isWhitelisted")),
            "last_reported": d.get("lastReportedAt") or "",
        }
        return ProviderResult(self.name, found=True, data=data, link=link)
