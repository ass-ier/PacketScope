import base64
import json
import os
from abc import ABC, abstractmethod
from urllib.parse import quote

import httpx
from fastapi import HTTPException

from app.models import ThreatIntelResult
from app.services.query import record


class ThreatIntelProvider(ABC):
    name: str
    types: set[str]

    @abstractmethod
    def lookup(self, ioc):
        """Return only actual provider data; never a success-shaped fallback."""

    def request(self, url, headers=None, params=None):
        with httpx.Client(timeout=8, follow_redirects=False, trust_env=False) as client:
            with client.stream("GET", url, headers=headers, params=params) as response:
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    if len(body) + len(chunk) > 1024 * 1024:
                        raise ValueError("Provider response exceeded 1 MiB limit")
                    body.extend(chunk)
        result = json.loads(body)
        if not isinstance(result, dict):
            raise ValueError("Unexpected provider response shape")
        return result


class RDAP(ThreatIntelProvider):
    name, types = "rdap", {"ipv4", "ipv6"}

    def lookup(self, ioc):
        result = self.request("https://rdap.arin.net/registry/ip/" + quote(ioc.value, safe=""))
        return {"name": result.get("name"), "country": result.get("country"),
                "start_address": result.get("startAddress"), "end_address": result.get("endAddress"),
                "notice": "Registration data is not a reputation verdict. Redirects are not followed."}


class DNSProvider(ThreatIntelProvider):
    name, types = "dns", {"domain"}

    def lookup(self, ioc):
        result = self.request("https://cloudflare-dns.com/dns-query",
                              headers={"Accept": "application/dns-json"}, params={"name": ioc.value, "type": "A"})
        if "Status" not in result:
            raise ValueError("DNS provider did not return a DNS status")
        return {"status": result["Status"], "answers": result.get("Answer", []),
                "notice": "Current external DNS response, not historical capture evidence"}


class VirusTotal(ThreatIntelProvider):
    name, types = "virustotal", {"ipv4", "ipv6", "domain", "url", "sha256", "sha1", "md5"}

    def lookup(self, ioc):
        category = "ip_addresses" if ioc.type in ("ipv4", "ipv6") else "domains" if ioc.type == "domain" else "urls" if ioc.type == "url" else "files"
        value = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=") if ioc.type == "url" else ioc.value
        result = self.request(f"https://www.virustotal.com/api/v3/{category}/{quote(value, safe='')}",
                              headers={"x-apikey": os.environ["PACKETSCOPE_VT_API_KEY"]})
        attributes = result.get("data", {}).get("attributes")
        if not isinstance(attributes, dict):
            raise ValueError("VirusTotal response did not contain attributes")
        return {"last_analysis_stats": attributes.get("last_analysis_stats"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "notice": "External provider observation, not a PacketScope verdict"}


PROVIDERS = {provider.name: provider for provider in (RDAP(), DNSProvider(), VirusTotal())}


def provider_status():
    enabled = os.environ.get("PACKETSCOPE_EXTERNAL_ENABLED") == "true"
    return {"external_enabled": enabled, "providers": [
        {"name": name, "enabled": enabled, "configured": name != "virustotal" or bool(os.environ.get("PACKETSCOPE_VT_API_KEY")),
         "types": sorted(provider.types)} for name, provider in PROVIDERS.items()],
        "notice": "External lookups send the selected indicator only after explicit per-request consent. Core analysis never calls providers."}


def lookup(db, ioc, provider_name, consent):
    if not consent:
        raise HTTPException(422, "Explicit consent to share this indicator is required")
    if os.environ.get("PACKETSCOPE_EXTERNAL_ENABLED") != "true":
        raise HTTPException(409, "External intelligence is disabled; no indicator was sent")
    provider = PROVIDERS.get(provider_name)
    if provider is None:
        raise HTTPException(422, "Unknown threat-intelligence provider")
    if ioc.type not in provider.types:
        raise HTTPException(422, "Provider does not support this indicator type")
    if provider_name == "virustotal" and not os.environ.get("PACKETSCOPE_VT_API_KEY"):
        raise HTTPException(409, "VirusTotal is not configured")
    try:
        result = provider.lookup(ioc)
    except (httpx.HTTPError, ValueError) as exc:
        message = f"Provider lookup failed ({type(exc).__name__}); no reputation result available"
        db.add(ThreatIntelResult(ioc_id=ioc.id, provider=provider_name, status="failed", result={"error": message}))
        db.commit()
        raise HTTPException(502, message) from exc
    row = ThreatIntelResult(ioc_id=ioc.id, provider=provider_name, status="completed", result=result)
    db.add(row)
    db.commit()
    return record(row)
