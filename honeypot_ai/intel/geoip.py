"""
geoip.py
~~~~~~~~
Enrich attacker IP addresses with geolocation data.

Uses the free ip-api.com batch endpoint (up to 100 IPs per request,
no API key required). Gracefully falls back to 'Unknown' on any error.

Private/loopback IPs (RFC 1918, 127.x.x.x, ::1) are tagged as
"Private Network" without making a network request.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any

import requests

log = logging.getLogger(__name__)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_UNKNOWN = {
    "country": "Unknown",
    "countryCode": "??",
    "city": "Unknown",
    "lat": 0.0,
    "lon": 0.0,
    "isp": "Unknown",
    "org": "Unknown",
}

_PRIVATE_RESULT = {
    "country": "Private Network",
    "countryCode": "LO",
    "city": "Local",
    "lat": 0.0,
    "lon": 0.0,
    "isp": "Private",
    "org": "Private",
}


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def enrich_ips(ips: list[str], timeout: int = 5) -> dict[str, dict[str, Any]]:
    """
    Fetch geolocation for a list of unique IP strings.

    Parameters
    ----------
    ips:
        List of IPv4/IPv6 address strings (duplicates are deduplicated).
    timeout:
        HTTP request timeout in seconds.

    Returns
    -------
    dict mapping IP → geo-dict with keys:
        country, countryCode, city, lat, lon, isp, org
    """
    unique = list(dict.fromkeys(ips))  # preserve order, deduplicate
    result: dict[str, dict[str, Any]] = {}

    public_ips = []
    for ip in unique:
        if _is_private(ip):
            result[ip] = _PRIVATE_RESULT.copy()
        else:
            public_ips.append(ip)

    # Batch in chunks of 100 (ip-api limit)
    for i in range(0, len(public_ips), 100):
        chunk = public_ips[i : i + 100]
        payload = [{"query": ip, "fields": "country,countryCode,city,lat,lon,isp,org,query,status"} for ip in chunk]
        try:
            resp = requests.post(
                "http://ip-api.com/batch",
                json=payload,
                timeout=timeout,
            )
            resp.raise_for_status()
            for item in resp.json():
                ip_key = item.get("query", "")
                if item.get("status") == "success":
                    result[ip_key] = {k: item.get(k, _UNKNOWN[k]) for k in _UNKNOWN}
                else:
                    result[ip_key] = _UNKNOWN.copy()
        except Exception as exc:  # noqa: BLE001
            log.warning("GeoIP lookup failed (%s) — marking as Unknown", exc)
            for ip in chunk:
                result.setdefault(ip, _UNKNOWN.copy())
        # Be polite to the free API
        if i + 100 < len(public_ips):
            time.sleep(1)

    return result
