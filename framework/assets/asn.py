"""Opt-in, bounded Team Cymru origin ASN lookup via the system dig client."""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from typing import Any, Dict


class TeamCymruAsnResolver:
    """Resolve public IP origin ASN metadata; never queries private/non-global IPs."""

    def __init__(self, *, dig_path: str | None = None, timeout: float = 3.0, max_queries: int = 25):
        self.dig_path = dig_path or shutil.which("dig")
        self.timeout = max(0.1, min(float(timeout), 10.0))
        self.max_queries = max(0, min(int(max_queries), 100))
        self.queries = 0
        self.cache: dict[str, Dict[str, Any]] = {}

    def __call__(self, value: str) -> Dict[str, Any]:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return {}
        key = str(ip)
        if key in self.cache:
            return dict(self.cache[key])
        if not ip.is_global or not self.dig_path or self.queries >= self.max_queries:
            return {}
        reversed_ip = ".".join(reversed(key.split("."))) if ip.version == 4 else ".".join(reversed(key.replace(":", "")))
        zone = "origin.asn.cymru.com." if ip.version == 4 else "origin6.asn.cymru.com."
        self.queries += 1
        try:
            result = subprocess.run(
                [self.dig_path, "+time=2", "+tries=1", "+short", "TXT", f"{reversed_ip}.{zone}"],
                capture_output=True, text=True, timeout=self.timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {}
        raw = result.stdout[:2048].strip().strip('"')
        fields = [field.strip() for field in raw.split("|")]
        if result.returncode != 0 or len(fields) < 5 or not re.fullmatch(r"\d{1,10}", fields[0]):
            return {}
        try:
            network = ipaddress.ip_network(fields[1], strict=False)
            if ip not in network:
                return {}
        except ValueError:
            return {}
        data = {"asn": f"AS{int(fields[0])}", "org": "UNKNOWN", "cidr": str(network),
                "country": fields[2][:32], "registry": fields[3][:32], "allocated": fields[4][:32],
                "source": "Team Cymru IP-to-ASN"}
        self.cache[key] = data
        return dict(data)
