"""
Reconnaissance State Management for BugBounty-Agent.

Provides persistent, atomic, resumable, and deduplicated storage of reconnaissance
observations (HTTP services, ports/services, DNS records, TLS details, technologies,
and endpoints) in ~/BugBounty-Workspace/programs/<program>/state/recon.json.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Set

from framework.recon.model import (
    DnsRecordObservation,
    EndpointObservation,
    HttpObservation,
    PortServiceObservation,
    TechnologyObservation,
    TlsObservation,
)


class ReconStateManager:
    """
    Manages persistent, atomic local state for reconnaissance observations.
    Stores and indexes observations to avoid redundant probing and support resumability.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)
        self.recon_file = os.path.join(self.state_dir, "recon.json")

        self.http_services: Dict[str, HttpObservation] = {}
        self.port_services: Dict[str, PortServiceObservation] = {}
        self.dns_records: Dict[str, DnsRecordObservation] = {}
        self.tls_records: Dict[str, TlsObservation] = {}
        self.technologies: Dict[str, TechnologyObservation] = {}
        self.endpoints: Dict[str, EndpointObservation] = {}
        self.probed_assets: Set[str] = set()
        self.metadata: Dict[str, Any] = {
            "first_run": datetime.now(timezone.utc).isoformat(),
            "last_run": datetime.now(timezone.utc).isoformat(),
            "total_observations": 0,
        }

        self.load()

    def _atomic_write_json(self, filepath: str, data: Any) -> None:
        """Writes JSON data atomically using a temporary file."""
        dir_name = os.path.dirname(filepath)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        os.replace(temp_path, filepath)

    def load(self) -> None:
        """Loads existing reconnaissance state from recon.json if present."""
        if not os.path.isfile(self.recon_file):
            return

        try:
            with open(self.recon_file, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except (json.JSONDecodeError, OSError):
            return

        self.metadata = data.get("metadata", self.metadata)
        self.probed_assets = set(data.get("probed_assets", []))

        # Rehydrate HTTP observations
        for item in data.get("http_services", []):
            obs = HttpObservation.from_dict(item)
            self.http_services[obs.key] = obs

        # Rehydrate Port observations
        for item in data.get("port_services", []):
            obs = PortServiceObservation.from_dict(item)
            self.port_services[obs.key] = obs

        # Rehydrate DNS observations
        for item in data.get("dns_records", []):
            obs = DnsRecordObservation.from_dict(item)
            self.dns_records[obs.key] = obs

        # Rehydrate TLS observations
        for item in data.get("tls_records", []):
            obs = TlsObservation.from_dict(item)
            self.tls_records[obs.key] = obs

        # Rehydrate Technology observations
        for item in data.get("technologies", []):
            obs = TechnologyObservation.from_dict(item)
            self.technologies[obs.key] = obs

        # Rehydrate Endpoint observations
        for item in data.get("endpoints", []):
            obs = EndpointObservation.from_dict(item)
            self.endpoints[obs.key] = obs

    def save(self) -> None:
        """Saves current reconnaissance state atomically to recon.json."""
        self.metadata["last_run"] = datetime.now(timezone.utc).isoformat()
        total = (
            len(self.http_services)
            + len(self.port_services)
            + len(self.dns_records)
            + len(self.tls_records)
            + len(self.technologies)
            + len(self.endpoints)
        )
        self.metadata["total_observations"] = total

        export_data = {
            "metadata": self.metadata,
            "probed_assets": sorted(list(self.probed_assets)),
            "http_services": [o.to_dict() for o in sorted(self.http_services.values(), key=lambda x: x.key)],
            "port_services": [o.to_dict() for o in sorted(self.port_services.values(), key=lambda x: x.key)],
            "dns_records": [o.to_dict() for o in sorted(self.dns_records.values(), key=lambda x: x.key)],
            "tls_records": [o.to_dict() for o in sorted(self.tls_records.values(), key=lambda x: x.key)],
            "technologies": [o.to_dict() for o in sorted(self.technologies.values(), key=lambda x: x.key)],
            "endpoints": [o.to_dict() for o in sorted(self.endpoints.values(), key=lambda x: x.key)],
        }
        self._atomic_write_json(self.recon_file, export_data)

    def mark_probed(self, asset_val: str) -> None:
        """Records that an asset has completed reconnaissance passes."""
        self.probed_assets.add(asset_val.strip().lower())

    def is_probed(self, asset_val: str) -> bool:
        """Checks if an asset has already been probed."""
        return asset_val.strip().lower() in self.probed_assets

    # ---------------- Add & Deduplicate Observations ----------------

    def add_http_observation(self, obs: HttpObservation) -> bool:
        """Adds or merges an HTTP service observation. Returns True if newly added."""
        key = obs.key
        if key in self.http_services:
            existing = self.http_services[key]
            # Merge fields if missing in existing
            if not existing.title and obs.title:
                existing.title = obs.title
            if not existing.server_header and obs.server_header:
                existing.server_header = obs.server_header
            if not existing.content_type and obs.content_type:
                existing.content_type = obs.content_type
            if not existing.content_length and obs.content_length:
                existing.content_length = obs.content_length
            if obs.redirect_chain:
                existing.redirect_chain = list(dict.fromkeys(existing.redirect_chain + obs.redirect_chain))
            if obs.technologies:
                existing.technologies = sorted(list(set(existing.technologies + obs.technologies)))
            existing.security_headers.update(obs.security_headers)
            # Merge provenance
            for p in obs.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.http_services[key] = obs
            return True

    def add_port_observation(self, obs: PortServiceObservation) -> bool:
        """Adds or merges a port/service observation. Returns True if newly added."""
        key = obs.key
        if key in self.port_services:
            existing = self.port_services[key]
            if not existing.product and obs.product:
                existing.product = obs.product
            if not existing.version and obs.version:
                existing.version = obs.version
            if not existing.banner and obs.banner:
                existing.banner = obs.banner
            for p in obs.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.port_services[key] = obs
            return True

    def add_dns_observation(self, obs: DnsRecordObservation) -> bool:
        """Adds or merges a DNS record observation. Returns True if newly added."""
        key = obs.key
        if key in self.dns_records:
            existing = self.dns_records[key]
            combined = sorted(list(set(existing.values + obs.values)))
            existing.values = combined
            for p in obs.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.dns_records[key] = obs
            return True

    def add_tls_observation(self, obs: TlsObservation) -> bool:
        """Adds or merges a TLS certificate observation. Returns True if newly added."""
        key = obs.key
        if key in self.tls_records:
            existing = self.tls_records[key]
            if not existing.issuer and obs.issuer:
                existing.issuer = obs.issuer
            if not existing.subject and obs.subject:
                existing.subject = obs.subject
            if obs.san_names:
                existing.san_names = sorted(list(set(existing.san_names + obs.san_names)))
            for p in obs.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.tls_records[key] = obs
            return True

    def add_technology_observation(self, obs: TechnologyObservation) -> bool:
        """Adds or merges a technology observation. Returns True if newly added."""
        key = obs.key
        if key in self.technologies:
            existing = self.technologies[key]
            if not existing.version and obs.version:
                existing.version = obs.version
            if obs.confidence == "CONFIRMED":
                existing.confidence = "CONFIRMED"
            elif obs.confidence == "PROBABLE" and existing.confidence == "OBSERVED":
                existing.confidence = "PROBABLE"
            for p in obs.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.technologies[key] = obs
            return True

    def add_endpoint_observation(self, obs: EndpointObservation) -> bool:
        """Adds or merges an endpoint observation. Returns True if newly added."""
        key = obs.key
        if key in self.endpoints:
            existing = self.endpoints[key]
            if not existing.status_code and obs.status_code:
                existing.status_code = obs.status_code
            if not existing.content_type and obs.content_type:
                existing.content_type = obs.content_type
            for p in obs.provenance:
                existing.provenance.append(p)
            return False
        else:
            self.endpoints[key] = obs
            return True

    # ---------------- Queries ----------------

    def get_http_for_host(self, host: str) -> List[HttpObservation]:
        h_clean = host.strip().lower()
        return [o for o in self.http_services.values() if o.host.lower() == h_clean]

    def get_ports_for_host(self, host: str) -> List[PortServiceObservation]:
        h_clean = host.strip().lower()
        return [o for o in self.port_services.values() if o.host.lower() == h_clean]

    def get_dns_for_host(self, host: str) -> List[DnsRecordObservation]:
        h_clean = host.strip().lower()
        return [o for o in self.dns_records.values() if o.host.lower() == h_clean]

    def get_technologies_for_host(self, host: str) -> List[TechnologyObservation]:
        h_clean = host.strip().lower()
        return [o for o in self.technologies.values() if o.host.lower() == h_clean]

    def get_endpoints_for_host(self, host: str) -> List[EndpointObservation]:
        h_clean = host.strip().lower()
        return [o for o in self.endpoints.values() if o.host.lower() == h_clean]
