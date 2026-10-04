"""
Payload Abstraction and Benign Markers for BugBounty-Agent Security Validation.

Provides bounded, deterministic, and harmless markers for verification without
weaponized exploitation or large embedded wordlists.
"""

from __future__ import annotations

from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional
import uuid

from framework.validation.model import RiskLevel, VulnerabilityFamily


class MutationType(str, Enum):
    """Mechanisms used to inject or append verification markers."""
    MARKER_REFLECTION = "MARKER_REFLECTION"
    REDIRECT_TARGET = "REDIRECT_TARGET"
    BOUNDARY_STRING = "BOUNDARY_STRING"
    NUMERIC_MATH = "NUMERIC_MATH"


class Payload:
    """
    Controlled verification payload definition.
    Contains stable identifiers, safety classification, and token generators.
    """

    def __init__(
        self,
        payload_id: str,
        vulnerability_family: VulnerabilityFamily | str,
        purpose: str,
        mutation_type: MutationType | str,
        risk_classification: RiskLevel | str = RiskLevel.SAFE,
        encoding_requirements: str = "raw",
        expected_signals: Optional[List[str]] = None,
        raw_template: str = "",
        max_size_bytes: int = 256,
    ):
        self.payload_id = payload_id.strip()

        if isinstance(vulnerability_family, str):
            try:
                self.vulnerability_family = VulnerabilityFamily(vulnerability_family)
            except ValueError:
                self.vulnerability_family = VulnerabilityFamily.UNKNOWN
        else:
            self.vulnerability_family = vulnerability_family

        self.purpose = purpose.strip()

        if isinstance(mutation_type, str):
            try:
                self.mutation_type = MutationType(mutation_type)
            except ValueError:
                self.mutation_type = MutationType.MARKER_REFLECTION
        else:
            self.mutation_type = mutation_type

        if isinstance(risk_classification, str):
            try:
                self.risk_classification = RiskLevel(risk_classification.upper())
            except ValueError:
                self.risk_classification = RiskLevel.SAFE
        else:
            self.risk_classification = risk_classification

        self.encoding_requirements = encoding_requirements.strip().lower()
        self.expected_signals = list(expected_signals or [])
        self.raw_template = raw_template
        self.max_size_bytes = max_size_bytes

    def generate_value(self, token: Optional[str] = None) -> str:
        """
        Substitutes a unique, stable token into the template.
        Guarantees that the resulting payload is strictly bounded.
        """
        tok = token or uuid.uuid4().hex[:8]
        val = self.raw_template.replace("{TOKEN}", tok)
        if len(val.encode("utf-8")) > self.max_size_bytes:
            val = val[:self.max_size_bytes]
        return val

    def to_dict(self) -> Dict[str, Any]:
        """Serializes payload metadata to dictionary."""
        return {
            "payload_id": self.payload_id,
            "vulnerability_family": self.vulnerability_family.value,
            "purpose": self.purpose,
            "mutation_type": self.mutation_type.value,
            "risk_classification": self.risk_classification.value,
            "encoding_requirements": self.encoding_requirements,
            "expected_signals": self.expected_signals,
            "raw_template": self.raw_template,
            "max_size_bytes": self.max_size_bytes,
        }


class PayloadRegistry:
    """
    Registry of approved non-destructive verification payloads.
    Provides standard benign probes for proof-of-concept validators.
    """

    _STANDARD_PAYLOADS: Dict[str, Payload] = {
        # Safe Reflected XSS marker - NEVER executes JavaScript
        "PL-XSS-REFL-01": Payload(
            payload_id="PL-XSS-REFL-01",
            vulnerability_family=VulnerabilityFamily.XSS,
            purpose="Harmless alphanumeric marker to detect reflection without script execution",
            mutation_type=MutationType.MARKER_REFLECTION,
            risk_classification=RiskLevel.SAFE,
            expected_signals=["MARKER_REFLECTED_IN_BODY"],
            raw_template="XSHIELD_TEST_{TOKEN}",
            max_size_bytes=64,
        ),
        # Safe Open Redirect canary destination
        "PL-REDIR-CANARY-01": Payload(
            payload_id="PL-REDIR-CANARY-01",
            vulnerability_family=VulnerabilityFamily.OPEN_REDIRECT,
            purpose="Controlled non-destructive canary URL to detect unvalidated external redirection",
            mutation_type=MutationType.REDIRECT_TARGET,
            risk_classification=RiskLevel.SAFE,
            expected_signals=["LOCATION_REDIRECT"],
            raw_template="https://canary.bugbounty-agent.local/redirect_{TOKEN}",
            max_size_bytes=128,
        ),
    }

    @classmethod
    def get_payload(cls, payload_id: str) -> Optional[Payload]:
        """Retrieves an approved payload by its stable identifier."""
        return cls._STANDARD_PAYLOADS.get(payload_id)

    @classmethod
    def get_payloads_for_family(cls, family: VulnerabilityFamily | str) -> List[Payload]:
        """Returns all registered payloads for a given vulnerability family."""
        target_fam = family.value if isinstance(family, VulnerabilityFamily) else family
        return [p for p in cls._STANDARD_PAYLOADS.values() if p.vulnerability_family.value == target_fam]

    @classmethod
    def list_all_payloads(cls) -> List[Payload]:
        """Returns all registered standard payloads."""
        return list(cls._STANDARD_PAYLOADS.values())
