"""
Observation Provenance for BugBounty-Agent Asset Intelligence.

Tracks multi-source observation metadata, recording the originating tool,
discovery method, timestamp, raw observation, and initial confidence score.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional


@dataclass
class ObservationProvenance:
    """Represents the historical provenance of an asset observation."""
    source: str
    method: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    raw_observation: Optional[str] = None
    confidence: str = "MEDIUM"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converts provenance record to JSON-serializable dictionary."""
        data = {
            "source": self.source,
            "method": self.method,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
        }
        if self.raw_observation is not None:
            data["raw_observation"] = self.raw_observation
        if self.details:
            data["details"] = self.details
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ObservationProvenance:
        """Constructs an ObservationProvenance instance from a dictionary."""
        return cls(
            source=data.get("source", "unknown"),
            method=data.get("method", "unknown"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            raw_observation=data.get("raw_observation"),
            confidence=data.get("confidence", "MEDIUM"),
            details=data.get("details", {}) or {},
        )
