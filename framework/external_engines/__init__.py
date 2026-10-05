"""
External Pentesting Engine Integration Subsystem (Phase 12).

Exports generic pentest engine contracts, Xalgorix adapter, Strix adapter,
engine selector, and independent finding correlator.
"""

from framework.external_engines.base import (
    ExternalEngineStatus,
    ExternalFinding,
    ExternalPentestEngine,
)
from framework.external_engines.correlator import (
    ExternalEngineSelector,
    ExternalFindingCorrelator,
    IndependentValidator,
)
from framework.external_engines.strix import StrixAdapter
from framework.external_engines.xalgorix import XalgorixAdapter

__all__ = [
    "ExternalEngineStatus",
    "ExternalFinding",
    "ExternalPentestEngine",
    "ExternalEngineSelector",
    "ExternalFindingCorrelator",
    "IndependentValidator",
    "XalgorixAdapter",
    "StrixAdapter",
]
