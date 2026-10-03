"""
Findings management package for BugBounty-Agent.
"""

from framework.findings.lifecycle import (
    FindingLifecycle,
    InvalidLifecycleTransition,
    validate_transition,
)
from framework.findings.schema import (
    Finding,
    FindingValidationError,
)

__all__ = [
    "FindingLifecycle",
    "InvalidLifecycleTransition",
    "validate_transition",
    "Finding",
    "FindingValidationError",
]
