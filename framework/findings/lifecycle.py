"""
Finding Lifecycle State Machine for BugBounty-Agent.

Enforces the transition pipeline:
OBSERVATION -> HYPOTHESIS -> CANDIDATE -> VALIDATED / REJECTED / DUPLICATE / INFORMATIONAL
Never allows automatic jumping from raw signal or scanner hit directly to VALIDATED.
"""

from __future__ import annotations

from enum import Enum
from typing import Set


class FindingLifecycle(str, Enum):
    OBSERVATION = "OBSERVATION"
    HYPOTHESIS = "HYPOTHESIS"
    CANDIDATE = "CANDIDATE"
    TESTING = "TESTING"
    OBSERVED = "OBSERVED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    INFORMATIONAL = "INFORMATIONAL"


# Legal transitions between lifecycle states
VALID_TRANSITIONS: dict[FindingLifecycle, Set[FindingLifecycle]] = {
    FindingLifecycle.OBSERVATION: {
        FindingLifecycle.HYPOTHESIS,
        FindingLifecycle.CANDIDATE,
        FindingLifecycle.INFORMATIONAL,
        FindingLifecycle.REJECTED,
    },
    FindingLifecycle.HYPOTHESIS: {
        FindingLifecycle.CANDIDATE,
        FindingLifecycle.REJECTED,
        FindingLifecycle.INFORMATIONAL,
    },
    FindingLifecycle.CANDIDATE: {
        FindingLifecycle.TESTING,
        FindingLifecycle.OBSERVED,
        FindingLifecycle.VALIDATED,
        FindingLifecycle.REJECTED,
        FindingLifecycle.DUPLICATE,
        FindingLifecycle.NEEDS_MANUAL_REVIEW,
        FindingLifecycle.INFORMATIONAL,
    },
    FindingLifecycle.TESTING: {
        FindingLifecycle.OBSERVED,
        FindingLifecycle.REJECTED,
        FindingLifecycle.DUPLICATE,
        FindingLifecycle.NEEDS_MANUAL_REVIEW,
    },
    FindingLifecycle.OBSERVED: {
        FindingLifecycle.VALIDATED,
        FindingLifecycle.REJECTED,
        FindingLifecycle.DUPLICATE,
        FindingLifecycle.NEEDS_MANUAL_REVIEW,
    },
    FindingLifecycle.VALIDATED: {
        FindingLifecycle.DUPLICATE,
        FindingLifecycle.REJECTED,
        FindingLifecycle.NEEDS_MANUAL_REVIEW,
        FindingLifecycle.INFORMATIONAL,
    },
    FindingLifecycle.REJECTED: {
        FindingLifecycle.HYPOTHESIS,
        FindingLifecycle.CANDIDATE,
        FindingLifecycle.TESTING,
    },
    FindingLifecycle.DUPLICATE: {
        FindingLifecycle.VALIDATED,
    },
    FindingLifecycle.NEEDS_MANUAL_REVIEW: {
        FindingLifecycle.VALIDATED,
        FindingLifecycle.REJECTED,
        FindingLifecycle.DUPLICATE,
    },
    FindingLifecycle.INFORMATIONAL: {
        FindingLifecycle.CANDIDATE,
    },
}


class InvalidLifecycleTransition(ValueError):
    """Raised when an illegal lifecycle state transition is attempted."""
    pass


def validate_transition(current: FindingLifecycle, target: FindingLifecycle) -> bool:
    """Verifies that a state transition is legal according to strict researcher methodology."""
    if current == target:
        return True
    allowed = VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidLifecycleTransition(
            f"Cannot transition finding from '{current.value}' to '{target.value}'. "
            f"Allowed transitions from '{current.value}': {[s.value for s in allowed]}"
        )
    return True
