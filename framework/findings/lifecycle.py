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
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"
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
        FindingLifecycle.VALIDATED,
        FindingLifecycle.REJECTED,
        FindingLifecycle.DUPLICATE,
        FindingLifecycle.INFORMATIONAL,
    },
    FindingLifecycle.VALIDATED: {
        FindingLifecycle.DUPLICATE,
        FindingLifecycle.REJECTED,
        FindingLifecycle.INFORMATIONAL,
    },
    FindingLifecycle.REJECTED: {
        FindingLifecycle.HYPOTHESIS,
        FindingLifecycle.CANDIDATE,
    },
    FindingLifecycle.DUPLICATE: {
        FindingLifecycle.VALIDATED,
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
