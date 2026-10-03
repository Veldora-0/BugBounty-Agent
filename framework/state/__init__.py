"""
State management package for BugBounty-Agent.
"""

from framework.state.dedup import (
    FindingDeduplicator,
    canonicalize_parameter,
    canonicalize_url_path,
    generate_test_fingerprint,
)
from framework.state.manager import (
    DEFAULT_COVERAGE,
    StateManager,
)

__all__ = [
    "FindingDeduplicator",
    "canonicalize_parameter",
    "canonicalize_url_path",
    "generate_test_fingerprint",
    "StateManager",
    "DEFAULT_COVERAGE",
]
