"""
BugBounty-Agent Infrastructure & Configuration Exposure Subsystem.

Provides non-destructive detection, differential soft-404 verification,
evidence-sufficiency stopping rules, and structured findings across 8 exposure classes.
"""

from __future__ import annotations

from framework.infrastructure.differential import (
    DifferentialComparisonResult,
    DifferentialSoft404Engine,
)
from framework.infrastructure.engine import (
    EXPOSURE_PATH_TEMPLATES,
    InfrastructureIntelligenceEngine,
)
from framework.infrastructure.exposure import (
    InfrastructureExposureEvaluator,
)
from framework.infrastructure.lab import (
    InfrastructureLabHandler,
    LocalInfrastructureLab,
)
from framework.infrastructure.model import (
    ExposureCandidate,
    ExposureCategory,
    ExposureEvaluationResult,
    ExposureHypothesis,
    generate_candidate_id,
)
from framework.infrastructure.policy import (
    InfrastructureExposurePolicy,
)
from framework.infrastructure.signatures import (
    InfrastructureSignatures,
)
from framework.infrastructure.state import (
    InfrastructureStateManager,
)

__all__ = [
    "DifferentialComparisonResult",
    "DifferentialSoft404Engine",
    "EXPOSURE_PATH_TEMPLATES",
    "ExposureCandidate",
    "ExposureCategory",
    "ExposureEvaluationResult",
    "ExposureHypothesis",
    "InfrastructureExposureEvaluator",
    "InfrastructureExposurePolicy",
    "InfrastructureIntelligenceEngine",
    "InfrastructureLabHandler",
    "InfrastructureSignatures",
    "InfrastructureStateManager",
    "LocalInfrastructureLab",
    "generate_candidate_id",
]
