"""
Phase 21: CVSS 3.1 Base Score Calculator & Metric Validator.

Implements the official FIRST CVSS v3.1 specification for metric validation,
sub-score calculations, and base score rounding without static multipliers
or confidence factoring.
"""

from __future__ import annotations

from enum import Enum
import math
from typing import Any, NamedTuple, Optional, Tuple


class CVSSMetricValidationError(Exception):
    """Raised when CVSS 3.1 base metrics are missing, invalid, or malformed."""
    pass


class AttackVector(str, Enum):
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, Enum):
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(str, Enum):
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, Enum):
    NONE = "N"
    REQUIRED = "R"


class Scope(str, Enum):
    UNCHANGED = "U"
    CHANGED = "C"


class CIAImpact(str, Enum):
    HIGH = "H"
    LOW = "L"
    NONE = "N"


class CVSS31Metrics(NamedTuple):
    av: AttackVector
    ac: AttackComplexity
    pr: PrivilegesRequired
    ui: UserInteraction
    scope: Scope
    c: CIAImpact
    i: CIAImpact
    a: CIAImpact


class CVSS31Calculator:
    """Authentic CVSS 3.1 Base Score Calculator complying with FIRST specifications."""
    
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"N": 0.0, "L": 0.22, "H": 0.56}
    PR_WEIGHTS = {
        "U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "C": {"N": 0.85, "L": 0.68, "H": 0.50},
    }

    @classmethod
    def validate_metrics(cls, m: Any) -> CVSS31Metrics:
        """Strict pre-calculation metric validation; rejects invalid types or missing metrics."""
        if not isinstance(m, CVSS31Metrics):
            raise CVSSMetricValidationError("Metrics object must be an instance of CVSS31Metrics")
        if not isinstance(m.av, AttackVector):
            raise CVSSMetricValidationError("Invalid AttackVector metric enum")
        if not isinstance(m.ac, AttackComplexity):
            raise CVSSMetricValidationError("Invalid AttackComplexity metric enum")
        if not isinstance(m.pr, PrivilegesRequired):
            raise CVSSMetricValidationError("Invalid PrivilegesRequired metric enum")
        if not isinstance(m.ui, UserInteraction):
            raise CVSSMetricValidationError("Invalid UserInteraction metric enum")
        if not isinstance(m.scope, Scope):
            raise CVSSMetricValidationError("Invalid Scope metric enum")
        if not isinstance(m.c, CIAImpact):
            raise CVSSMetricValidationError("Invalid Confidentiality impact metric enum")
        if not isinstance(m.i, CIAImpact):
            raise CVSSMetricValidationError("Invalid Integrity impact metric enum")
        if not isinstance(m.a, CIAImpact):
            raise CVSSMetricValidationError("Invalid Availability impact metric enum")
        return m

    @staticmethod
    def _round_up(val: float) -> float:
        input_round = round(val * 100000)
        if (input_round % 10000) == 0:
            return input_round / 100000.0
        return (math.floor(input_round / 10000) + 1) / 10.0

    @classmethod
    def calculate_base_score(cls, raw_metrics: CVSS31Metrics) -> Tuple[float, str, str]:
        # Validate all metrics before executing mathematical formula
        m = cls.validate_metrics(raw_metrics)

        iss = 1.0 - (
            (1.0 - cls.CIA_WEIGHTS[m.c.value]) *
            (1.0 - cls.CIA_WEIGHTS[m.i.value]) *
            (1.0 - cls.CIA_WEIGHTS[m.a.value])
        )
        if m.scope == Scope.UNCHANGED:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

        exploitability = (
            8.22 *
            cls.AV_WEIGHTS[m.av.value] *
            cls.AC_WEIGHTS[m.ac.value] *
            cls.PR_WEIGHTS[m.scope.value][m.pr.value] *
            cls.UI_WEIGHTS[m.ui.value]
        )

        if impact <= 0:
            base_score = 0.0
        else:
            if m.scope == Scope.UNCHANGED:
                base_score = cls._round_up(min(impact + exploitability, 10.0))
            else:
                base_score = cls._round_up(min(1.08 * (impact + exploitability), 10.0))

        # Explicit qualitative severity rating scale
        if base_score == 0.0:
            severity = "NONE"
        elif 0.1 <= base_score <= 3.9:
            severity = "LOW"
        elif 4.0 <= base_score <= 6.9:
            severity = "MEDIUM"
        elif 7.0 <= base_score <= 8.9:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        vector = (
            f"CVSS:3.1/AV:{m.av.value}/AC:{m.ac.value}/PR:{m.pr.value}/"
            f"UI:{m.ui.value}/S:{m.scope.value}/C:{m.c.value}/I:{m.i.value}/A:{m.a.value}"
        )
        return base_score, severity, vector
