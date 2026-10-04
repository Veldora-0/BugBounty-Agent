"""
Bounded Payload Registry Extension for Injection Testing (Phase 10).

Maintains strictly non-destructive, bounded verification payloads for
SQL differential checks, NoSQL operator validation, harmless SSTI mathematical expressions,
and safe command-injection candidate markers.

STRICT INVARIANTS:
1. Zero destructive SQL statements (DROP, DELETE, UPDATE, INSERT, ALTER, TRUNCATE).
2. Zero OS shell execution payloads (curl, wget, bash, sh, powershell, rm, nc).
3. Max payload size strictly capped (<= 256 bytes).
"""

from __future__ import annotations

from enum import Enum
import re
from typing import Any, Dict, List, Optional

from framework.injection.model import (
    InjectionContext,
    InjectionType,
)
from framework.validation.model import RiskLevel, VulnerabilityFamily
from framework.validation.payload import MutationType, Payload, PayloadRegistry


FORBIDDEN_DESTRUCTIVE_PATTERNS = [
    re.compile(r"\b(?:DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE|GRANT|REVOKE|SHUTDOWN)\b", re.IGNORECASE),
    re.compile(r"\b(?:curl|wget|bash|sh|zsh|powershell|cmd\.exe|nc|netcat|socat|rm\s+-rf)\b", re.IGNORECASE),
]


def is_destructive_payload(payload_str: str) -> bool:
    """Checks whether a proposed payload contains prohibited destructive or OS-execution patterns."""
    if not payload_str:
        return False
    for pat in FORBIDDEN_DESTRUCTIVE_PATTERNS:
        if pat.search(payload_str):
            return True
    return False


class InjectionPayloadDefinition:
    """Specialized injection payload specification."""

    def __init__(
        self,
        payload_id: str,
        injection_type: InjectionType,
        context: InjectionContext,
        purpose: str,
        mutation_type: MutationType,
        raw_template: str,
        expected_signals: List[str],
        risk_level: RiskLevel = RiskLevel.SAFE,
        max_size_bytes: int = 128,
        is_timing: bool = False,
    ):
        if is_destructive_payload(raw_template):
            raise ValueError(f"Payload '{payload_id}' rejected: contains destructive or shell patterns")

        self.payload_id = payload_id
        self.injection_type = injection_type
        self.context = context
        self.purpose = purpose
        self.mutation_type = mutation_type
        self.raw_template = raw_template
        self.expected_signals = list(expected_signals)
        self.risk_level = risk_level
        self.max_size_bytes = max_size_bytes
        self.is_timing = is_timing

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "injection_type": self.injection_type.value,
            "context": self.context.value,
            "purpose": self.purpose,
            "mutation_type": self.mutation_type.value,
            "raw_template": self.raw_template,
            "expected_signals": self.expected_signals,
            "risk_level": self.risk_level.value,
            "max_size_bytes": self.max_size_bytes,
            "is_timing": self.is_timing,
        }


# Bounded Injection Payload Catalog
INJECTION_PAYLOADS: Dict[str, InjectionPayloadDefinition] = {
    # --- SQL Injection Payloads ---
    "PL-SQL-QUOTE-01": InjectionPayloadDefinition(
        payload_id="PL-SQL-QUOTE-01",
        injection_type=InjectionType.SQL,
        context=InjectionContext.SQL_STRING,
        purpose="Harmless quote syntax probe to observe parser differential or syntax fault",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template="'",
        expected_signals=["SQL_SYNTAX_ERROR", "STATUS_500", "RESPONSE_DIFFERENTIAL"],
        max_size_bytes=8,
    ),
    "PL-SQL-BOOL-TRUE-01": InjectionPayloadDefinition(
        payload_id="PL-SQL-BOOL-TRUE-01",
        injection_type=InjectionType.SQL,
        context=InjectionContext.SQL_STRING,
        purpose="Safe string boolean true differential probe",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template="' OR '1'='1",
        expected_signals=["BOOLEAN_TRUE_MATCH"],
        max_size_bytes=32,
    ),
    "PL-SQL-BOOL-FALSE-01": InjectionPayloadDefinition(
        payload_id="PL-SQL-BOOL-FALSE-01",
        injection_type=InjectionType.SQL,
        context=InjectionContext.SQL_STRING,
        purpose="Safe string boolean false differential probe",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template="' OR '1'='2",
        expected_signals=["BOOLEAN_FALSE_EMPTY"],
        max_size_bytes=32,
    ),
    "PL-SQL-NUM-TRUE-01": InjectionPayloadDefinition(
        payload_id="PL-SQL-NUM-TRUE-01",
        injection_type=InjectionType.SQL,
        context=InjectionContext.SQL_NUMERIC,
        purpose="Safe unquoted numeric boolean true probe",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template=" OR 1=1",
        expected_signals=["BOOLEAN_TRUE_MATCH"],
        max_size_bytes=32,
    ),
    "PL-SQL-NUM-FALSE-01": InjectionPayloadDefinition(
        payload_id="PL-SQL-NUM-FALSE-01",
        injection_type=InjectionType.SQL,
        context=InjectionContext.SQL_NUMERIC,
        purpose="Safe unquoted numeric boolean false probe",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template=" OR 1=2",
        expected_signals=["BOOLEAN_FALSE_EMPTY"],
        max_size_bytes=32,
    ),
    "PL-SQL-NUM-MATH-01": InjectionPayloadDefinition(
        payload_id="PL-SQL-NUM-MATH-01",
        injection_type=InjectionType.SQL,
        context=InjectionContext.SQL_NUMERIC,
        purpose="Safe arithmetic identity probe (value - 0)",
        mutation_type=MutationType.NUMERIC_MATH,
        raw_template="-0",
        expected_signals=["ARITHMETIC_IDENTITY_PRESERVED"],
        max_size_bytes=16,
    ),
    "PL-SQL-TIME-01": InjectionPayloadDefinition(
        payload_id="PL-SQL-TIME-01",
        injection_type=InjectionType.SQL,
        context=InjectionContext.SQL_STRING,
        purpose="Bounded 1-second delay probe (strictly disabled by default, requires explicit flag)",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template="' OR SLEEP(1)='",
        expected_signals=["TIMING_ANOMALY"],
        risk_level=RiskLevel.INFORMATIVE,
        max_size_bytes=32,
        is_timing=True,
    ),

    # --- NoSQL Injection Payloads ---
    "PL-NOSQL-OP-NE-01": InjectionPayloadDefinition(
        payload_id="PL-NOSQL-OP-NE-01",
        injection_type=InjectionType.NOSQL,
        context=InjectionContext.NOSQL_OPERATOR,
        purpose="Non-destructive NoSQL inequality operator probe",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template='{"$ne": "__bb_nonexistent__"}',
        expected_signals=["NOSQL_BOOLEAN_TRUE", "DATA_EXPANSION"],
        max_size_bytes=64,
    ),
    "PL-NOSQL-OP-EQ-01": InjectionPayloadDefinition(
        payload_id="PL-NOSQL-OP-EQ-01",
        injection_type=InjectionType.NOSQL,
        context=InjectionContext.NOSQL_OPERATOR,
        purpose="Non-destructive NoSQL equality to nonexistent value probe",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template='{"$eq": "__bb_nonexistent__"}',
        expected_signals=["NOSQL_BOOLEAN_FALSE", "DATA_EMPTY"],
        max_size_bytes=64,
    ),
    "PL-NOSQL-PARAM-NE-01": InjectionPayloadDefinition(
        payload_id="PL-NOSQL-PARAM-NE-01",
        injection_type=InjectionType.NOSQL,
        context=InjectionContext.NOSQL_QUERY,
        purpose="Query-parameter style NoSQL operator array probe",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template="[$ne]=__bb_nonexistent__",
        expected_signals=["NOSQL_BOOLEAN_TRUE"],
        max_size_bytes=64,
    ),

    # --- SSTI Payloads (Harmless Arithmetic Evaluation) ---
    "PL-SSTI-MATH-01": InjectionPayloadDefinition(
        payload_id="PL-SSTI-MATH-01",
        injection_type=InjectionType.SSTI,
        context=InjectionContext.TEMPLATE_EXPRESSION,
        purpose="Benign mathematical expression evaluation in double curly syntax ({{7*7}} -> 49)",
        mutation_type=MutationType.NUMERIC_MATH,
        raw_template="{{7*7}}",
        expected_signals=["MATH_EVALUATION_49"],
        max_size_bytes=16,
    ),
    "PL-SSTI-MATH-02": InjectionPayloadDefinition(
        payload_id="PL-SSTI-MATH-02",
        injection_type=InjectionType.SSTI,
        context=InjectionContext.TEMPLATE_EXPRESSION,
        purpose="Benign mathematical expression in dollar syntax (${7*7} -> 49)",
        mutation_type=MutationType.NUMERIC_MATH,
        raw_template="${7*7}",
        expected_signals=["MATH_EVALUATION_49"],
        max_size_bytes=16,
    ),
    "PL-SSTI-MATH-03": InjectionPayloadDefinition(
        payload_id="PL-SSTI-MATH-03",
        injection_type=InjectionType.SSTI,
        context=InjectionContext.TEMPLATE_EXPRESSION,
        purpose="Benign mathematical expression in ERB/ASP syntax (<%= 7*7 %> -> 49)",
        mutation_type=MutationType.NUMERIC_MATH,
        raw_template="<%= 7*7 %>",
        expected_signals=["MATH_EVALUATION_49"],
        max_size_bytes=16,
    ),
    "PL-SSTI-MATH-04": InjectionPayloadDefinition(
        payload_id="PL-SSTI-MATH-04",
        injection_type=InjectionType.SSTI,
        context=InjectionContext.TEMPLATE_EXPRESSION,
        purpose="Benign mathematical expression in hash syntax (#{7*7} -> 49)",
        mutation_type=MutationType.NUMERIC_MATH,
        raw_template="#{7*7}",
        expected_signals=["MATH_EVALUATION_49"],
        max_size_bytes=16,
    ),

    # --- Command Injection Foundation (Safe Token Only) ---
    "PL-CMD-CANARY-01": InjectionPayloadDefinition(
        payload_id="PL-CMD-CANARY-01",
        injection_type=InjectionType.COMMAND,
        context=InjectionContext.COMMAND_ARGUMENT,
        purpose="Safe non-executable canary marker to assess argument parsing boundary without OS execution",
        mutation_type=MutationType.BOUNDARY_STRING,
        raw_template="bbcmd_{TOKEN}",
        expected_signals=["CAPABILITY_REQUIRES_SPECIALIZED_VALIDATION"],
        risk_level=RiskLevel.SAFE,
        max_size_bytes=32,
    ),
}


class InjectionPayloadRegistry:
    """Registry and query interface for injection payloads."""

    @classmethod
    def get_payload(cls, payload_id: str) -> Optional[InjectionPayloadDefinition]:
        return INJECTION_PAYLOADS.get(payload_id)

    @classmethod
    def get_payloads_for_type(
        cls,
        injection_type: InjectionType | str,
        include_timing: bool = False,
    ) -> List[InjectionPayloadDefinition]:
        target = (
            injection_type if isinstance(injection_type, InjectionType)
            else InjectionType.from_string(str(injection_type))
        )
        results = []
        for p in INJECTION_PAYLOADS.values():
            if p.injection_type == target:
                if p.is_timing and not include_timing:
                    continue
                results.append(p)
        return results

    @classmethod
    def list_all(cls) -> List[InjectionPayloadDefinition]:
        return list(INJECTION_PAYLOADS.values())
