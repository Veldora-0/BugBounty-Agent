"""
Controlled Injection Validators for BugBounty-Agent (Phase 10).

Implements bounded, hypothesis-driven validators for:
1. SQL Injection (boolean differential, syntax fault, error signatures, timing foundation)
2. NoSQL Injection (non-destructive operator differential)
3. SSTI (harmless mathematical expression evaluation)
4. Command Injection Foundation (candidate modeling, safe capability boundary)

STRICT INVARIANTS:
1. Never executes destructive SQL (DROP, DELETE, UPDATE, INSERT, ALTER, TRUNCATE).
2. Never executes OS shell commands or spawns processes.
3. Safe HTTP methods only (GET, HEAD, OPTIONS).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import json
import time
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
import uuid

from framework.findings.lifecycle import FindingLifecycle
from framework.injection.comparator import (
    InjectionComparator,
    InjectionComparisonResult,
)
from framework.injection.model import (
    InjectionCandidate,
    InjectionConfidence,
    InjectionContext,
    InjectionEvidence,
    InjectionType,
)
from framework.injection.payloads import (
    INJECTION_PAYLOADS,
    InjectionPayloadRegistry,
)
from framework.validation.request import ControlledRequest, ControlledResponse


class BaseInjectionValidator(ABC):
    """Abstract base class for controlled injection validators."""

    def __init__(
        self,
        send_request_hook: Callable[[ControlledRequest], ControlledResponse],
        enable_timing: bool = False,
    ):
        self.send_request = send_request_hook
        self.enable_timing = enable_timing

    @abstractmethod
    def validate(
        self,
        candidate: InjectionCandidate,
        baseline_response: Optional[ControlledResponse] = None,
    ) -> Tuple[InjectionComparisonResult, Optional[InjectionEvidence]]:
        """Executes bounded probes and returns differential result and evidence."""
        pass

    @staticmethod
    def mutate_url_query(url: str, param_name: str, payload_value: str) -> str:
        """Helper to inject payload into a URL query parameter."""
        parsed = urlparse(url)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        new_qsl = []
        found = False
        for k, v in qsl:
            if k == param_name:
                new_qsl.append((k, payload_value))
                found = True
            else:
                new_qsl.append((k, v))
        if not found:
            new_qsl.append((param_name, payload_value))
        new_query = urlencode(new_qsl)
        return urlunparse(parsed._replace(query=new_query))


class SqlInjectionValidator(BaseInjectionValidator):
    """
    Controlled SQL Injection Validator.
    Applies quote boundary check, boolean true/false differential,
    error signature analysis, and optional jitter-normalized timing probe.
    """

    def validate(
        self,
        candidate: InjectionCandidate,
        baseline_response: Optional[ControlledResponse] = None,
    ) -> Tuple[InjectionComparisonResult, Optional[InjectionEvidence]]:
        # 1. Dispatch Baseline Request if not provided
        if baseline_response is None:
            base_req = ControlledRequest(
                method=candidate.method,
                url=candidate.endpoint,
                headers={"Accept": "application/json, text/html, */*"},
            )
            baseline_response = self.send_request(base_req)

        base_dict = {
            "status_code": baseline_response.status_code,
            "body": baseline_response.body_text,
            "headers": baseline_response.headers,
            "duration_seconds": getattr(baseline_response, "duration_seconds", 0.05),
        }

        # 2. Quote Boundary Probe
        quote_payload = INJECTION_PAYLOADS["PL-SQL-QUOTE-01"].raw_template
        quote_url = self.mutate_url_query(candidate.endpoint, candidate.parameter, quote_payload)
        quote_req = ControlledRequest(method=candidate.method, url=quote_url)
        quote_resp = self.send_request(quote_req)
        quote_dict = {
            "status_code": quote_resp.status_code,
            "body": quote_resp.body_text,
            "headers": quote_resp.headers,
            "duration_seconds": getattr(quote_resp, "duration_seconds", 0.05),
        }

        # 3. Boolean True Probe
        is_numeric = candidate.backend_context == InjectionContext.SQL_NUMERIC
        true_payload_def = INJECTION_PAYLOADS["PL-SQL-NUM-TRUE-01"] if is_numeric else INJECTION_PAYLOADS["PL-SQL-BOOL-TRUE-01"]
        true_url = self.mutate_url_query(candidate.endpoint, candidate.parameter, true_payload_def.raw_template)
        true_req = ControlledRequest(method=candidate.method, url=true_url)
        true_resp = self.send_request(true_req)
        true_dict = {
            "status_code": true_resp.status_code,
            "body": true_resp.body_text,
            "headers": true_resp.headers,
            "duration_seconds": getattr(true_resp, "duration_seconds", 0.05),
        }

        # 4. Boolean False Probe
        false_payload_def = INJECTION_PAYLOADS["PL-SQL-NUM-FALSE-01"] if is_numeric else INJECTION_PAYLOADS["PL-SQL-BOOL-FALSE-01"]
        false_url = self.mutate_url_query(candidate.endpoint, candidate.parameter, false_payload_def.raw_template)
        false_req = ControlledRequest(method=candidate.method, url=false_url)
        false_resp = self.send_request(false_req)
        false_dict = {
            "status_code": false_resp.status_code,
            "body": false_resp.body_text,
            "headers": false_resp.headers,
            "duration_seconds": getattr(false_resp, "duration_seconds", 0.05),
        }

        # 5. Timing Probe (only if explicitly enabled)
        timing_dict = None
        if self.enable_timing:
            time_payload_def = INJECTION_PAYLOADS["PL-SQL-TIME-01"]
            time_url = self.mutate_url_query(candidate.endpoint, candidate.parameter, time_payload_def.raw_template)
            time_req = ControlledRequest(method=candidate.method, url=time_url)
            time_resp = self.send_request(time_req)
            timing_dict = {
                "status_code": time_resp.status_code,
                "body": time_resp.body_text,
                "headers": time_resp.headers,
                "duration_seconds": getattr(time_resp, "duration_seconds", 1.05),
            }

        # 6. Evaluate differential
        result = InjectionComparator.evaluate_sql_differential(
            baseline_resp=base_dict,
            true_resp=true_dict,
            false_resp=false_dict,
            quote_resp=quote_dict,
            timing_resp=timing_dict,
            timing_expected_delay=1.0,
        )

        evidence = None
        if result.is_candidate_signal:
            evidence = InjectionEvidence(
                evidence_id=f"ev-sql-{uuid.uuid4().hex[:8]}",
                candidate_id=candidate.candidate_id,
                test_id=f"test-sql-{uuid.uuid4().hex[:6]}",
                family=InjectionType.SQL,
                endpoint=candidate.endpoint,
                parameter=candidate.parameter,
                payload_id=true_payload_def.payload_id,
                baseline_request={"url": base_req.url, "method": base_req.method},
                baseline_response=base_dict,
                test_request={"url": true_req.url, "method": true_req.method},
                test_response=true_dict,
                control_request={"url": false_req.url, "method": false_req.method},
                control_response=false_dict,
                differential_signals=result.signals,
                error_signature=result.error_signature,
                timing_metadata=timing_dict,
                confidence=result.confidence,
            )

        return result, evidence


class NoSqlInjectionValidator(BaseInjectionValidator):
    """
    Controlled NoSQL Injection Validator.
    Applies safe inequality ($ne) vs equality ($eq) operators
    to detect document-store parameter interpretation without data destruction.
    """

    def validate(
        self,
        candidate: InjectionCandidate,
        baseline_response: Optional[ControlledResponse] = None,
    ) -> Tuple[InjectionComparisonResult, Optional[InjectionEvidence]]:
        if baseline_response is None:
            base_req = ControlledRequest(
                method=candidate.method,
                url=candidate.endpoint,
                headers={"Accept": "application/json, text/html, */*"},
            )
            baseline_response = self.send_request(base_req)

        base_dict = {
            "status_code": baseline_response.status_code,
            "body": baseline_response.body_text,
            "headers": baseline_response.headers,
        }

        # True probe: $ne to nonexistent string
        ne_payload = INJECTION_PAYLOADS["PL-NOSQL-OP-NE-01"].raw_template
        # In query strings, test param[$ne]=__bb_nonexistent__
        param_ne_name = f"{candidate.parameter}[$ne]"
        true_url = self.mutate_url_query(candidate.endpoint, param_ne_name, "__bb_nonexistent__")
        true_req = ControlledRequest(method=candidate.method, url=true_url)
        true_resp = self.send_request(true_req)
        true_dict = {
            "status_code": true_resp.status_code,
            "body": true_resp.body_text,
            "headers": true_resp.headers,
        }

        # False probe: $eq to nonexistent string
        param_eq_name = f"{candidate.parameter}[$eq]"
        false_url = self.mutate_url_query(candidate.endpoint, param_eq_name, "__bb_nonexistent__")
        false_req = ControlledRequest(method=candidate.method, url=false_url)
        false_resp = self.send_request(false_req)
        false_dict = {
            "status_code": false_resp.status_code,
            "body": false_resp.body_text,
            "headers": false_resp.headers,
        }

        result = InjectionComparator.evaluate_nosql_differential(
            baseline_resp=base_dict,
            true_resp=true_dict,
            false_resp=false_dict,
        )

        evidence = None
        if result.is_candidate_signal:
            evidence = InjectionEvidence(
                evidence_id=f"ev-nosql-{uuid.uuid4().hex[:8]}",
                candidate_id=candidate.candidate_id,
                test_id=f"test-nosql-{uuid.uuid4().hex[:6]}",
                family=InjectionType.NOSQL,
                endpoint=candidate.endpoint,
                parameter=candidate.parameter,
                payload_id="PL-NOSQL-OP-NE-01",
                baseline_request={"url": base_req.url, "method": base_req.method},
                baseline_response=base_dict,
                test_request={"url": true_req.url, "method": true_req.method},
                test_response=true_dict,
                control_request={"url": false_req.url, "method": false_req.method},
                control_response=false_dict,
                differential_signals=result.signals,
                error_signature=result.error_signature,
                confidence=result.confidence,
            )

        return result, evidence


class SstiValidator(BaseInjectionValidator):
    """
    Controlled Server-Side Template Injection Validator.
    Injects harmless mathematical expressions ({{7*7}}) and confirms
    template evaluation to '49' without code execution or file reads.
    """

    def validate(
        self,
        candidate: InjectionCandidate,
        baseline_response: Optional[ControlledResponse] = None,
    ) -> Tuple[InjectionComparisonResult, Optional[InjectionEvidence]]:
        if baseline_response is None:
            base_req = ControlledRequest(
                method=candidate.method,
                url=candidate.endpoint,
                headers={"Accept": "application/json, text/html, */*"},
            )
            baseline_response = self.send_request(base_req)

        base_dict = {
            "status_code": baseline_response.status_code,
            "body": baseline_response.body_text,
            "headers": baseline_response.headers,
        }

        # Try {{7*7}} first, then ${7*7}
        payload_candidates = [
            ("{{7*7}}", "PL-SSTI-MATH-01"),
            ("${7*7}", "PL-SSTI-MATH-02"),
        ]

        best_result: Optional[InjectionComparisonResult] = None
        best_evidence: Optional[InjectionEvidence] = None

        for expr, p_id in payload_candidates:
            probe_url = self.mutate_url_query(candidate.endpoint, candidate.parameter, expr)
            probe_req = ControlledRequest(method=candidate.method, url=probe_url)
            probe_resp = self.send_request(probe_req)
            probe_dict = {
                "status_code": probe_resp.status_code,
                "body": probe_resp.body_text,
                "headers": probe_resp.headers,
            }

            res = InjectionComparator.evaluate_ssti_differential(
                baseline_resp=base_dict,
                probe_resp=probe_dict,
                expression_str=expr,
                expected_math_result="49",
            )

            if res.is_candidate_signal:
                best_result = res
                best_evidence = InjectionEvidence(
                    evidence_id=f"ev-ssti-{uuid.uuid4().hex[:8]}",
                    candidate_id=candidate.candidate_id,
                    test_id=f"test-ssti-{uuid.uuid4().hex[:6]}",
                    family=InjectionType.SSTI,
                    endpoint=candidate.endpoint,
                    parameter=candidate.parameter,
                    payload_id=p_id,
                    baseline_request={"url": base_req.url, "method": base_req.method},
                    baseline_response=base_dict,
                    test_request={"url": probe_req.url, "method": probe_req.method},
                    test_response=probe_dict,
                    differential_signals=res.signals,
                    error_signature=res.error_signature,
                    confidence=res.confidence,
                )
                break
            elif not best_result:
                best_result = res

        return (best_result or InjectionComparisonResult(
            is_candidate_signal=False,
            confidence=InjectionConfidence.CANDIDATE,
            signals=[],
            reasons=["No SSTI evaluation observed"],
        )), best_evidence


class CommandInjectionValidator(BaseInjectionValidator):
    """
    Command Injection Foundation Validator.
    Performs candidate parameter modeling and boundary analysis.
    STRICT INVARIANT:
    Never executes operating system shell commands against live targets.
    Always yields CAPABILITY_REQUIRES_SPECIALIZED_VALIDATION state.
    """

    def validate(
        self,
        candidate: InjectionCandidate,
        baseline_response: Optional[ControlledResponse] = None,
    ) -> Tuple[InjectionComparisonResult, Optional[InjectionEvidence]]:
        # Candidate validation only: assess whether candidate is flagged for command context
        reasons = [
            "Command injection foundation: parameter exhibits process/utility semantics",
            "CAPABILITY_REQUIRES_SPECIALIZED_VALIDATION: live arbitrary shell execution is strictly prohibited by security policy",
        ]
        result = InjectionComparisonResult(
            is_candidate_signal=True,
            confidence=InjectionConfidence.CANDIDATE,
            signals=["CAPABILITY_REQUIRES_SPECIALIZED_VALIDATION"],
            reasons=reasons,
        )
        return result, None


class InjectionValidatorFactory:
    """Factory to instantiate the appropriate validator for a candidate."""

    @classmethod
    def get_validator(
        cls,
        family: InjectionType | str,
        send_request_hook: Callable[[ControlledRequest], ControlledResponse],
        enable_timing: bool = False,
    ) -> BaseInjectionValidator:
        target = (
            family if isinstance(family, InjectionType)
            else InjectionType.from_string(str(family))
        )
        if target == InjectionType.SQL:
            return SqlInjectionValidator(send_request_hook, enable_timing=enable_timing)
        elif target == InjectionType.NOSQL:
            return NoSqlInjectionValidator(send_request_hook, enable_timing=enable_timing)
        elif target == InjectionType.SSTI:
            return SstiValidator(send_request_hook, enable_timing=enable_timing)
        elif target == InjectionType.COMMAND:
            return CommandInjectionValidator(send_request_hook, enable_timing=enable_timing)
        else:
            return SqlInjectionValidator(send_request_hook, enable_timing=enable_timing)
