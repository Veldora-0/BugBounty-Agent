"""
XSS Validators for BugBounty-Agent Validation Engine.

Provides context-aware Reflected, DOM, and Stored XSS validators that eliminate
false positives through fine-grained HTML/JS lexical context analysis, never
prematurely jumping to VALIDATED without execution proof, and safely discarding
defended entity-encoded reflections.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.validation.baseline import BaselineComparison, BaselineObservation
from framework.validation.model import RiskLevel, SecurityTestCase, ValidationResult, VulnerabilityFamily
from framework.validation.payload import PayloadRegistry
from framework.validation.request import ControlledResponse
from framework.validation.validator import BaseValidator
from framework.xss.context import HtmlContextAnalyzer
from framework.xss.dom import DomXssEngine
from framework.xss.model import (
    ReflectionState,
    XssCandidate,
    XssCategory,
    XssConfidence,
    XssContextType,
)


class ReflectedXssContextValidator(BaseValidator):
    """
    Context-aware Reflected XSS Validator.
    Uses harmless canary probes, analyzes lexical response context,
    and rejects defended/encoded reflections to eliminate false positives.
    """

    def __init__(self):
        super().__init__(
            validator_id="reflected-xss",
            vulnerability_family=VulnerabilityFamily.XSS,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        return bool(parameter) or "?" in endpoint

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        payload = PayloadRegistry.get_payload("PL-XSS-REFL-01")
        if not payload:
            return []

        return [
            SecurityTestCase(
                vulnerability_family=self.vulnerability_family,
                target=target,
                endpoint=endpoint,
                method="GET",
                parameter=parameter,
                payload_identifier=payload.payload_id,
                test_strategy="context_aware_marker",
                risk_level=RiskLevel.SAFE,
                request_budget=2,
                expected_signals=["MARKER_REFLECTED"],
                provenance=provenance,
            )
        ]

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        token = comparison.injected_token

        # Perform lexical context analysis
        content_type = response.headers.get("content-type", "text/html")
        analysis = HtmlContextAnalyzer.analyze(
            response_body=response.body,
            canary_token=token,
            content_type=content_type,
        )

        if not analysis.canary_reflected:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=["NO_REFLECTION"],
                evidence_summary="Test canary was not reflected in the HTTP response body.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # Check defensive encoding (False Positive Elimination)
        if analysis.is_defended:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=["DEFENDED_BY_ENCODING", f"CONTEXT_{analysis.context_type.value}"],
                evidence_summary=(
                    f"Canary was reflected but properly neutralized by contextual encoding "
                    f"({analysis.reflection_state.value}) in {analysis.context_type.value} context. Discarded as defended."
                ),
                confidence="REJECTED",
                severity="INFORMATIONAL",
            )
            return result, None

        # Unencoded reflection observed
        ctx = analysis.context_type.value
        signals = [f"REFLECTED_IN_{ctx}", f"STATE_{analysis.reflection_state.value}"]

        if analysis.context_type in (XssContextType.SCRIPT_BLOCK, XssContextType.EVENT_HANDLER):
            severity = "HIGH"
            confidence = "SUSPECTED"
            summary = f"Unencoded canary reflected inside {ctx} for parameter '{test_case.parameter}'."
        elif analysis.context_type == XssContextType.HTML_ATTRIBUTE and analysis.is_exploitable_context:
            severity = "MEDIUM"
            confidence = "SUSPECTED"
            summary = f"Unencoded canary reflected in HTML attribute with unescaped delimiters for parameter '{test_case.parameter}'."
        else:
            severity = "MEDIUM"
            confidence = "OBSERVED"
            summary = f"Canary reflected in {ctx} without verified execution proof for parameter '{test_case.parameter}'."

        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.OBSERVED,
            signals_observed=signals,
            evidence_summary=summary,
            confidence=confidence,
            severity=severity,
        )

        finding = Finding(
            title=f"Potential Reflected XSS Context on {test_case.endpoint} ({test_case.parameter or 'input'})",
            summary=summary,
            affected_asset=test_case.target,
            affected_endpoint=test_case.endpoint,
            vulnerability_type="Cross-Site Scripting (Reflected)",
            severity=severity,
            confidence=confidence,
            lifecycle_state=FindingLifecycle.OBSERVED,
            description=(
                f"Controlled input marker injected into parameter '{test_case.parameter}' was reflected in the HTTP "
                f"response in syntactic context '{ctx}'. Contextual analysis indicates raw characters are unencoded. "
                f"Remains OBSERVED per hypothesis-driven safe research rules."
            ),
            root_cause=f"User-supplied input reflected in {ctx} without context-sensitive output encoding.",
            prerequisites="Target endpoint accessible over HTTP/HTTPS.",
            reproduction_steps=[
                f"Send baseline GET request to '{test_case.endpoint}'.",
                f"Inject harmless canary marker '{token}' into parameter '{test_case.parameter}'.",
                f"Inspect HTTP response body to observe unencoded reflection in context '{ctx}'.",
            ],
            expected_result="Input is sanitized or contextually escaped (e.g. HTML entity or JS escape).",
            observed_result=f"Input marker was reflected with state '{analysis.reflection_state.value}' in '{ctx}'.",
            security_impact="If untrusted JavaScript executes in victim browser context, session tokens or DOM state may be exposed.",
            remediation="Implement strict context-aware output encoding and configure Content-Security-Policy (CSP).",
            scope_reference=f"Target {test_case.target} authorized in scope",
        )

        return result, finding


class DomXssValidator(BaseValidator):
    """
    DOM XSS Validator based on static source-to-sink intelligence and data flow.
    """

    def __init__(self):
        super().__init__(
            validator_id="dom-xss",
            vulnerability_family=VulnerabilityFamily.XSS,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        return endpoint.endswith(".js") or ".js?" in endpoint or "inline" in endpoint or bool(parameter)

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        return [
            SecurityTestCase(
                vulnerability_family=self.vulnerability_family,
                target=target,
                endpoint=endpoint,
                method="GET",
                parameter=parameter or "dom_source",
                payload_identifier="PL-DOM-STATIC",
                test_strategy="dom_source_sink_analysis",
                risk_level=RiskLevel.SAFE,
                request_budget=1,
                expected_signals=["DOM_SOURCE_TO_SINK"],
                provenance=provenance,
            )
        ]

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        candidates = DomXssEngine.analyze_script_text(
            script_content=response.body,
            file_path=test_case.endpoint,
            target_asset=test_case.target,
            endpoint=test_case.endpoint,
        )

        if not candidates:
            return ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=["NO_DOM_SINK"],
                evidence_summary="No dangerous DOM sinks or unmitigated source-to-sink flows identified.",
            ), None

        primary = candidates[0]
        finding = Finding(
            title=f"Potential DOM XSS via {primary.sink.name if primary.sink else 'DOM Sink'} on {test_case.endpoint}",
            summary=primary.notes,
            affected_asset=test_case.target,
            affected_endpoint=test_case.endpoint,
            vulnerability_type="Cross-Site Scripting (DOM-Based)",
            severity=primary.severity,
            confidence=primary.confidence.value,
            lifecycle_state=FindingLifecycle.OBSERVED,
            description=primary.notes,
            root_cause="Untrusted client-side data from DOM source flows into an unmitigated execution or markup sink.",
            prerequisites="Target script executed in victim browser.",
            reproduction_steps=[
                f"Inspect script at '{test_case.endpoint}'.",
                f"Locate DOM sink '{primary.sink.name if primary.sink else 'sink'}'.",
                f"Verify input path from DOM source '{primary.source.name if primary.source else 'source'}'.",
            ],
            expected_result="Untrusted input is sanitized via DOMPurify or safe properties like textContent are used.",
            observed_result=f"Static trace indicates potentially unmitigated data flow to sink.",
            security_impact="Client-side DOM manipulation or arbitrary script execution in victim browser context.",
            remediation="Use textContent instead of innerHTML, or sanitize untrusted input with DOMPurify.",
            scope_reference=f"Target {test_case.target} authorized in scope",
        )

        return ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.OBSERVED,
            signals_observed=["DOM_CANDIDATE_IDENTIFIED"],
            evidence_summary=primary.notes,
            confidence=primary.confidence.value,
            severity=primary.severity,
        ), finding
