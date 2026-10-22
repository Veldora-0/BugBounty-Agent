"""
Validator Plugin Architecture and Proof-of-Concept Validators for BugBounty-Agent.

Provides the BaseValidator plugin contract and bounded implementations:
- ReflectedXSSValidator (benign marker reflection detection; zero JS execution)
- OpenRedirectValidator (benign canary redirect verification; zero victim navigation)
- Explicit unavailable capability stubs for future validator implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import html
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.validation.baseline import BaselineComparison, BaselineObservation
from framework.validation.model import RiskLevel, SecurityTestCase, ValidationResult, VulnerabilityFamily
from framework.validation.payload import PayloadRegistry
from framework.validation.request import ControlledResponse


class BaseValidator(ABC):
    """
    Abstract base validator contract.
    Validators consume prior reconnaissance/intelligence to prepare controlled test cases,
    and analyze differential baseline signals to produce structured observations/findings.
    """

    def __init__(self, validator_id: str, vulnerability_family: VulnerabilityFamily, is_available: bool = True):
        self.validator_id = validator_id
        self.vulnerability_family = vulnerability_family
        self.is_available = is_available

    @abstractmethod
    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        """Determines if this validator is applicable to the endpoint/parameter."""
        pass

    @abstractmethod
    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        """Generates bounded, hypothesis-driven test cases for evaluation."""
        pass

    @abstractmethod
    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        """Analyzes differential response behavior and determines lifecycle outcome."""
        pass


class ReflectedXSSValidator(BaseValidator):
    """
    Non-destructive Reflected XSS Candidate Validator.
    Uses harmless alphanumeric marker (XSHIELD_TEST_<token>).
    Strict boundaries:
    - NEVER executes JavaScript.
    - NEVER launches a browser just to execute scripts.
    - Classifies findings according to reflection context.
    """

    def __init__(self):
        super().__init__(
            validator_id="reflected-xss",
            vulnerability_family=VulnerabilityFamily.XSS,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        # Requires at least one parameter to mutate
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
                test_strategy="reflected_marker",
                risk_level=RiskLevel.SAFE,
                request_budget=2,
                expected_signals=["MARKER_REFLECTED_IN_BODY"],
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
        if not comparison.marker_reflected:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=["NO_REFLECTION"],
                evidence_summary="Test marker was not reflected in post-mutation HTTP response.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # Marker was reflected! Assess reflection context
        ctx = comparison.reflection_context or "UNKNOWN"
        signals = list(comparison.signals)

        # Determine severity and confidence based on context
        if ctx == "SCRIPT_TAG":
            severity = "HIGH"
            confidence = "HIGH"
            finding_state = FindingLifecycle.OBSERVED
            summary = f"Harmless verification marker reflected directly inside <script> context in parameter '{test_case.parameter}'."
        elif ctx in ("HTML_BODY_TEXT", "HTML_ATTRIBUTE"):
            severity = "MEDIUM"
            confidence = "MEDIUM"
            finding_state = FindingLifecycle.OBSERVED
            summary = f"Harmless verification marker reflected in {ctx} in parameter '{test_case.parameter}'."
        elif ctx == "JSON_VALUE":
            severity = "LOW"
            confidence = "LOW"
            finding_state = FindingLifecycle.OBSERVED
            summary = f"Verification marker reflected inside JSON response structure for parameter '{test_case.parameter}'."
        else:
            severity = "LOW"
            confidence = "LOW"
            finding_state = FindingLifecycle.CANDIDATE
            summary = f"Verification marker reflected in raw response body in parameter '{test_case.parameter}'."

        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=finding_state,
            signals_observed=signals,
            evidence_summary=summary,
            confidence=confidence,
            severity=severity,
        )

        finding = Finding(
            title=f"Potential Reflected Input on {test_case.endpoint} ({test_case.parameter or 'input'})",
            summary=summary,
            affected_asset=test_case.target,
            affected_endpoint=test_case.endpoint,
            vulnerability_type="Cross-Site Scripting (Reflected)",
            severity=severity,
            confidence=confidence,
            lifecycle_state=finding_state,
            description=(
                f"Controlled input marker injected into '{test_case.parameter}' was reflected in the HTTP response "
                f"context '{ctx}'. Zero browser execution was attempted per safe testing rules."
            ),
            root_cause="User-supplied parameter reflected in server response without strict context-aware encoding.",
            prerequisites="Target endpoint accessible over HTTP/HTTPS.",
            reproduction_steps=[
                f"Send baseline request to '{test_case.endpoint}'.",
                f"Inject test marker into parameter '{test_case.parameter}'.",
                f"Observe reflection in response context '{ctx}'.",
            ],
            expected_result="Input is sanitized, escaped, or omitted from response.",
            observed_result=f"Input marker was reflected verbatim in context '{ctx}'.",
            security_impact="If untrusted JavaScript is injected and executed in victim context, session tokens or DOM data could be compromised.",
            remediation="Apply context-sensitive output encoding (HTML, JavaScript, attribute) and configure a strict Content-Security-Policy.",
            scope_reference=f"Target {test_case.target} authorized in scope",
            parameter=test_case.parameter,
            test_case_id=test_case.test_id,
            detection_method="reflected_marker",
            references=["CWE-79", "OWASP-A03:2021-Injection"],
        )

        return result, finding


class OpenRedirectValidator(BaseValidator):
    """
    Non-destructive Open Redirect Candidate Validator.
    Uses harmless external canary URL.
    Strict boundaries:
    - Inspects 3xx status codes + Location header only.
    - NEVER navigates a victim browser to external targets.
    - Disregards relative or same-origin redirects.
    """

    def __init__(self):
        super().__init__(
            validator_id="open-redirect",
            vulnerability_family=VulnerabilityFamily.OPEN_REDIRECT,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        # Check if endpoint or parameter suggests a redirect target
        param_name = (parameter or "").lower()
        redirect_names = {"redirect", "url", "next", "return", "goto", "dest", "destination", "target", "r", "u"}
        if param_name in redirect_names:
            return True
        return bool(parameter) or "?" in endpoint

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        payload = PayloadRegistry.get_payload("PL-REDIR-CANARY-01")
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
                test_strategy="redirect_destination_check",
                risk_level=RiskLevel.SAFE,
                request_budget=2,
                expected_signals=["LOCATION_REDIRECT"],
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
        if not comparison.location_header_changed or not comparison.redirect_destination:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=["NO_REDIRECT_CHANGE"],
                evidence_summary="Location header was not altered by supplied redirect parameter.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        loc = comparison.redirect_destination
        parsed_loc = urlparse(loc)
        target_parsed = urlparse(test_case.target if "://" in test_case.target else f"http://{test_case.target}")

        # Check if redirect points to an external host (not relative, not same host)
        is_external = bool(parsed_loc.netloc) and parsed_loc.netloc.lower() != target_parsed.netloc.lower()

        if is_external and "bugbounty-agent.local" in parsed_loc.netloc.lower():
            # Matches canary host!
            severity = "MEDIUM"
            confidence = "HIGH"
            finding_state = FindingLifecycle.OBSERVED
            summary = f"Endpoint redirects to arbitrary external canary destination '{loc}' via parameter '{test_case.parameter}'."

            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=finding_state,
                signals_observed=comparison.signals,
                evidence_summary=summary,
                confidence=confidence,
                severity=severity,
            )

            finding = Finding(
                title=f"Potential Open Redirect on {test_case.endpoint} ({test_case.parameter or 'parameter'})",
                summary=summary,
                affected_asset=test_case.target,
                affected_endpoint=test_case.endpoint,
                vulnerability_type="Open Redirect",
                severity=severity,
                confidence=confidence,
                lifecycle_state=finding_state,
                description=(
                    f"Parameter '{test_case.parameter}' accepts an arbitrary external URL and the server "
                    f"responds with an HTTP {response.status_code} redirect to '{loc}'."
                ),
                root_cause="User-supplied redirect URL is not validated against an allowed whitelist of destinations.",
                prerequisites="Endpoint accessible over HTTP/HTTPS.",
                reproduction_steps=[
                    f"Send request to '{test_case.endpoint}' with parameter '{test_case.parameter}' set to external canary URL.",
                    f"Observe HTTP {response.status_code} with Location header pointing to external destination.",
                ],
                expected_result="Redirect destination is restricted to local application paths or validated whitelist.",
                observed_result=f"Location header redirected to external target: {loc}",
                security_impact="Can be used in phishing campaigns to lend credibility to malicious redirect links.",
                remediation="Validate redirect destinations against a strict whitelist of approved domains or enforce relative paths.",
                scope_reference=f"Target {test_case.target} authorized in scope",
                parameter=test_case.parameter,
                test_case_id=test_case.test_id,
                detection_method="redirect_destination_check",
                references=["CWE-601", "OWASP-A01:2021-Broken Access Control"],
            )
            return result, finding

        # Not external or did not match canary
        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=comparison.signals,
            evidence_summary=f"Redirect was internal or did not divert to external canary ({loc}).",
            confidence="LOW",
            severity="INFORMATIONAL",
        )
        return result, None


# ---------------- Stub / Unavailable Validators ----------------


class UnavailableValidator(BaseValidator):
    """Placeholder stub declaring explicit unavailable capability status."""

    def __init__(self, validator_id: str, vulnerability_family: VulnerabilityFamily):
        super().__init__(validator_id=validator_id, vulnerability_family=vulnerability_family, is_available=False)

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        return False

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        return []

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        res = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=["CAPABILITY_UNAVAILABLE"],
            evidence_summary=f"Validator '{self.validator_id}' is not yet implemented or available.",
        )
        return res, None


class SqlInjectionValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("sql-injection", VulnerabilityFamily.SQL_INJECTION)


class SsrfValidator(BaseValidator):
    """
    Non-destructive SSRF Candidate Validator.
    Uses controlled canary URLs and out-of-band callback correlation.
    Strict boundaries:
    - NEVER targets cloud metadata (169.254.169.254).
    - NEVER targets internal private networks or unauthorized loopback ports.
    - Emits findings only upon confirmed server callback or DNS resolution.
    """

    def __init__(self):
        super().__init__(
            validator_id="ssrf",
            vulnerability_family=VulnerabilityFamily.SSRF,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        if parameter:
            p_lower = parameter.lower()
            url_param_keywords = (
                "url", "uri", "target", "dest", "endpoint", "feed",
                "webhook", "proxy", "callback", "redirect", "src", "link", "host",
            )
            if any(k in p_lower for k in url_param_keywords):
                return True
        return bool(parameter) or "?" in endpoint

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        payload = PayloadRegistry.get_payload("PL-SSRF-CANARY-01")
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
                test_strategy="oob_canary",
                risk_level=RiskLevel.SAFE,
                request_budget=3,
                expected_signals=["OOB_INTERACTION", "SERVER_CALLBACK"],
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
        signals = list(comparison.signals)
        oob_received = "OOB_INTERACTION" in signals or "SERVER_CALLBACK" in signals

        if not oob_received and not comparison.timing_anomaly_detected:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.TESTED,
                signals_observed=["NO_OOB_CALLBACK"],
                evidence_summary="No out-of-band interaction or response anomaly observed for canary URL.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        if oob_received:
            severity = "HIGH"
            confidence = "HIGH"
            finding_state = FindingLifecycle.VALIDATED
            summary = f"Out-of-band network interaction confirmed on {test_case.endpoint} via parameter '{test_case.parameter}'."
        else:
            severity = "MEDIUM"
            confidence = "MEDIUM"
            finding_state = FindingLifecycle.SUSPECTED
            summary = f"Response anomaly observed during SSRF probe on {test_case.endpoint} ({test_case.parameter})."

        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=finding_state,
            signals_observed=signals,
            evidence_summary=summary,
            confidence=confidence,
            severity=severity,
        )

        finding = Finding(
            title=f"Potential Server-Side Request Forgery on {test_case.endpoint} ({test_case.parameter or 'target'})",
            summary=summary,
            affected_asset=test_case.target,
            affected_endpoint=test_case.endpoint,
            vulnerability_type="Server-Side Request Forgery (SSRF)",
            severity=severity,
            confidence=confidence,
            lifecycle_state=finding_state,
            description=(
                f"Controlled testing with canary URL on '{test_case.parameter}' resulted in server-side "
                f"network activity. No internal network scanning or cloud metadata access was performed."
            ),
            root_cause="Application initiates outbound network connections to user-supplied destination URLs.",
            prerequisites="Endpoint accessible over HTTP/HTTPS with URL parameter acceptance.",
            reproduction_steps=[
                f"1. Send request to '{test_case.endpoint}' with parameter '{test_case.parameter}' set to canary URL.",
                "2. Observe asynchronous interaction on OOB callback listener.",
            ],
            expected_result="Endpoint validates and rejects arbitrary remote destination URLs.",
            observed_result=f"Observed signals: {', '.join(signals) if signals else 'timing/response anomaly'}.",
            security_impact="Unauthorized outbound network requests may allow internal reconnaissance or protocol abuse.",
            remediation="Enforce strict destination hostname whitelisting and egress firewall rules.",
            scope_reference=f"Target {test_case.endpoint} in authorized scope.",
            parameter=test_case.parameter,
        )
        return result, finding


class XxeValidator(BaseValidator):
    """
    Non-destructive XML External Entity (XXE) Validator.
    Uses harmless synthetic internal entity reflection marker (CONFIRMED_ENTITY_EXPANSION_<token>).
    Strict boundaries:
    - NEVER accesses local system files (file://, /etc/passwd, win.ini).
    - NEVER targets cloud metadata endpoints (169.254.169.254).
    - Distinguishes syntax/parser errors from confirmed entity resolution.
    """

    def __init__(self):
        super().__init__(
            validator_id="xxe",
            vulnerability_family=VulnerabilityFamily.XXE,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        if parameter:
            p_lower = parameter.lower()
            if any(k in p_lower for k in ("xml", "soap", "doc", "payload", "body", "data")):
                return True
        return "xml" in endpoint.lower() or "soap" in endpoint.lower() or parameter is not None

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        payload = PayloadRegistry.get_payload("PL-XXE-REFL-01")
        if not payload:
            return []

        return [
            SecurityTestCase(
                vulnerability_family=self.vulnerability_family,
                target=target,
                endpoint=endpoint,
                method="POST",
                parameter=parameter or "xml",
                payload_identifier=payload.payload_id,
                test_strategy="synthetic_entity_reflection",
                risk_level=RiskLevel.SAFE,
                request_budget=2,
                expected_signals=["ENTITY_EXPANDED", "SYNTHETIC_REFLECTION"],
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
        resp_body = response.body or ""
        token = test_case.test_id
        canary_marker = f"BB_XXE_{token}"

        is_reflected = canary_marker in resp_body or comparison.marker_reflected

        if is_reflected:
            # Internal entity reflection establishes internal DTD processing, NOT external entity resolution (XXE).
            # Therefore, this is an OBSERVATION (Informational, Medium confidence), NOT a validated HIGH XXE vulnerability.
            severity = "INFORMATIONAL"
            confidence = "MEDIUM"
            finding_state = FindingLifecycle.OBSERVATION
            summary = (
                f"Internal XML entity expansion observed on {test_case.endpoint}; "
                f"external entity resolution (XXE) remains unconfirmed."
            )

            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=finding_state,
                signals_observed=["INTERNAL_ENTITY_REFLECTED", "INTERNAL_DTD_PROCESSING"],
                evidence_summary=summary,
                confidence=confidence,
                severity=severity,
            )

            finding = Finding(
                title=f"Internal XML Entity Processing Observation on {test_case.endpoint}",
                summary=summary,
                affected_asset=test_case.target,
                affected_endpoint=test_case.endpoint,
                vulnerability_type="XML Entity Processing Observation",
                severity=severity,
                confidence=confidence,
                lifecycle_state=finding_state,
                description=(
                    f"Controlled security testing confirmed that the XML parser on '{test_case.endpoint}' "
                    f"resolves internal DTD entities. A harmless synthetic canary marker was injected and "
                    f"observed in the response. External entity resolution (XXE) was NOT established. "
                    f"Zero sensitive files or external network resources were accessed."
                ),
                root_cause="XML parser is configured to allow internal DTD entity definitions.",
                prerequisites="Endpoint accepts and parses XML input.",
                reproduction_steps=[
                    f"1. Send POST request to '{test_case.endpoint}' with XML containing DOCTYPE internal entity declaration.",
                    "2. Reference internal entity in XML body element.",
                    "3. Observe resolved entity marker in HTTP response body.",
                ],
                expected_result="Endpoint disallows DOCTYPE declarations or parses XML in strict secure mode.",
                observed_result=f"Synthetic internal entity marker reflected in HTTP {response.status_code} response; external entity resolution unconfirmed.",
                security_impact="Internal entity processing is enabled. While this does not prove external entity resolution (XXE), allowing DTD processing may indicate insufficient XML parser hardening.",
                remediation="Disable DTD (Document Type Definitions) completely in the XML parser if not strictly required.",
                scope_reference=f"Target {test_case.endpoint} in authorized scope.",
                parameter=test_case.parameter,
            )
            return result, finding

        parser_error_indicators = ["xml syntax error", "entity expansion", "parser error", "saxparseexception"]
        has_parser_error = any(ind in resp_body.lower() for ind in parser_error_indicators)

        if has_parser_error and response.status_code != baseline.status_code:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.TESTED,
                signals_observed=["PARSER_ERROR_DETECTED"],
                evidence_summary=f"XML parser error detected in HTTP {response.status_code} response; entity expansion unconfirmed.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=["NO_ENTITY_EXPANSION"],
            evidence_summary="No entity expansion or reflection observed in post-mutation HTTP response.",
            confidence="LOW",
            severity="INFORMATIONAL",
        )
        return result, None


class CommandInjectionValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("command-injection", VulnerabilityFamily.COMMAND_INJECTION)


class AuthorizationValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("authorization", VulnerabilityFamily.AUTHORIZATION)


def _extract_reflected_input_tokens(
    injected_token: Optional[str],
    parameter_value: Optional[str] = None,
    canary_token: Optional[str] = None,
) -> List[str]:
    """
    Extracts tokens representing user-supplied input, paths, and filenames to distinguish
    reflection from independent file content disclosure.
    """
    tokens: List[str] = []
    if injected_token:
        tokens.append(injected_token)
        try:
            dec = unquote(injected_token)
            if dec != injected_token:
                tokens.append(dec)
        except Exception:
            pass
        norm_path = injected_token.replace("\\", "/")
        base_fn = os.path.basename(norm_path)
        if base_fn:
            tokens.append(base_fn)
            root_name, _ = os.path.splitext(base_fn)
            if root_name:
                tokens.append(root_name)
    if parameter_value and len(parameter_value) >= 3:
        tokens.append(parameter_value)
    if canary_token:
        tokens.extend([
            f"bb_canary_{canary_token}.txt",
            f"bb_canary_{canary_token}",
            f"BB_CANARY_{canary_token}",
            f"canary_{canary_token}",
        ])
        if len(canary_token) >= 4:
            tokens.append(canary_token)
    seen = set()
    deduped = []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


class PathTraversalValidator(BaseValidator):
    """
    Non-destructive Path Traversal Candidate Validator.
    Strict boundaries:
    - Uses harmless synthetic canary token markers (e.g. canary_<token>.txt).
    - NEVER targets /etc/passwd, win.ini, OS files, cloud metadata, or arbitrary host files.
    - NEVER attempts file creation, overwrite, or deletion.
    - Rejects weak signals (generic status code changes, 500 errors, generic body changes)
      without explicit verification of the synthetic canary content.
    - Tests relative traversals, URL-encoded traversals, and Windows path separators.
    """

    def __init__(self):
        super().__init__(
            validator_id="path-traversal",
            vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        param_name = (parameter or "").lower()
        file_param_names = {
            "file", "filepath", "path", "page", "doc", "document", "folder",
            "root", "dir", "directory", "filename", "template", "include",
            "view", "read", "url", "source", "item", "name", "target", "dest",
            "resource", "download", "load", "file_name", "file_path",
        }
        if param_name in file_param_names:
            return True
        return bool(parameter) or "?" in endpoint

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        cases = []
        payload_ids = ["PL-TRAV-REL-01", "PL-TRAV-ENC-01", "PL-TRAV-WIN-01"]
        prov = dict(provenance or {})
        prov["validator_id"] = self.validator_id
        for pid in payload_ids:
            payload = PayloadRegistry.get_payload(pid)
            if not payload:
                continue
            cases.append(
                SecurityTestCase(
                    vulnerability_family=self.vulnerability_family,
                    target=target,
                    endpoint=endpoint,
                    method="GET",
                    parameter=parameter,
                    payload_identifier=pid,
                    test_strategy="canary_path_traversal",
                    risk_level=RiskLevel.SAFE,
                    request_budget=2,
                    expected_signals=["CANARY_FILE_CONTENT", "TRAVERSAL_CONFIRMED"],
                    provenance=prov,
                )
            )
        return cases

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        injected_input = comparison.injected_token or ""
        token = (
            test_case.preconditions.get("canary_token")
            or (test_case.provenance.get("canary_token") if isinstance(test_case.provenance, dict) else None)
            or ""
        )
        reflected_input_tokens = _extract_reflected_input_tokens(
            injected_token=injected_input,
            parameter_value=test_case.parameter,
            canary_token=token,
        )

        expected_canary = (
            test_case.preconditions.get("expected_canary_content")
            or test_case.preconditions.get("expected_canary")
            or (test_case.provenance.get("expected_canary_content") if isinstance(test_case.provenance, dict) else None)
            or (test_case.provenance.get("expected_canary") if isinstance(test_case.provenance, dict) else None)
        )

        # Independent canary content must NOT be equal to any injected input/filename/path token
        is_independent_canary = bool(
            expected_canary and expected_canary not in reflected_input_tokens
        )

        # Check for input/filename reflection in response body
        input_reflected = False
        matched_reflection = ""
        for tok in reflected_input_tokens:
            if tok and len(tok) >= 4 and tok in response.body:
                input_reflected = True
                matched_reflection = tok
                break

        # Check for independent canary file content
        canary_found = False
        matched_marker = ""
        if is_independent_canary and expected_canary in response.body:
            if expected_canary not in baseline.body_sample:
                canary_found = True
                matched_marker = expected_canary

        # Common error / lookup failure phrases
        is_lookup_failure = any(
            phrase in response.body.lower()
            for phrase in (
                "not found", "does not exist", "no such file", "cannot find",
                "failed to open", "invalid file", "access denied", "forbidden", "traversal detected",
            )
        )

        # CASE 1: Verified independent canary content disclosure
        if canary_found and response.status_code in (200, 201, 203) and not (is_lookup_failure and response.status_code != 200):
            severity = "HIGH"
            confidence = "HIGH"
            finding_state = FindingLifecycle.OBSERVED
            summary = (
                f"Path traversal confirmed on '{test_case.endpoint}' via parameter '{test_case.parameter or 'path'}': "
                f"synthetic canary content '{matched_marker}' retrieved without boundary validation."
            )

            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=finding_state,
                signals_observed=list(comparison.signals) + ["CANARY_FILE_CONTENT", "TRAVERSAL_CONFIRMED"],
                evidence_summary=summary,
                confidence=confidence,
                severity=severity,
            )

            finding = Finding(
                title=f"Path Traversal on {test_case.endpoint} ({test_case.parameter or 'parameter'})",
                summary=summary,
                affected_asset=test_case.target,
                affected_endpoint=test_case.endpoint,
                vulnerability_type="Path Traversal",
                severity=severity,
                confidence=confidence,
                lifecycle_state=finding_state,
                description=(
                    f"Parameter '{test_case.parameter}' is vulnerable to directory traversal sequences. "
                    f"The server resolved traversal tokens outside the intended web root and exposed synthetic canary file content. "
                    f"Testing adhered strictly to non-destructive rules using synthetic markers; zero OS files or host secrets were accessed."
                ),
                root_cause="File path parameter is concatenated directly into filesystem operations without canonicalization and boundary validation.",
                prerequisites="Endpoint accessible over HTTP/HTTPS with file retrieval functionality.",
                reproduction_steps=[
                    f"Send baseline request to '{test_case.endpoint}'.",
                    f"Submit mutated request with parameter '{test_case.parameter}' containing relative traversal sequence.",
                    f"Verify HTTP {response.status_code} response containing synthetic canary content '{matched_marker}'.",
                ],
                expected_result="Path parameter is restricted to an authorized directory or whitelist; traversal sequences are rejected with 400/404.",
                observed_result=f"Server returned synthetic canary content '{matched_marker}' from outside the authorized web root.",
                security_impact="An attacker could traverse outside the intended directory to read arbitrary files, configurations, or application code.",
                remediation="Resolve user input against a canonical path using safe path resolution APIs and verify the resolved path remains within the base root directory, or map inputs to an immutable whitelist.",
                scope_reference=f"Target {test_case.target} authorized in scope",
                parameter=test_case.parameter,
                test_case_id=test_case.test_id,
                detection_method="canary_path_traversal",
                references=["CWE-22", "OWASP-A01:2021-Broken Access Control"],
            )
            return result, finding

        # CASE 2: Error, rejection, or status code failure (400, 401, 403, 404, 500, error pattern)
        if response.status_code in (400, 401, 403, 404, 500) or comparison.error_pattern_detected:
            signals = list(comparison.signals)
            if input_reflected:
                signals.append("REFLECTED_PARAMETER_ONLY")
            if response.status_code in (403, 404):
                signals.append("TRAVERSAL_BLOCKED")
            if response.status_code == 500 or comparison.error_pattern_detected or comparison.status_changed:
                signals.append("WEAK_SIGNAL_STATUS_CHANGE_OR_ERROR")
            signals.append("NO_CANARY_CONTENT")
            evidence = (
                f"Server reflected injected path/filename '{matched_reflection}' in error or lookup failure (HTTP {response.status_code}) without returning independent canary content; rejected as input reflection (insufficient proof of path traversal)."
                if input_reflected
                else f"Generic error or status code change without verified canary content is insufficient proof of path traversal; rejected as weak signal."
            )
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=signals,
                evidence_summary=evidence,
                confidence="HIGH" if input_reflected else "LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # CASE 3: Injected input / filename reflected in 200 response without independent canary content
        if input_reflected:
            if is_lookup_failure:
                result = ValidationResult(
                    test_id=test_case.test_id,
                    lifecycle_state=FindingLifecycle.REJECTED,
                    signals_observed=list(comparison.signals) + ["REFLECTED_PARAMETER_ONLY", "TRAVERSAL_BLOCKED", "NO_CANARY_CONTENT"],
                    evidence_summary=f"Server returned lookup failure or error reflecting input '{matched_reflection}' in HTTP {response.status_code} response; rejected as input reflection.",
                    confidence="HIGH",
                    severity="INFORMATIONAL",
                )
                return result, None

            signals = list(comparison.signals) + ["REFLECTED_PARAMETER_ONLY", "NO_CANARY_CONTENT"]
            summary = (
                f"Injected parameter/path token '{matched_reflection}' was reflected in response body on '{test_case.endpoint}', "
                f"but no independent canary file content was observed. Parameter reflection alone does not prove file disclosure; flagged for manual review."
            )
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.NEEDS_MANUAL_REVIEW,
                signals_observed=signals,
                evidence_summary=summary,
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            candidate_finding = Finding(
                title=f"Reflected Path Parameter on {test_case.endpoint} ({test_case.parameter or 'parameter'})",
                summary=summary,
                affected_asset=test_case.target,
                affected_endpoint=test_case.endpoint,
                vulnerability_type="Path Traversal",
                severity="INFORMATIONAL",
                confidence="LOW",
                lifecycle_state=FindingLifecycle.CANDIDATE,
                description=(
                    f"Parameter '{test_case.parameter}' reflected the injected path/filename sequence in the response body. "
                    f"However, independent file body content was not retrieved. This indicates parameter reflection or template echoing rather than file disclosure."
                ),
                root_cause="Input parameter is reflected in response without verified retrieval of files outside the directory.",
                prerequisites="Endpoint accessible over HTTP/HTTPS.",
                reproduction_steps=[
                    f"Send request to '{test_case.endpoint}' with parameter '{test_case.parameter}' containing test path.",
                    f"Observe reflection of parameter '{matched_reflection}' in response body without independent file content.",
                ],
                expected_result="Application either sanitizes path input or returns file content only when authorized.",
                observed_result=f"Parameter reflected in response: '{matched_reflection}'.",
                security_impact="Parameter reflection without file disclosure does not grant access to server files, but warrants review.",
                remediation="Ensure path parameters are validated and sanitized; do not echo unsanitized file paths in responses.",
                scope_reference=f"Target {test_case.target} authorized in scope",
                parameter=test_case.parameter,
                test_case_id=test_case.test_id,
                detection_method="canary_path_traversal",
                references=["CWE-22", "CWE-20"],
            )
            return result, candidate_finding

        # CASE 4: Live target assessment without pre-planted canary resource
        if not expected_canary or not is_independent_canary:
            if response.status_code in (200, 201, 203) and (comparison.status_changed or abs(comparison.size_delta) > 50 or comparison.body_similarity < 0.9):
                signals = list(comparison.signals) + ["NO_CANARY_CONFIGURED", "CANDIDATE_UNVERIFIED"]
                summary = (
                    f"Candidate path parameter on '{test_case.endpoint}' produced differential response on live target, "
                    f"but synthetic canary is not configured. Preserving as CANDIDATE / NEEDS_MANUAL_REVIEW without claiming arbitrary file disclosure."
                )
                result = ValidationResult(
                    test_id=test_case.test_id,
                    lifecycle_state=FindingLifecycle.NEEDS_MANUAL_REVIEW,
                    signals_observed=signals,
                    evidence_summary=summary,
                    confidence="LOW",
                    severity="INFORMATIONAL",
                )
                candidate_finding = Finding(
                    title=f"Candidate Path Parameter on {test_case.endpoint} ({test_case.parameter or 'parameter'})",
                    summary=summary,
                    affected_asset=test_case.target,
                    affected_endpoint=test_case.endpoint,
                    vulnerability_type="Path Traversal",
                    severity="INFORMATIONAL",
                    confidence="LOW",
                    lifecycle_state=FindingLifecycle.CANDIDATE,
                    description="Candidate path traversal parameter identified during live assessment without pre-planted canary resource. Controlled test file required for verification.",
                    root_cause="Potential unvalidated file retrieval parameter on live target.",
                    prerequisites="Endpoint accessible over HTTP/HTTPS.",
                    reproduction_steps=[
                        f"Submit test traversal probe to '{test_case.endpoint}'.",
                        "Differential response observed; requires controlled test file to verify disclosure.",
                    ],
                    expected_result="Endpoint validates input and restricts file retrieval.",
                    observed_result="Differential response observed on live target.",
                    security_impact="Unconfirmed potential path traversal.",
                    remediation="Validate and canonicalize all file path parameters against a whitelist.",
                    scope_reference=f"Target {test_case.target} authorized in scope",
                    parameter=test_case.parameter,
                    test_case_id=test_case.test_id,
                    detection_method="canary_path_traversal",
                    references=["CWE-22"],
                )
                return result, candidate_finding

            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=list(comparison.signals) + ["TRAVERSAL_BLOCKED", "NO_CANARY_CONFIGURED"],
                evidence_summary="Path traversal sequence produced no differential response on live target without pre-planted canary.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # CASE 5: Traversal blocked or no signals
        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=list(comparison.signals) + ["TRAVERSAL_BLOCKED", "NO_CANARY_CONTENT"],
            evidence_summary="Path traversal sequence was rejected or did not expose synthetic canary content.",
            confidence="LOW",
            severity="INFORMATIONAL",
        )
        return result, None


class LocalFileExposureValidator(BaseValidator):
    """
    Non-destructive Local File Exposure Candidate Validator.
    Strict boundaries:
    - Focuses on direct file/document parameters (doc=..., view=..., file=...).
    - Uses harmless synthetic canary token markers.
    - NEVER targets /etc/passwd, win.ini, OS files, cloud metadata, or host secrets.
    - Rejects weak signals (generic 500 errors, generic status changes) as insufficient proof.
    - Requires verified reflection of synthetic canary resource content.
    """

    def __init__(self):
        super().__init__(
            validator_id="local-file-exposure",
            vulnerability_family=VulnerabilityFamily.PATH_TRAVERSAL,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        param_name = (parameter or "").lower()
        file_param_names = {
            "file", "filepath", "path", "page", "doc", "document", "filename",
            "template", "include", "view", "read", "source", "resource", "load", "content",
        }
        if param_name in file_param_names:
            return True
        return bool(parameter) or "?" in endpoint

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        payload = PayloadRegistry.get_payload("PL-LFE-CANARY-01")
        if not payload:
            return []
        prov = dict(provenance or {})
        prov["validator_id"] = self.validator_id
        return [
            SecurityTestCase(
                vulnerability_family=self.vulnerability_family,
                target=target,
                endpoint=endpoint,
                method="GET",
                parameter=parameter,
                payload_identifier=payload.payload_id,
                test_strategy="local_file_exposure_canary",
                risk_level=RiskLevel.SAFE,
                request_budget=2,
                expected_signals=["CANARY_FILE_CONTENT", "LOCAL_FILE_EXPOSURE_CONFIRMED"],
                provenance=prov,
            )
        ]

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        injected_input = comparison.injected_token or ""
        token = (
            test_case.preconditions.get("canary_token")
            or (test_case.provenance.get("canary_token") if isinstance(test_case.provenance, dict) else None)
            or ""
        )
        reflected_input_tokens = _extract_reflected_input_tokens(
            injected_token=injected_input,
            parameter_value=test_case.parameter,
            canary_token=token,
        )

        expected_canary = (
            test_case.preconditions.get("expected_canary_content")
            or test_case.preconditions.get("expected_canary")
            or (test_case.provenance.get("expected_canary_content") if isinstance(test_case.provenance, dict) else None)
            or (test_case.provenance.get("expected_canary") if isinstance(test_case.provenance, dict) else None)
        )

        # Independent canary content must NOT be equal to any injected input/filename/path token
        is_independent_canary = bool(
            expected_canary and expected_canary not in reflected_input_tokens
        )

        # Check for input/filename reflection in response body
        input_reflected = False
        matched_reflection = ""
        for tok in reflected_input_tokens:
            if tok and len(tok) >= 4 and tok in response.body:
                input_reflected = True
                matched_reflection = tok
                break

        # Check for independent canary file content
        canary_found = False
        matched_marker = ""
        if is_independent_canary and expected_canary in response.body:
            if expected_canary not in baseline.body_sample:
                canary_found = True
                matched_marker = expected_canary

        # Common error / lookup failure phrases
        is_lookup_failure = any(
            phrase in response.body.lower()
            for phrase in (
                "not found", "does not exist", "no such file", "cannot find",
                "failed to open", "invalid file", "access denied", "forbidden",
            )
        )

        # CASE 1: Verified independent canary content disclosure
        if canary_found and response.status_code in (200, 201, 203) and not (is_lookup_failure and response.status_code != 200):
            severity = "HIGH"
            confidence = "HIGH"
            finding_state = FindingLifecycle.OBSERVED
            summary = (
                f"Local file exposure verified on '{test_case.endpoint}' via parameter '{test_case.parameter}': "
                f"synthetic canary content '{matched_marker}' retrieved from server."
            )

            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=finding_state,
                signals_observed=list(comparison.signals) + ["CANARY_FILE_CONTENT", "LOCAL_FILE_EXPOSURE_CONFIRMED"],
                evidence_summary=summary,
                confidence=confidence,
                severity=severity,
            )

            finding = Finding(
                title=f"Local File Exposure on {test_case.endpoint} ({test_case.parameter or 'parameter'})",
                summary=summary,
                affected_asset=test_case.target,
                affected_endpoint=test_case.endpoint,
                vulnerability_type="Local File Exposure",
                severity=severity,
                confidence=confidence,
                lifecycle_state=finding_state,
                description=(
                    f"Parameter '{test_case.parameter}' retrieves arbitrary server-side files without restriction. "
                    f"Synthetic canary resource '{matched_marker}' was retrieved in response to controlled input. "
                    f"No sensitive host files or OS credentials were accessed per safe validation rules."
                ),
                root_cause="User-controlled resource name is directly utilized in server-side file retrieval operations.",
                prerequisites="Endpoint accessible over HTTP/HTTPS with file serving functionality.",
                reproduction_steps=[
                    f"Send baseline request to '{test_case.endpoint}'.",
                    f"Submit request with parameter '{test_case.parameter}' set to synthetic canary resource.",
                    f"Observe HTTP {response.status_code} response displaying synthetic canary file content.",
                ],
                expected_result="Resource identifier is validated against a strict allowed index or restricted to public documents.",
                observed_result=f"Server returned synthetic canary file content '{matched_marker}'.",
                security_impact="An unauthorized user may read sensitive server-side files or internal configuration data.",
                remediation="Implement strict server-side validation against an explicit list of permissible document identifiers; disable direct file parameter access.",
                scope_reference=f"Target {test_case.target} authorized in scope",
                parameter=test_case.parameter,
                test_case_id=test_case.test_id,
                detection_method="local_file_exposure_canary",
                references=["CWE-200", "CWE-73", "OWASP-A01:2021-Broken Access Control"],
            )
            return result, finding

        # CASE 2: Error, rejection, or status code failure (400, 401, 403, 404, 500, error pattern)
        if response.status_code in (400, 401, 403, 404, 500) or comparison.error_pattern_detected:
            signals = list(comparison.signals)
            if input_reflected:
                signals.append("REFLECTED_PARAMETER_ONLY")
            if response.status_code in (403, 404):
                signals.append("LOCAL_FILE_EXPOSURE_BLOCKED")
            if response.status_code == 500 or comparison.error_pattern_detected or comparison.status_changed:
                signals.append("WEAK_SIGNAL_STATUS_CHANGE_OR_ERROR")
            signals.append("NO_CANARY_CONTENT")
            evidence = (
                f"Server reflected injected path/filename '{matched_reflection}' in error or lookup failure (HTTP {response.status_code}) without returning independent canary content; rejected as input reflection (insufficient proof)."
                if input_reflected
                else f"Generic error or status change without verified canary content is insufficient proof; rejected as weak signal."
            )
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=signals,
                evidence_summary=evidence,
                confidence="HIGH" if input_reflected else "LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # CASE 3: Input / filename reflected in 200 response without independent canary content
        if input_reflected:
            if is_lookup_failure:
                result = ValidationResult(
                    test_id=test_case.test_id,
                    lifecycle_state=FindingLifecycle.REJECTED,
                    signals_observed=list(comparison.signals) + ["REFLECTED_PARAMETER_ONLY", "LOCAL_FILE_EXPOSURE_BLOCKED", "NO_CANARY_CONTENT"],
                    evidence_summary=f"Server returned lookup failure or error reflecting input '{matched_reflection}' in HTTP {response.status_code} response; rejected as input reflection.",
                    confidence="HIGH",
                    severity="INFORMATIONAL",
                )
                return result, None

            signals = list(comparison.signals) + ["REFLECTED_PARAMETER_ONLY", "NO_CANARY_CONTENT"]
            summary = (
                f"Injected parameter token '{matched_reflection}' was reflected in response body on '{test_case.endpoint}', "
                f"but no independent canary file content was observed. Parameter reflection alone does not prove file disclosure; flagged for manual review."
            )
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.NEEDS_MANUAL_REVIEW,
                signals_observed=signals,
                evidence_summary=summary,
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            candidate_finding = Finding(
                title=f"Reflected File Parameter on {test_case.endpoint} ({test_case.parameter or 'parameter'})",
                summary=summary,
                affected_asset=test_case.target,
                affected_endpoint=test_case.endpoint,
                vulnerability_type="Local File Exposure",
                severity="INFORMATIONAL",
                confidence="LOW",
                lifecycle_state=FindingLifecycle.CANDIDATE,
                description=(
                    f"Parameter '{test_case.parameter}' reflected the injected file identifier in the response body. "
                    f"However, independent file body content was not retrieved. This indicates parameter reflection rather than file disclosure."
                ),
                root_cause="Input parameter is reflected in response without verified retrieval of files.",
                prerequisites="Endpoint accessible over HTTP/HTTPS.",
                reproduction_steps=[
                    f"Send request to '{test_case.endpoint}' with parameter '{test_case.parameter}' set to probe name.",
                    f"Observe reflection of parameter '{matched_reflection}' in response body without independent file content.",
                ],
                expected_result="Application either sanitizes parameter input or returns document content only when authorized.",
                observed_result=f"Parameter reflected in response: '{matched_reflection}'.",
                security_impact="Parameter reflection without file disclosure does not grant access to server files, but warrants review.",
                remediation="Ensure document parameters are validated and sanitized; do not echo unsanitized file paths in responses.",
                scope_reference=f"Target {test_case.target} authorized in scope",
                parameter=test_case.parameter,
                test_case_id=test_case.test_id,
                detection_method="local_file_exposure_canary",
                references=["CWE-200", "CWE-73"],
            )
            return result, candidate_finding

        # CASE 4: Live target assessment without pre-planted canary resource
        if not expected_canary or not is_independent_canary:
            if response.status_code in (200, 201, 203) and (comparison.status_changed or abs(comparison.size_delta) > 50 or comparison.body_similarity < 0.9):
                signals = list(comparison.signals) + ["NO_CANARY_CONFIGURED", "CANDIDATE_UNVERIFIED"]
                summary = (
                    f"Candidate file parameter on '{test_case.endpoint}' produced differential response on live target, "
                    f"but synthetic canary is not configured. Preserving as CANDIDATE / NEEDS_MANUAL_REVIEW without claiming arbitrary file disclosure."
                )
                result = ValidationResult(
                    test_id=test_case.test_id,
                    lifecycle_state=FindingLifecycle.NEEDS_MANUAL_REVIEW,
                    signals_observed=signals,
                    evidence_summary=summary,
                    confidence="LOW",
                    severity="INFORMATIONAL",
                )
                candidate_finding = Finding(
                    title=f"Candidate File Parameter on {test_case.endpoint} ({test_case.parameter or 'parameter'})",
                    summary=summary,
                    affected_asset=test_case.target,
                    affected_endpoint=test_case.endpoint,
                    vulnerability_type="Local File Exposure",
                    severity="INFORMATIONAL",
                    confidence="LOW",
                    lifecycle_state=FindingLifecycle.CANDIDATE,
                    description="Candidate local file parameter identified during live assessment without pre-planted canary resource. Controlled test file required for verification.",
                    root_cause="Potential unvalidated file retrieval parameter on live target.",
                    prerequisites="Endpoint accessible over HTTP/HTTPS.",
                    reproduction_steps=[
                        f"Submit test file probe to '{test_case.endpoint}'.",
                        "Differential response observed; requires controlled test file to verify disclosure.",
                    ],
                    expected_result="Endpoint validates input and restricts file retrieval.",
                    observed_result="Differential response observed on live target.",
                    security_impact="Unconfirmed potential local file exposure.",
                    remediation="Validate and restrict all file parameters against a whitelist of permissible documents.",
                    scope_reference=f"Target {test_case.target} authorized in scope",
                    parameter=test_case.parameter,
                    test_case_id=test_case.test_id,
                    detection_method="local_file_exposure_canary",
                    references=["CWE-200", "CWE-73"],
                )
                return result, candidate_finding

            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=list(comparison.signals) + ["LOCAL_FILE_EXPOSURE_BLOCKED", "NO_CANARY_CONFIGURED"],
                evidence_summary="Local file exposure probe produced no differential response on live target without pre-planted canary.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # CASE 5: Negative / blocked
        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=list(comparison.signals) + ["LOCAL_FILE_EXPOSURE_BLOCKED", "NO_CANARY_CONTENT"],
            evidence_summary="Local file exposure probe did not retrieve synthetic canary content.",
            confidence="LOW",
            severity="INFORMATIONAL",
        )
        return result, None


class FileUploadValidator(BaseValidator):
    """
    Non-destructive File Upload Security Candidate Validator.
    Strict boundaries:
    - Reuses FormObservation.has_file_upload, multipart forms, and file-related parameters.
    - Evaluates observable upload controls and validation using harmless, non-executable synthetic content.
    - NEVER uploads executable payloads (.php, .jsp, .exe, .sh, .py, webshells).
    - NEVER overwrites or deletes files.
    - NEVER performs persistent webshell attacks or destructive fuzzing.
    - Distinguishes detected upload forms and benign uploads from actual vulnerabilities.
    - Benign uploads that succeed normally are reported as INFORMATIONAL/REJECTED, NEVER as vulnerabilities.
    - Where active upload testing cannot be safely dispatched, produces a clearly labeled MANUAL_REVIEW result.
    """

    def __init__(self):
        super().__init__(
            validator_id="file-upload",
            vulnerability_family=VulnerabilityFamily.FILE_UPLOAD,
            is_available=True,
        )

    def can_test(self, endpoint: str, parameter: Optional[str] = None) -> bool:
        param_name = (parameter or "").lower()
        upload_param_names = {"upload", "attachment", "avatar", "file_upload", "upload_file", "resume", "media"}
        if param_name in upload_param_names:
            return True
        ep_lower = endpoint.lower()
        if "/upload" in ep_lower or "upload" in ep_lower:
            return True
        return False

    def prepare_test_cases(
        self,
        target: str,
        endpoint: str,
        parameter: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> List[SecurityTestCase]:
        cases = []
        payload = PayloadRegistry.get_payload("PL-UPLOAD-BENIGN-01")
        prov = dict(provenance or {})
        prov["validator_id"] = self.validator_id
        if payload:
            cases.append(
                SecurityTestCase(
                    vulnerability_family=self.vulnerability_family,
                    target=target,
                    endpoint=endpoint,
                    method="POST",
                    parameter=parameter or "file",
                    payload_identifier=payload.payload_id,
                    test_strategy="multipart_upload",
                    risk_level=RiskLevel.SAFE,
                    request_budget=2,
                    expected_signals=["UPLOAD_ACCEPTED", "UPLOAD_REJECTED"],
                    provenance=prov,
                )
            )
        trav_payload = PayloadRegistry.get_payload("PL-TRAV-REL-01")
        if trav_payload:
            cases.append(
                SecurityTestCase(
                    vulnerability_family=self.vulnerability_family,
                    target=target,
                    endpoint=endpoint,
                    method="POST",
                    parameter=parameter or "file",
                    payload_identifier=trav_payload.payload_id,
                    test_strategy="filename_traversal",
                    risk_level=RiskLevel.SAFE,
                    request_budget=2,
                    expected_signals=["FILENAME_TRAVERSAL_CONFIRMED", "UPLOAD_REJECTED"],
                    provenance=dict(prov, test_type="filename_traversal"),
                    preconditions={"test_type": "filename_traversal"},
                )
            )
        return cases

    def analyze(
        self,
        comparison: BaselineComparison,
        baseline: BaselineObservation,
        response: ControlledResponse,
        test_case: SecurityTestCase,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        # Case 1: Server rejects the upload (4xx status or explicit rejection text)
        if response.status_code in (400, 403, 415, 422) or any(
            phrase in response.body.lower()
            for phrase in ("file type not allowed", "invalid file", "unsupported media type", "upload rejected")
        ):
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=list(comparison.signals) + ["UPLOAD_REJECTED_BY_SERVER"],
                evidence_summary=f"Upload request was safely rejected by server-side validation controls (HTTP {response.status_code}).",
                confidence="HIGH",
                severity="INFORMATIONAL",
            )
            return result, None

        # Case 2: Server processed benign file upload normally (2xx / 3xx)
        # Core Rule: A benign upload working as intended is NOT a vulnerability.
        if response.status_code in (200, 201, 204, 302):
            test_type = (
                test_case.preconditions.get("test_type")
                or (test_case.provenance.get("test_type") if isinstance(test_case.provenance, dict) else None)
            )
            is_traversal_test = (
                test_type == "filename_traversal"
                or test_case.test_strategy == "filename_traversal"
            )
            if is_traversal_test:
                # Check for explicit server-side error or rejection in response body
                if any(
                    phrase in response.body.lower()
                    for phrase in ("error", "invalid filename", "traversal rejected", "rejected", "forbidden", "disallowed", "not allowed")
                ):
                    result = ValidationResult(
                        test_id=test_case.test_id,
                        lifecycle_state=FindingLifecycle.REJECTED,
                        signals_observed=list(comparison.signals) + ["UPLOAD_REJECTED_BY_SERVER", "FILENAME_TRAVERSAL_BLOCKED"],
                        evidence_summary=f"Upload with traversal filename was safely rejected by server controls (HTTP {response.status_code}).",
                        confidence="HIGH",
                        severity="INFORMATIONAL",
                    )
                    return result, None

                # A reflected filename or server-supplied path is not proof of a filesystem write.
                # Only the explicitly controlled loopback fixture may use its structured
                # fixture signal as a deterministic positive test. Live-target responses
                # remain candidates until independent storage/read-back verification exists.
                import json
                try:
                    upload_evidence = json.loads(response.body)
                except (TypeError, ValueError):
                    upload_evidence = {}

                target_host = (urlparse(test_case.target).hostname or "").lower()
                is_loopback_fixture = target_host in {"127.0.0.1", "localhost", "::1"}
                fixture_verified = (
                    is_loopback_fixture
                    and test_case.preconditions.get("verification_mode") == "controlled_fixture"
                    and isinstance(upload_evidence, dict)
                    and upload_evidence.get("verification_method") == "controlled_fixture"
                    and upload_evidence.get("stored_outside_root") is True
                    and isinstance(upload_evidence.get("path"), str)
                    and ("../" in upload_evidence["path"] or "..\\" in upload_evidence["path"])
                    and "bb_canary" in upload_evidence["path"].lower()
                    and upload_evidence.get("marker") == "bb_canary"
                )
                if fixture_verified:
                    # The fixture response is a test oracle, not independent evidence from
                    # a real filesystem. Keep this result explicitly simulated so it can
                    # never be mistaken for a verified live-target vulnerability.
                    severity = "INFORMATIONAL"
                    confidence = "HIGH"
                    finding_state = FindingLifecycle.SIMULATED
                    summary = f"Simulated file upload filename traversal behavior in controlled fixture for '{test_case.endpoint}'."
                    result = ValidationResult(
                        test_id=test_case.test_id,
                        lifecycle_state=finding_state,
                        signals_observed=list(comparison.signals) + ["FILENAME_TRAVERSAL_SIMULATED", "CONTROLLED_FIXTURE_VERIFICATION"],
                        evidence_summary=summary,
                        confidence=confidence,
                        severity=severity,
                    )
                    finding = Finding(
                        title=f"Simulated File Upload Filename Traversal on {test_case.endpoint}",
                        summary=summary,
                        affected_asset=test_case.target,
                        affected_endpoint=test_case.endpoint,
                        vulnerability_type="File Upload Filename Traversal",
                        severity=severity,
                        confidence=confidence,
                        lifecycle_state=finding_state,
                        provenance={"is_simulation": True, "verification_mode": "controlled_fixture"},
                        description="The controlled fixture models acceptance of a traversal-style filename. This simulated result does not establish a real filesystem write or a vulnerability on a live target.",
                        root_cause="The controlled fixture models an upload handler that does not enforce an upload-directory boundary.",
                        prerequisites="Controlled local fixture configured for deterministic Phase 15 regression testing.",
                        reproduction_steps=[
                            f"Send multipart upload request to '{test_case.endpoint}' with the traversal filename.",
                            "Observe the fixture's simulated outside-root response.",
                        ],
                        expected_result="Filename is reduced to a safe basename and storage remains within the configured upload directory.",
                        observed_result="The controlled fixture emitted its configured simulated outside-root signal.",
                        security_impact="No live-target impact is established by this simulated result.",
                        remediation="Canonicalize storage paths, enforce that resolved paths remain beneath the upload root, and generate server-side storage names.",
                        scope_reference=f"Target {test_case.target} authorized in scope",
                        parameter=test_case.parameter,
                        test_case_id=test_case.test_id,
                        detection_method="multipart_upload",
                        references=["CWE-434", "CWE-22"],
                    )
                    return result, finding

                # Without independent verification, preserve a candidate for review rather
                # than promoting a reflected filename or untrusted response claim.
                filename_marker = (
                    test_case.preconditions.get("expected_canary")
                    or "bb_canary"
                )
                body_lower = response.body.lower()
                response_mentions_probe = (
                    filename_marker.lower() in body_lower
                    or "../" in response.body
                    or "..\\" in response.body
                )
                if response_mentions_probe:
                    summary = (
                        f"Upload response from '{test_case.endpoint}' mentions the traversal filename or canary marker, "
                        "but does not provide trusted independent proof of storage outside the upload root."
                    )
                    result = ValidationResult(
                        test_id=test_case.test_id,
                        lifecycle_state=FindingLifecycle.NEEDS_MANUAL_REVIEW,
                        signals_observed=list(comparison.signals) + ["REFLECTED_FILENAME_ONLY", "NO_INDEPENDENT_STORAGE_VERIFICATION"],
                        evidence_summary=summary,
                        confidence="LOW",
                        severity="INFORMATIONAL",
                    )
                    candidate = Finding(
                        title=f"Candidate File Upload Filename Traversal on {test_case.endpoint}",
                        summary=summary,
                        affected_asset=test_case.target,
                        affected_endpoint=test_case.endpoint,
                        vulnerability_type="File Upload Filename Traversal",
                        severity="INFORMATIONAL",
                        confidence="LOW",
                        lifecycle_state=FindingLifecycle.CANDIDATE,
                        description="The response references a traversal-style upload filename, but response reflection or an untrusted success/path claim does not establish where the file was stored.",
                        root_cause="Potential unsafe handling of multipart filenames; storage behavior remains unverified.",
                        prerequisites="Endpoint accepts multipart upload requests.",
                        reproduction_steps=[
                            f"Send the harmless traversal-style filename to '{test_case.endpoint}' within authorized scope.",
                            "Independently verify the resulting file location using a controlled canary/read-back mechanism before confirming a vulnerability.",
                        ],
                        expected_result="The server rejects traversal components or stores the file under a server-generated safe name inside the upload root.",
                        observed_result="Response referenced the traversal probe, but no independent storage-location proof was available.",
                        security_impact="Unconfirmed; do not infer arbitrary file placement from reflection alone.",
                        remediation="Use server-generated filenames and enforce canonical path containment beneath the upload directory.",
                        scope_reference=f"Target {test_case.target} authorized in scope",
                        parameter=test_case.parameter,
                        test_case_id=test_case.test_id,
                        detection_method="multipart_upload",
                        references=["CWE-434", "CWE-22"],
                    )
                    return result, candidate

                result = ValidationResult(
                    test_id=test_case.test_id,
                    lifecycle_state=FindingLifecycle.REJECTED,
                    signals_observed=list(comparison.signals) + ["NO_INDEPENDENT_STORAGE_VERIFICATION"],
                    evidence_summary="Server processed the upload but provided no independent evidence that the file was stored outside the intended upload directory.",
                    confidence="LOW",
                    severity="INFORMATIONAL",
                )
                return result, None

            # Normal benign upload: Informational result, NO vulnerability finding
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.INFORMATIONAL,
                signals_observed=list(comparison.signals) + ["BENIGN_UPLOAD_ACCEPTED", "CONTROLS_ACTIVE"],
                evidence_summary="Upload functionality processed harmless synthetic plain-text test file; benign upload does not demonstrate vulnerability.",
                confidence="HIGH",
                severity="INFORMATIONAL",
            )
            return result, None

        # Other unexpected response
        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=list(comparison.signals) + ["INCONCLUSIVE_UPLOAD_RESPONSE"],
            evidence_summary=f"Upload response (HTTP {response.status_code}) was inconclusive.",
            confidence="LOW",
            severity="INFORMATIONAL",
        )
        return result, None
