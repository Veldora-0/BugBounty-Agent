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
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

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


class SsrfValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("ssrf", VulnerabilityFamily.SSRF)


class CommandInjectionValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("command-injection", VulnerabilityFamily.COMMAND_INJECTION)


class AuthorizationValidator(UnavailableValidator):
    def __init__(self):
        super().__init__("authorization", VulnerabilityFamily.AUTHORIZATION)


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
        expected_canary = (
            test_case.preconditions.get("expected_canary")
            or (test_case.provenance.get("expected_canary") if isinstance(test_case.provenance, dict) else None)
        )
        token = (
            test_case.preconditions.get("canary_token")
            or (test_case.provenance.get("canary_token") if isinstance(test_case.provenance, dict) else None)
        )

        canary_markers = []
        if expected_canary:
            canary_markers.append(expected_canary)
        if token:
            canary_markers.extend([f"bb_canary_{token}", f"BB_CANARY_{token}", f"canary_{token}"])

        if comparison.injected_token:
            m = re.search(r"bb_canary_([a-zA-Z0-9_-]+)\.txt", comparison.injected_token)
            if m:
                tok_val = m.group(1)
                canary_markers.extend([f"bb_canary_{tok_val}", f"BB_CANARY_{tok_val}", f"canary_{tok_val}"])

        canary_found = False
        matched_marker = ""
        for marker in canary_markers:
            if marker in response.body and marker not in baseline.body_sample:
                canary_found = True
                matched_marker = marker
                break

        if canary_found and response.status_code in (200, 201, 203):
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

        # Reject weak signals: generic status codes or server errors without canary content
        if comparison.status_changed or comparison.error_pattern_detected:
            signals = list(comparison.signals) + ["WEAK_SIGNAL_STATUS_CHANGE_OR_ERROR", "NO_CANARY_EVIDENCE"]
            if response.status_code in (403, 404):
                signals.append("TRAVERSAL_BLOCKED")
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=signals,
                evidence_summary="Generic error or status code change without verified canary content is insufficient proof of path traversal; rejected as weak signal.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # Negative / blocked traversal
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
        expected_canary = (
            test_case.preconditions.get("expected_canary")
            or (test_case.provenance.get("expected_canary") if isinstance(test_case.provenance, dict) else None)
        )
        token = (
            test_case.preconditions.get("canary_token")
            or (test_case.provenance.get("canary_token") if isinstance(test_case.provenance, dict) else None)
        )

        canary_markers = []
        if expected_canary:
            canary_markers.append(expected_canary)
        if token:
            canary_markers.extend([f"bb_canary_{token}", f"BB_CANARY_{token}", f"canary_{token}"])

        if comparison.injected_token:
            m = re.search(r"bb_canary_([a-zA-Z0-9_-]+)\.txt", comparison.injected_token)
            if m:
                tok_val = m.group(1)
                canary_markers.extend([f"bb_canary_{tok_val}", f"BB_CANARY_{tok_val}", f"canary_{tok_val}"])

        canary_found = False
        matched_marker = ""
        for marker in canary_markers:
            if marker in response.body and marker not in baseline.body_sample:
                canary_found = True
                matched_marker = marker
                break

        if canary_found and response.status_code in (200, 201, 203):
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

        # Reject weak signals: generic status codes or server errors
        if comparison.status_changed or comparison.error_pattern_detected:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.REJECTED,
                signals_observed=list(comparison.signals) + ["WEAK_SIGNAL_STATUS_CHANGE_OR_ERROR", "NO_CANARY_EVIDENCE"],
                evidence_summary="Generic error or status change without verified canary content is insufficient proof; rejected as weak signal.",
                confidence="LOW",
                severity="INFORMATIONAL",
            )
            return result, None

        # Negative / blocked
        result = ValidationResult(
            test_id=test_case.test_id,
            lifecycle_state=FindingLifecycle.REJECTED,
            signals_observed=list(comparison.signals) + ["LOCAL_FILE_EXPOSURE_BLOCKED"],
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
        payload = PayloadRegistry.get_payload("PL-UPLOAD-BENIGN-01")
        if not payload:
            return []
        prov = dict(provenance or {})
        prov["validator_id"] = self.validator_id
        return [
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
        ]

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
            test_type = test_case.preconditions.get("test_type")
            if test_type == "filename_traversal":
                expected_marker = test_case.preconditions.get("expected_canary") or "bb_canary"
                if expected_marker in response.body and expected_marker not in baseline.body_sample:
                    severity = "HIGH"
                    confidence = "HIGH"
                    finding_state = FindingLifecycle.OBSERVED
                    summary = f"File upload filename traversal confirmed on '{test_case.endpoint}' via parameter '{test_case.parameter}'."
                    result = ValidationResult(
                        test_id=test_case.test_id,
                        lifecycle_state=finding_state,
                        signals_observed=list(comparison.signals) + ["FILENAME_TRAVERSAL_CONFIRMED"],
                        evidence_summary=summary,
                        confidence=confidence,
                        severity=severity,
                    )
                    finding = Finding(
                        title=f"Arbitrary File Upload Filename Traversal on {test_case.endpoint}",
                        summary=summary,
                        affected_asset=test_case.target,
                        affected_endpoint=test_case.endpoint,
                        vulnerability_type="File Upload Filename Traversal",
                        severity=severity,
                        confidence=confidence,
                        lifecycle_state=finding_state,
                        description="Uploaded file filename parameter permits directory traversal sequences, allowing placement outside intended upload storage.",
                        root_cause="Unsanitized filename header in multipart upload processed directly in filesystem storage path.",
                        prerequisites="Endpoint accessible over HTTP/HTTPS with file upload capability.",
                        reproduction_steps=[
                            f"Send multipart upload request to '{test_case.endpoint}' with traversal filename.",
                            "Observe server-side confirmation of write outside intended directory.",
                        ],
                        expected_result="Filename is stripped of traversal sequences and sanitized to a safe basename.",
                        observed_result="Server accepted traversal sequence in uploaded file filename.",
                        security_impact="An attacker could overwrite critical files or place files in unauthorized directories.",
                        remediation="Sanitize all incoming filenames using secure basename extraction and generate deterministic random storage identifiers.",
                        scope_reference=f"Target {test_case.target} authorized in scope",
                        parameter=test_case.parameter,
                        test_case_id=test_case.test_id,
                        detection_method="multipart_upload",
                        references=["CWE-434", "CWE-22"],
                    )
                    return result, finding

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
