"""
Active Exposure Evaluator and Bounded Stream Processor for BugBounty-Agent.

Executes safe non-destructive probes for the 8 exposure classes:
- Enforces strict Evidence-Sufficiency Stopping Rules and records actual bytes consumed.
- Applies DifferentialSoft404Engine to eliminate SPA/custom-404 false alarms.
- Never promotes login forms to vulnerability findings (retains as OBSERVATION).
- Never reports HTTP 403 Forbidden as absent/REJECTED (retains as OBSERVED / ACCESS_RESTRICTED).
- Sanitizes all excerpts with sanitize_sensitive_data() before persistence.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
from typing import Any, Callable, Dict, List, Optional, Tuple

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.infrastructure.differential import DifferentialSoft404Engine
from framework.infrastructure.model import (
    ExposureCandidate,
    ExposureCategory,
    ExposureEvaluationResult,
)
from framework.infrastructure.signatures import InfrastructureSignatures
from framework.validation.request import ControlledRequest, ControlledResponse


CONFIG_SECRET_PATTERN = re.compile(
    r"^([A-Z0-9_]*(?:PASS|PWD|SECRET|KEY|TOKEN|AUTH|CREDENTIAL|PRIVATE)[A-Z0-9_]*\s*[:=]\s*)[^\r\n]+",
    re.IGNORECASE | re.MULTILINE,
)


def _classify_request_exception(exc: Exception) -> str:
    """
    Returns a safe, high-level diagnostic string for a request exception.
    Strictly avoids exposing raw str(exc), URLs, query strings, headers, credentials,
    or response content.
    """
    exc_type = type(exc).__name__
    exc_module = getattr(type(exc), "__module__", "")

    # Check for scope or policy violations first
    if "Scope" in exc_type or "scope" in exc_module.lower():
        return "scope authorization failure"
    if "Policy" in exc_type or "policy" in exc_module.lower():
        return "security policy violation"

    # Network, transport, and protocol categories
    if isinstance(exc, (TimeoutError, socket.timeout)) or "Timeout" in exc_type:
        return "connection or read timeout"
    if "SSL" in exc_type or "Certificate" in exc_type or "TLS" in exc_type:
        return "TLS/SSL handshake or certificate error"
    if isinstance(exc, ConnectionError) or any(k in exc_type for k in ("Connection", "Unreachable", "GaiError", "Resolve")):
        return "network connection failure"
    if "HTTP" in exc_type:
        return "HTTP protocol error"

    # Default fallback: safe sanitized exception class name
    safe_name = re.sub(r"[^A-Za-z0-9_]", "", exc_type) or "ExecutionError"
    return f"network transport error ({safe_name})"


def sanitize_exposure_content(text: str) -> str:
    """Sanitizes exposure text, ensuring key-value credentials and tokens are scrubbed."""
    if not text:
        return ""
    redacted = CONFIG_SECRET_PATTERN.sub(r"\g<1>[REDACTED_BY_BB_AGENT]", text)
    return sanitize_sensitive_data(redacted)


class InfrastructureExposureEvaluator:
    """
    Evaluates individual exposure candidates with safe bounds and strict stopping rules.
    """

    def __init__(
        self,
        send_request_fn: Callable[[ControlledRequest], ControlledResponse],
        max_response_bytes: int = 32_768,
        max_manifest_bytes: int = 8_192,
        max_binary_magic_bytes: int = 1_024,
    ):
        self.send_request_fn = send_request_fn
        self.max_response_bytes = max_response_bytes
        self.max_manifest_bytes = max_manifest_bytes
        self.max_binary_magic_bytes = max_binary_magic_bytes

    def evaluate_candidate(
        self,
        candidate: ExposureCandidate,
        baseline_response: Optional[ControlledResponse] = None,
    ) -> ExposureEvaluationResult:
        """
        Executes a targeted, non-destructive probe against candidate endpoint and evaluates the result.
        """
        # Enforce category-specific streaming ceilings at transport layer
        req_cap = self.max_response_bytes
        if candidate.category == ExposureCategory.BACKUP_ARCHIVE:
            req_cap = self.max_binary_magic_bytes
        elif candidate.category in (
            ExposureCategory.CONFIG_FILE,
            ExposureCategory.DEPLOYMENT_MANIFEST,
            ExposureCategory.SOURCE_MAP,
        ):
            req_cap = self.max_manifest_bytes

        req = ControlledRequest(
            method="GET",
            url=candidate.endpoint,
            headers={
                "User-Agent": "BugBounty-Agent/Infrastructure-Intelligence (Safe Research)",
                "Accept": "*/*",
            },
            max_response_bytes=req_cap,
        )

        try:
            cand_resp = self.send_request_fn(req)
        except Exception as e:
            category = _classify_request_exception(e)
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="LOW",
                lifecycle_state=FindingLifecycle.NEEDS_MANUAL_REVIEW,
                severity="INFORMATIONAL",
                reasons=[f"Request failed: {category}"],
                evidence={"error_category": category, "status": "failed"},
            )

        status = cand_resp.status_code
        headers = cand_resp.headers or {}
        body = cand_resp.body or ""
        bytes_consumed = cand_resp.size_bytes if hasattr(cand_resp, "size_bytes") else len(body.encode("utf-8", errors="replace"))

        # 1. HTTP 403 Forbidden Handling
        # Invariant: HTTP 403 alone does not prove the target resource exists (may be generic WAF,
        # default deny rule, or catch-all ACL). Must NOT be reported as REJECTED (absent), but
        # kept as an access-restricted observation with conservative confidence (LOW) and wording.
        if status == 403:
            sanitized_body = sanitize_exposure_content(body[:512])
            fingerprint = hashlib.sha256(sanitized_body.encode("utf-8")).hexdigest()
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="LOW",
                lifecycle_state=FindingLifecycle.OBSERVED,
                severity="INFORMATIONAL",
                reasons=[
                    "HTTP 403 Forbidden: access restricted by server access control or WAF policy "
                    "(does not verify underlying resource existence)"
                ],
                evidence={
                    "status_code": 403,
                    "access_restricted": True,
                    "resource_confirmed": False,
                    "sanitized_sample": sanitized_body,
                },
                bytes_consumed=bytes_consumed,
                stopping_rule_triggered=True,
                sanitized_excerpt=sanitized_body,
                evidence_fingerprint=fingerprint,
            )

        # 2. HTTP 401 Unauthorized / Basic Auth challenge
        if status == 401:
            sanitized_body = sanitize_exposure_content(body[:512])
            fingerprint = hashlib.sha256(sanitized_body.encode("utf-8")).hexdigest()
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="HIGH",
                lifecycle_state=FindingLifecycle.NEEDS_MANUAL_REVIEW,
                severity="INFORMATIONAL",
                reasons=["HTTP 401 Unauthorized: authentication challenge in place"],
                evidence={
                    "status_code": 401,
                    "auth_required": True,
                    "sanitized_sample": sanitized_body,
                },
                bytes_consumed=bytes_consumed,
                stopping_rule_triggered=True,
                sanitized_excerpt=sanitized_body,
                evidence_fingerprint=fingerprint,
            )

        # 3. Direct 404 / 410 / 500 error codes
        if status in (404, 410):
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="HIGH",
                lifecycle_state=FindingLifecycle.REJECTED,
                severity="INFORMATIONAL",
                reasons=[f"HTTP {status} Not Found"],
                bytes_consumed=bytes_consumed,
            )

        # 4. Check Category Structural Signatures
        ct_header = headers.get("Content-Type", headers.get("content-type", ""))
        sig_match = False
        sig_reason = ""
        sig_meta: Dict[str, Any] = {}
        has_sensitive_data = False
        is_login_page = False
        stopping_triggered = False

        if candidate.category == ExposureCategory.VERSION_CONTROL:
            sig_match, sig_reason, sig_meta = InfrastructureSignatures.match_version_control(body)
            stopping_triggered = True

        elif candidate.category == ExposureCategory.CONFIG_FILE:
            # Enforce 8 KB ceiling on config files
            sample_body = body[: self.max_manifest_bytes]
            sig_match, sig_reason, sig_meta, has_sensitive_data = InfrastructureSignatures.match_config_file(sample_body)
            stopping_triggered = True

        elif candidate.category == ExposureCategory.BACKUP_ARCHIVE:
            # Enforce 1 KB binary magic bytes ceiling
            raw_bytes = body.encode("latin-1", errors="replace")[: self.max_binary_magic_bytes]
            sig_match, sig_reason, sig_meta = InfrastructureSignatures.match_backup_archive(raw_bytes, ct_header)
            stopping_triggered = True

        elif candidate.category == ExposureCategory.ADMIN_INTERFACE:
            sig_match, sig_reason, sig_meta, is_login_page = InfrastructureSignatures.match_admin_interface(body, status)

        elif candidate.category == ExposureCategory.DEPLOYMENT_MANIFEST:
            sample_body = body[: self.max_manifest_bytes]
            sig_match, sig_reason, sig_meta = InfrastructureSignatures.match_deployment_manifest(sample_body)
            stopping_triggered = True

        elif candidate.category == ExposureCategory.SOURCE_MAP:
            sample_body = body[: self.max_manifest_bytes]
            sig_match, sig_reason, sig_meta = InfrastructureSignatures.match_source_map(sample_body)
            stopping_triggered = True

        elif candidate.category == ExposureCategory.DIRECTORY_LISTING:
            sig_match, sig_reason, sig_meta = InfrastructureSignatures.match_directory_listing(body)

        elif candidate.category == ExposureCategory.DEBUG_INTERFACE:
            sig_match, sig_reason, sig_meta = InfrastructureSignatures.match_debug_interface(body)

        # 5. Differential Soft-404 Analysis against Baseline (if provided)
        if baseline_response is not None:
            diff_result = DifferentialSoft404Engine.evaluate(
                candidate_status=status,
                candidate_headers=headers,
                candidate_body=body,
                baseline_status=baseline_response.status_code,
                baseline_headers=baseline_response.headers or {},
                baseline_body=baseline_response.body or "",
                candidate_final_url=getattr(cand_resp, "final_url", candidate.endpoint),
                baseline_final_url=getattr(baseline_response, "final_url", ""),
                candidate_has_structural_signature=sig_match,
            )
            if diff_result.is_soft_404:
                return ExposureEvaluationResult(
                    is_exposed=False,
                    confidence="CONFIRMED",
                    lifecycle_state=FindingLifecycle.REJECTED,
                    severity="INFORMATIONAL",
                    reasons=diff_result.reasons,
                    is_soft_404=True,
                    bytes_consumed=bytes_consumed,
                )

        # 6. Evaluate Signature Match & Classify
        if not sig_match:
            return ExposureEvaluationResult(
                is_exposed=False,
                confidence="HIGH",
                lifecycle_state=FindingLifecycle.REJECTED,
                severity="INFORMATIONAL",
                reasons=[f"No valid structural signature matched: {sig_reason}"],
                bytes_consumed=bytes_consumed,
            )

        # 7. Sensitive Data Redaction & Fingerprinting
        raw_excerpt = body[:1024]
        clean_excerpt = sanitize_exposure_content(raw_excerpt)
        # Accurately defined fingerprint: identifies the sanitized record representation
        fingerprint = hashlib.sha256(clean_excerpt.encode("utf-8")).hexdigest()

        # 8. Finding Classification & Realistic Severity Calibration
        if is_login_page:
            # Login pages are expected functionality: classify strictly as OBSERVATION (INFORMATIONAL)
            return ExposureEvaluationResult(
                is_exposed=True,
                confidence="HIGH",
                lifecycle_state=FindingLifecycle.OBSERVATION,
                severity="INFORMATIONAL",
                reasons=[sig_reason, "Standard login interface (retained as asset observation)"],
                evidence={
                    "status_code": status,
                    "content_type": ct_header,
                    "metadata": sig_meta,
                    "sanitized_excerpt": clean_excerpt,
                },
                bytes_consumed=bytes_consumed,
                stopping_rule_triggered=stopping_triggered,
                sanitized_excerpt=clean_excerpt,
                evidence_fingerprint=fingerprint,
            )

        # Validated Exposure Class Severities
        severity = "LOW"
        if candidate.category == ExposureCategory.VERSION_CONTROL:
            # .git/HEAD alone defaults to MEDIUM (never automatic HIGH)
            severity = "MEDIUM"

        elif candidate.category == ExposureCategory.CONFIG_FILE:
            # HIGH only if verified sensitive credential keys were found; otherwise MEDIUM or LOW
            severity = "HIGH" if has_sensitive_data else "MEDIUM"

        elif candidate.category == ExposureCategory.BACKUP_ARCHIVE:
            severity = "MEDIUM"

        elif candidate.category == ExposureCategory.ADMIN_INTERFACE:
            severity = "MEDIUM"

        elif candidate.category == ExposureCategory.DIRECTORY_LISTING:
            severity = "LOW"

        elif candidate.category == ExposureCategory.DEPLOYMENT_MANIFEST:
            severity = "LOW"

        elif candidate.category == ExposureCategory.SOURCE_MAP:
            severity = "LOW"

        elif candidate.category == ExposureCategory.DEBUG_INTERFACE:
            severity = "MEDIUM"

        return ExposureEvaluationResult(
            is_exposed=True,
            confidence="CONFIRMED",
            lifecycle_state=FindingLifecycle.VALIDATED,
            severity=severity,
            reasons=[sig_reason],
            evidence={
                "status_code": status,
                "content_type": ct_header,
                "metadata": sig_meta,
                "has_sensitive_data": has_sensitive_data,
                "credentials_untested": True, # Explicit declaration
                "sanitized_excerpt": clean_excerpt,
            },
            bytes_consumed=bytes_consumed,
            stopping_rule_triggered=stopping_triggered,
            sanitized_excerpt=clean_excerpt,
            evidence_fingerprint=fingerprint,
        )
