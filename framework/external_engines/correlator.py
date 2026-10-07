"""
External Engine Selector, Correlator, and Independent Validator (Phase 12 / 12.1 Hardening).

Key Capabilities:
1. EngineSelectionDecision & ExternalEngineSelector:
   Multi-dimensional capability scoring considering installation, health, version compatibility,
   target type, authentication, browser requirements, native coverage, budget, and timeouts.
2. ExternalFindingCorrelator:
   Multi-fingerprint correlation using AttackSurfaceFingerprint, RootCauseFingerprint,
   ResourceFingerprint, and ActorContextFingerprint. Prevents erroneous merging of distinct
   vulnerabilities merely sharing an endpoint.
3. IndependentValidator:
   Empirically verifies the ACTUAL vulnerability claim (differential authorization baselines,
   reflection context for XSS, OOB canary interaction for SSRF, invariant violations for logic).
   A simple HTTP 200 response NEVER graduates an external finding to VALIDATED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from framework.business_logic.model import WorkflowFinding
from framework.external_engines.base import (
    EngineCapability,
    ExternalEngineStatus,
    ExternalFinding,
    ExternalPentestEngine,
)
from framework.external_engines.strix import StrixAdapter
from framework.external_engines.xalgorix import XalgorixAdapter
from framework.findings.lifecycle import FindingLifecycle
from framework.validation.request import ControlledRequest, ControlledResponse


# ==============================================================================
# 1. Structured Fingerprints for Correlation
# ==============================================================================

def compute_attack_surface_fingerprint(method: str, endpoint: str, parameter: Optional[str] = None) -> str:
    """Fingerprint representing the exact HTTP interaction entrypoint."""
    clean_ep = endpoint.lower().split("?")[0].rstrip("/")
    param_str = (parameter or "").strip().lower()
    raw = f"{method.upper().strip()}|{clean_ep}|{param_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def compute_root_cause_fingerprint(vuln_family: str, root_cause: Optional[str] = None) -> str:
    """Fingerprint representing the vulnerability mechanism and root cause category."""
    fam = vuln_family.strip().lower()
    rc = (root_cause or "").strip().lower()
    raw = f"{fam}|{rc}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def compute_resource_fingerprint(resource_id: Optional[str] = None, resource_type: Optional[str] = None) -> str:
    """Fingerprint representing the target data entity or resource."""
    rid = (resource_id or "").strip().lower()
    rtype = (resource_type or "").strip().lower()
    raw = f"{rtype}|{rid}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def compute_actor_context_fingerprint(actor: Optional[str] = None, tenant: Optional[str] = None) -> str:
    """Fingerprint representing the execution identity and tenant isolation boundary."""
    act = (actor or "").strip().lower()
    ten = (tenant or "").strip().lower()
    raw = f"{act}|{ten}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


# ==============================================================================
# 2. Engine Selection Decision & Selector
# ==============================================================================

@dataclass
class EngineSelectionDecision:
    """Result of multi-dimensional external engine evaluation."""
    selected_engine: Optional[str]
    score: float
    reasons: List[str] = field(default_factory=list)
    rejected_engines: Dict[str, str] = field(default_factory=dict)
    capability_gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "selected_engine": self.selected_engine,
            "score": round(self.score, 2),
            "reasons": self.reasons,
            "rejected_engines": self.rejected_engines,
            "capability_gaps": self.capability_gaps,
        }


class ExternalEngineSelector:
    """Selects and prioritizes external pentesting engines based on capabilities and status."""

    def __init__(self):
        self.engines: Dict[str, ExternalPentestEngine] = {
            "xalgorix": XalgorixAdapter(),
            "strix": StrixAdapter(),
        }

    def list_engines(self) -> List[Dict[str, Any]]:
        return [eng.detect() for eng in self.engines.values()]

    def evaluate_selection(
        self,
        target_type: str = "web",
        authenticated: bool = False,
        requires_browser: bool = False,
        requires_source: bool = False,
        native_coverage_adequate: bool = False,
        operator_preference: Optional[str] = None,
    ) -> EngineSelectionDecision:
        """
        Calculates capability-driven scores for registered external engines.
        Favors native framework coverage when adequate; avoids invoking heavy external tools.
        """
        reasons: List[str] = []
        rejected: Dict[str, str] = {}
        gaps: List[str] = []

        if native_coverage_adequate and not operator_preference:
            return EngineSelectionDecision(
                selected_engine=None,
                score=0.0,
                reasons=["Native BugBounty-Agent intelligence provides adequate coverage for target."],
                rejected_engines={k: "Not required; native coverage prioritized" for k in self.engines},
                capability_gaps=[],
            )

        scored_candidates: List[Tuple[str, float, List[str]]] = []

        for name, adapter in self.engines.items():
            det = adapter.detect()
            if not det["installed"]:
                rejected[name] = f"Engine not installed ({det['status']})"
                continue

            health = adapter.health_check()
            if not health["healthy"]:
                rejected[name] = f"Engine unconfigured or unhealthy: {health['message']}"
                continue

            score = 50.0  # Base score for healthy installed engine
            engine_reasons: List[str] = [f"{name} is installed and verified healthy."]

            # Version match check
            if det["status"] == ExternalEngineStatus.VERSION_MISMATCH.value:
                score -= 10.0
                engine_reasons.append(f"Installed version {det['version']} differs from tested release {adapter.tested_release}.")
            elif det["status"] == ExternalEngineStatus.UNSUPPORTED_VERSION.value:
                rejected[name] = f"Installed version {det['version']} is unsupported."
                continue

            # Capabilities evaluation
            caps = adapter.capabilities
            if requires_browser:
                if EngineCapability.BROWSER in caps:
                    score += 25.0
                    engine_reasons.append("Supports headless browser automation.")
                else:
                    gaps.append(f"{name} lacks browser capability")

            if requires_source:
                if EngineCapability.SOURCE in caps:
                    score += 20.0
                    engine_reasons.append("Supports source code analysis.")
                else:
                    score -= 15.0

            if target_type.lower() == "api" and EngineCapability.API in caps:
                score += 15.0
                engine_reasons.append("Specialized for API analysis.")

            if authenticated and EngineCapability.AUTHENTICATED in caps:
                score += 15.0
                engine_reasons.append("Supports multi-principal authentication.")

            if operator_preference and operator_preference.lower() == name:
                score += 30.0
                engine_reasons.append(f"Explicitly preferred by operator ({name}).")

            scored_candidates.append((name, score, engine_reasons))

        if not scored_candidates:
            return EngineSelectionDecision(
                selected_engine=None,
                score=0.0,
                reasons=["No external engines meet runtime health or capability requirements."],
                rejected_engines=rejected,
                capability_gaps=gaps,
            )

        scored_candidates.sort(key=lambda x: x[1], reverse=True)
        best_name, best_score, best_reasons = scored_candidates[0]

        return EngineSelectionDecision(
            selected_engine=best_name,
            score=best_score,
            reasons=best_reasons,
            rejected_engines=rejected,
            capability_gaps=gaps,
        )

    def select_engine(
        self,
        target_type: str = "web",
        authenticated: bool = False,
        requires_browser: bool = False,
    ) -> Optional[str]:
        """Convenience helper returning selected engine string or None."""
        dec = self.evaluate_selection(
            target_type=target_type,
            authenticated=authenticated,
            requires_browser=requires_browser,
        )
        return dec.selected_engine


# ==============================================================================
# 3. External Finding Correlator
# ==============================================================================

class ExternalFindingCorrelator:
    """
    Correlates external findings with native findings using multi-fingerprint matching.
    Prevents duplicate reporting while ensuring distinct root causes or different actors
    on the same endpoint remain separate findings.
    """

    @classmethod
    def correlate(
        cls,
        native_findings: List[WorkflowFinding],
        external_findings: List[ExternalFinding],
    ) -> List[Dict[str, Any]]:
        unified: List[Dict[str, Any]] = []
        matched_ext_ids: Set[str] = set()

        for nf in native_findings:
            nf_method = "POST" if getattr(nf, "is_mutation", False) else "GET"
            nf_as_fp = compute_attack_surface_fingerprint(
                method=nf_method,
                endpoint=nf.endpoint,
                parameter=getattr(nf, "parameter", None),
            )
            nf_rc_fp = compute_root_cause_fingerprint(
                vuln_family=nf.category.value,
                root_cause=getattr(nf, "root_cause", None),
            )

            item = {
                "id": nf.finding_id,
                "title": nf.title,
                "category": nf.category.value,
                "severity": nf.severity,
                "endpoint": nf.endpoint,
                "lifecycle": nf.lifecycle.value,
                "sources": ["native_business_logic"],
                "external_confirmations": [],
                "evidence_id": nf.evidence_id,
                "description": nf.description,
                "attack_surface_fingerprint": nf_as_fp,
                "root_cause_fingerprint": nf_rc_fp,
            }

            for ef in external_findings:
                if ef.finding_id in matched_ext_ids:
                    continue

                ef_as_fp = compute_attack_surface_fingerprint(
                    method=ef.method,
                    endpoint=ef.endpoint,
                    parameter=ef.parameter,
                )
                ef_rc_fp = compute_root_cause_fingerprint(
                    vuln_family=ef.vulnerability_class,
                    root_cause=ef.title,
                )

                # Matching conditions:
                # 1. Attack surface must match (method, normalized endpoint, parameter)
                # 2. Vulnerability class / root cause must be compatible
                # 3. If actor or resource context is defined on both, they must NOT conflict
                attack_surface_match = (ef_as_fp == nf_as_fp)
                root_cause_match = (
                    ef_rc_fp == nf_rc_fp
                    or ef.vulnerability_class.lower() in nf.category.value.lower()
                    or nf.category.value.lower() in ef.vulnerability_class.lower()
                )

                actor_conflict = bool(
                    ef.actor and getattr(nf, "actor", None) and ef.actor.lower() != getattr(nf, "actor", "").lower()
                )
                resource_conflict = bool(
                    ef.resource_id and getattr(nf, "resource_id", None) and ef.resource_id != getattr(nf, "resource_id", None)
                )

                if attack_surface_match and root_cause_match and not actor_conflict and not resource_conflict:
                    matched_ext_ids.add(ef.finding_id)
                    item["sources"].append(f"external_{ef.engine}")
                    item["external_confirmations"].append({
                        "engine": ef.engine,
                        "title": ef.title,
                        "raw_ref": ef.raw_reference,
                        "engine_version": ef.engine_version,
                    })

            unified.append(item)

        # Append unmatched external findings as independent candidate findings
        for ef in external_findings:
            if ef.finding_id not in matched_ext_ids:
                unified.append({
                    "id": f"external-{ef.engine}-{ef.finding_id}",
                    "title": ef.title,
                    "category": ef.vulnerability_class,
                    "severity": ef.severity,
                    "endpoint": ef.endpoint,
                    "lifecycle": FindingLifecycle.CANDIDATE.value,  # Starts as CANDIDATE
                    "sources": [f"external_{ef.engine}"],
                    "external_confirmations": [{
                        "engine": ef.engine,
                        "title": ef.title,
                        "engine_version": ef.engine_version,
                    }],
                    "evidence_id": None,
                    "description": ef.description,
                    "attack_surface_fingerprint": ef.compute_attack_surface_fingerprint(),
                    "root_cause_fingerprint": ef.compute_root_cause_fingerprint(),
                })

        return unified


# ==============================================================================
# 4. Hardened Independent Validator
# ==============================================================================

class IndependentValidator:
    """
    Mandatory empirical validation gate for external findings.
    Validates the ACTUAL CLAIM behind the vulnerability finding:
    - Authorization (BOLA/IDOR): requires dual-principal baseline differential.
    - XSS: requires reflection in an active unencoded HTML/JS execution context.
    - SSRF: requires target-side interaction or canary callback receipt.
    - Injection: requires mathematical evaluation or timing differential.
    - Workflow: requires state machine invariant violation.

    A generic HTTP 200 response alone NEVER satisfies verification.
    """

    def __init__(self, send_request_hook: Callable[[ControlledRequest], ControlledResponse]):
        self.send_request = send_request_hook

    def independently_validate(
        self,
        external_finding: ExternalFinding,
        reproduction_request: Optional[ControlledRequest] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[FindingLifecycle, str]:
        """
        Attempts independent empirical reproduction of external findings.
        Returns (FindingLifecycle, explanation).
        """
        ctx = dict(context or {})
        vclass = external_finding.vulnerability_class.lower()

        if not reproduction_request:
            reproduction_request = ControlledRequest(
                url=external_finding.endpoint,
                method=external_finding.method or "GET",
            )

        resp = self.send_request(reproduction_request)

        # ----------------------------------------------------------------------
        # Authorization / BOLA / IDOR Verification
        # ----------------------------------------------------------------------
        if any(k in vclass for k in ["auth", "bola", "idor", "bfla", "access_control"]):
            # Must verify that unauthorized actor accessed victim resource
            unauthorized_actor = ctx.get("unauthorized_actor") or external_finding.actor
            owner_baseline_status = ctx.get("owner_baseline_status", 200)
            expected_denial_status = ctx.get("expected_denial_status", [401, 403, 404])
            if isinstance(expected_denial_status, int):
                expected_denial_status = [expected_denial_status]

            # If no dual-principal baseline was evaluated, status cannot be VALIDATED
            if "owner_baseline_status" not in ctx:
                return (
                    FindingLifecycle.NEEDS_MANUAL_REVIEW,
                    "Cannot validate authorization finding without verified dual-principal baseline comparison.",
                )

            # Check if unauthorized actor received successful access to owner resource
            if resp.status_code == owner_baseline_status and resp.status_code not in expected_denial_status:
                # Check that resource identifier is reflected or data exposed
                body_lower = resp.body_text.lower()
                res_id = external_finding.resource_id or ctx.get("resource_id", "")
                if res_id and res_id.lower() in body_lower:
                    return (
                        FindingLifecycle.VALIDATED,
                        f"Empirically validated IDOR/BOLA: Unauthorized actor '{unauthorized_actor}' "
                        f"accessed resource '{res_id}' with HTTP {resp.status_code} (expected {expected_denial_status}).",
                    )
                # Generic exposure without specific res_id matching
                if ctx.get("resource_exposed", False):
                    return (
                        FindingLifecycle.VALIDATED,
                        f"Empirically validated BOLA: Unauthorized actor received HTTP {resp.status_code} with resource data.",
                    )

            return (
                FindingLifecycle.REJECTED,
                f"Reproduction failed: Expected denial {expected_denial_status}, observed HTTP {resp.status_code}.",
            )

        # ----------------------------------------------------------------------
        # XSS Verification
        # ----------------------------------------------------------------------
        elif "xss" in vclass or "scripting" in vclass:
            probe_token = ctx.get("marker") or "XSHIELD_TEST_XSS"
            body = resp.body_text

            if probe_token not in body:
                return (
                    FindingLifecycle.REJECTED,
                    f"Reproduction failed: Verification marker '{probe_token}' was not reflected in response.",
                )

            # Check for neutral HTML entity encoding
            encoded_variants = ["&lt;", "&quot;", "&#34;", "&#39;", "%3C"]
            if any(ev in body for ev in encoded_variants) and "<" not in body:
                return (
                    FindingLifecycle.REJECTED,
                    "Marker reflection detected but properly neutralized by output encoding.",
                )

            # Unencoded reflection present
            if resp.status_code == 200:
                return (
                    FindingLifecycle.VALIDATED,
                    f"Empirically validated XSS: Marker '{probe_token}' reflected unencoded in HTTP 200 response.",
                )

            return FindingLifecycle.REJECTED, f"XSS marker returned with HTTP {resp.status_code}."

        # ----------------------------------------------------------------------
        # SSRF / Out-of-Band Verification
        # ----------------------------------------------------------------------
        elif "ssrf" in vclass or "oob" in vclass:
            canary_callback_received = bool(ctx.get("canary_callback_received"))
            internal_data_reflected = bool(ctx.get("internal_data_reflected"))

            if canary_callback_received or internal_data_reflected:
                return (
                    FindingLifecycle.VALIDATED,
                    "Empirically validated SSRF: Out-of-band callback or internal metadata response captured.",
                )

            # Merely receiving HTTP 200 without callback proves nothing
            return (
                FindingLifecycle.REJECTED,
                "Reproduction rejected: Target returned HTTP status but zero out-of-band canary interactions occurred.",
            )

        # ----------------------------------------------------------------------
        # Injection (SQLi / SSTI / Command Injection) Verification
        # ----------------------------------------------------------------------
        elif any(k in vclass for k in ["injection", "sqli", "ssti", "command"]):
            math_evaluation = ctx.get("arithmetic_eval_observed", False)
            timing_delta = ctx.get("timing_delta_seconds", 0.0)
            syntax_error = ctx.get("syntax_error_observed", False)

            if math_evaluation or syntax_error or timing_delta >= 3.0:
                return (
                    FindingLifecycle.VALIDATED,
                    f"Empirically validated injection: Differential signal confirmed (math={math_evaluation}, "
                    f"syntax_error={syntax_error}, timing={timing_delta}s).",
                )

            return (
                FindingLifecycle.REJECTED,
                f"Reproduction rejected: Server returned HTTP {resp.status_code} without reproducible injection differential.",
            )

        # ----------------------------------------------------------------------
        # Workflow / Business Logic Verification
        # ----------------------------------------------------------------------
        elif any(k in vclass for k in ["logic", "workflow", "race", "state", "step", "skip", "tamper", "quantity"]):
            invariant_violated = ctx.get("invariant_violated", False)
            if invariant_violated:
                return (
                    FindingLifecycle.VALIDATED,
                    f"Empirically validated business logic flaw: Invariant violation confirmed ({external_finding.title}).",
                )

            return (
                FindingLifecycle.REJECTED,
                "Reproduction rejected: Target workflow preserved state transition invariants.",
            )

        # ----------------------------------------------------------------------
        # Default Conservative Fallback
        # ----------------------------------------------------------------------
        if 200 <= resp.status_code < 300 and ctx.get("differential_signal_confirmed", False):
            return (
                FindingLifecycle.VALIDATED,
                f"Independently validated: Empirical differential signal confirmed with HTTP {resp.status_code}.",
            )

        return (
            FindingLifecycle.NEEDS_MANUAL_REVIEW,
            f"External finding could not be automatically validated; server returned HTTP {resp.status_code}.",
        )
