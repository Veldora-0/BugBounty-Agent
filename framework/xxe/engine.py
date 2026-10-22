"""
XXE & XML Parser Security Intelligence Engine (Phase 18).

Orchestrates passive candidate discovery, safe non-destructive synthetic entity generation,
baseline comparison, parser signal classification, out-of-band correlation, and finding deduplication.
Strictly prohibits local file extraction (file://) and cloud metadata probing.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
import uuid

from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.scope.engine import ScopeEngine
from framework.ssrf.canary import CanaryManager
from framework.ssrf.model import OobProviderStatus
from framework.ssrf.provider import MockOobProvider, OobProvider, OobProviderFactory
from framework.state.dedup import FindingDeduplicator
from framework.validation.engine import SecurityValidationEngine
from framework.validation.policy import PolicyViolationError, SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse
from framework.xxe.model import (
    XxeCandidate,
    XxeCategory,
    XxeConfidence,
    XxeEvidence,
    XxeInteractionType,
    XxeSource,
)
from framework.xxe.state import XxeStateManager


# Strict disallowed targets to guarantee zero system damage or sensitive file reads
DISALLOWED_TARGET_PATTERNS = [
    re.compile(r"file://", re.IGNORECASE),
    re.compile(r"/etc/(?:passwd|shadow|hosts|issue)", re.IGNORECASE),
    re.compile(r"win\.ini", re.IGNORECASE),
    re.compile(r"boot\.ini", re.IGNORECASE),
    re.compile(r"169\.254\.169\.254"),
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
]


class XxeIntelligenceEngine:
    """Primary orchestrator for safe XXE and server-side XML parser intelligence."""

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[SecurityTestPolicy] = None,
        validation_engine: Optional[SecurityValidationEngine] = None,
        send_request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        oob_provider: Optional[OobProvider] = None,
        correlation_window_seconds: float = 60.0,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.scope_engine = scope_engine
        if policy is not None:
            self.policy = policy
        else:
            self.policy = SecurityTestPolicy(
                allowed_methods={"GET", "HEAD", "OPTIONS", "POST"},
                block_destructive_actions=False,
            )
        self.send_request_hook = send_request_hook
        self.validation_engine = validation_engine or SecurityValidationEngine(
            program_dir=self.program_dir,
            scope_engine=self.scope_engine,
            policy=self.policy,
            send_request_hook=send_request_hook,
        )
        self.state_mgr = XxeStateManager(self.program_dir)

        program_name = os.path.basename(self.program_dir)
        self.oob_provider = oob_provider or OobProviderFactory.get_provider(provider_name="auto")
        self.canary_mgr = CanaryManager(
            provider=self.oob_provider,
            program_id=program_name,
            correlation_window_seconds=correlation_window_seconds,
        )

        self.excluded_source_ips: Set[str] = {"127.0.0.1", "::1", "192.168.1.50"}

    @property
    def total_bytes(self) -> int:
        """Global accepted response bytes accounted for during validation."""
        return getattr(self.validation_engine, "total_bytes", 0)

    @property
    def total_bytes_transferred(self) -> int:
        """Total network bytes transferred across all requests including partial and failed reads."""
        return getattr(self.validation_engine, "total_bytes_transferred", 0)

    # ---------------- Safety Policy Validator ----------------

    def _validate_payload_safety(self, payload: str) -> None:
        """Enforces that XXE test payloads never attempt sensitive file or metadata access."""
        for pattern in DISALLOWED_TARGET_PATTERNS:
            if pattern.search(payload):
                raise ValueError(
                    f"Disallowed payload pattern detected: '{pattern.pattern}'. "
                    f"BugBounty-Agent strictly prohibits local file extraction and cloud metadata access."
                )

    # ---------------- Candidate Discovery ----------------

    def discover_candidates(
        self,
        asset_filter: Optional[str] = None,
        endpoint_filter: Optional[str] = None,
        param_filter: Optional[str] = None,
    ) -> List[XxeCandidate]:
        """Discovers XML-accepting endpoints from prior intelligence states and existing candidates."""
        existing = self.state_mgr.list_candidates()
        all_map: Dict[str, XxeCandidate] = {c.compute_fingerprint(): c for c in existing}

        discovered: List[XxeCandidate] = []

        # 1. Inspect API State (endpoints with application/xml or xml schema)
        api_state_file = os.path.join(self.program_dir, "state", "api.json")
        if os.path.exists(api_state_file):
            try:
                with open(api_state_file, "r", encoding="utf-8") as f:
                    api_data = json.load(f)
                for ep in api_data.get("endpoints", {}).values():
                    url = ep.get("url") or f"http://{ep.get('host', 'unknown')}{ep.get('path', '/')}"
                    content_types = ep.get("consumes", []) + ep.get("produces", [])
                    is_xml = any("xml" in str(ct).lower() for ct in content_types)
                    if is_xml:
                        cand = XxeCandidate(
                            application=ep.get("api_type", "API"),
                            endpoint=url,
                            parameter="xml_body",
                            param_location="XML_BODY",
                            method=ep.get("method", "POST"),
                            source_intel=XxeSource("API_SCHEMA", "xml_body", context="API consumes XML"),
                        )
                        discovered.append(cand)
            except Exception:
                pass

        # 2. Inspect WebApp State (forms or endpoints with XML keywords)
        webapp_state_file = os.path.join(self.program_dir, "state", "webapp.json")
        if os.path.exists(webapp_state_file):
            try:
                with open(webapp_state_file, "r", encoding="utf-8") as f:
                    web_data = json.load(f)
                for form in web_data.get("forms", {}).values():
                    action = form.get("action_url") or ""
                    enc = form.get("enctype") or ""
                    if "xml" in action.lower() or "xml" in enc.lower():
                        cand = XxeCandidate(
                            application="WebApp",
                            endpoint=action,
                            parameter="form_xml",
                            param_location="XML_BODY",
                            method=form.get("method", "POST"),
                            source_intel=XxeSource("WEBAPP_FORM", "form_xml", context="Form with XML enctype"),
                        )
                        discovered.append(cand)
            except Exception:
                pass

        # Merge newly discovered
        for c in discovered:
            fp = c.compute_fingerprint()
            if fp not in all_map:
                all_map[fp] = c
                self.state_mgr.save_candidate(c)

        candidates = list(all_map.values())
        if endpoint_filter:
            candidates = [c for c in candidates if endpoint_filter in c.endpoint]
        if asset_filter:
            candidates = [c for c in candidates if asset_filter in c.endpoint or asset_filter in c.application]
        if param_filter:
            candidates = [c for c in candidates if c.parameter.lower() == param_filter.lower()]

        return candidates

    # ---------------- Controlled Payload & Request Builders ----------------

    def _build_synthetic_reflection_payload(
        self,
        candidate: XxeCandidate,
        entity_name: str,
        canary_marker: str,
    ) -> str:
        """Constructs a non-destructive synthetic internal entity expansion payload."""
        orig_body = candidate.body or ""
        param = candidate.parameter or "val"

        # Check if original XML body has root and elements
        if orig_body and "<" in orig_body and ">" in orig_body:
            # Inject DTD definition before root element
            match = re.search(r"<([a-zA-Z0-9_\-]+)[^>]*>", orig_body)
            if match:
                root_tag = match.group(1)
                dtd_decl = f'<!DOCTYPE {root_tag} [\n  <!ENTITY {entity_name} "{canary_marker}">\n]>\n'
                clean_body = re.sub(r"<!DOCTYPE[^>]*(\[[^\]]*\])?>", "", orig_body, flags=re.IGNORECASE).strip()
                # If param element exists, substitute its text with &entity_name;
                elem_pat = re.compile(rf"(<{re.escape(param)}[^>]*>)(.*?)(</{re.escape(param)}>)", re.IGNORECASE | re.DOTALL)
                if elem_pat.search(clean_body):
                    mutated = elem_pat.sub(rf"\g<1>&{entity_name};\g<3>", clean_body)
                else:
                    mutated = clean_body.replace(f"</{root_tag}>", f"  <{param}>&{entity_name};</{param}>\n</{root_tag}>")
                payload = dtd_decl + mutated
                self._validate_payload_safety(payload)
                return payload

        payload = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE test [\n'
            f'  <!ENTITY {entity_name} "{canary_marker}">\n'
            f']>\n'
            f'<test>\n'
            f'  <{param}>&{entity_name};</{param}>\n'
            f'</test>'
        )
        self._validate_payload_safety(payload)
        return payload

    def _build_blind_oob_payload(
        self,
        candidate: XxeCandidate,
        canary_url: str,
    ) -> str:
        """Constructs a non-destructive blind out-of-band external entity payload."""
        payload = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE test [\n'
            f'  <!ENTITY % oob SYSTEM "{canary_url}">\n'
            f'  %oob;\n'
            f']>\n'
            f'<test>\n'
            f'  <param>canary_probe</param>\n'
            f'</test>'
        )
        self._validate_payload_safety(payload)
        return payload

    def _build_baseline_payload(self, candidate: XxeCandidate) -> str:
        """Constructs a harmless baseline XML payload without DOCTYPE or entities."""
        param = candidate.parameter or "val"
        payload = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<test>\n'
            f'  <{param}>baseline_control_marker</{param}>\n'
            f'</test>'
        )
        self._validate_payload_safety(payload)
        return payload

    # ---------------- Active Controlled Validation ----------------

    def validate_candidate(
        self,
        candidate: XxeCandidate,
        force_approved: bool = False,
        poll_wait_seconds: float = 2.0,
    ) -> Tuple[XxeCandidate, Optional[Finding]]:
        """
        Executes controlled, non-destructive XXE verification:
        1. Human approval check
        2. Scope boundary check (Agent network safety)
        3. Baseline capture (benign XML without entities)
        4. Synthetic in-band entity reflection test
        5. Blind out-of-band canary test (if provider available)
        6. Response signal classification (distinguish parser error vs confirmed reflection)
        7. Finding deduplication and structured report generation
        """
        # 1. Human Approval Gate
        if not candidate.is_approved_for_execution() and not force_approved:
            candidate.notes = "Execution halted: awaiting explicit human approval gate."
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        # 2. Scope Validation
        if self.validation_engine:
            try:
                self.validation_engine.check_request_scope(candidate.endpoint)
            except Exception as e:
                candidate.lifecycle_state = "OUT_OF_SCOPE"
                candidate.notes = f"Target endpoint {candidate.endpoint} is out of authorized scope: {e}"
                self.state_mgr.save_candidate(candidate)
                return candidate, None

        # 3. Baseline Request (Benign XML)
        baseline_payload = self._build_baseline_payload(candidate)
        headers = dict(candidate.headers) if candidate.headers else {}
        if "Content-Type" not in headers and "content-type" not in headers:
            headers["Content-Type"] = "application/xml"

        baseline_req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method,
            headers=headers,
            body=baseline_payload,
            mutated_target="baseline",
            mutated_value="control",
        )
        baseline_resp = self.validation_engine.send_request(baseline_req)

        # 4. In-Band Synthetic Entity Reflection Probe
        canary_token = f"bbxxe_{uuid.uuid4().hex[:8]}"
        canary_marker = f"CONFIRMED_ENTITY_EXPANSION_{canary_token}"
        entity_name = f"canary_{uuid.uuid4().hex[:6]}"

        test_payload = self._build_synthetic_reflection_payload(candidate, entity_name, canary_marker)
        test_req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method,
            headers=headers,
            body=test_payload,
            mutated_target=candidate.parameter,
            mutated_value=canary_marker,
        )
        test_resp = self.validation_engine.send_request(test_req)

        # 5. Evaluate Reflection Signals
        resp_body = test_resp.body or ""
        test_status = test_resp.status_code

        finding: Optional[Finding] = None
        evidence: Optional[XxeEvidence] = None

        if canary_marker in resp_body:
            # Internal entity reflection confirmed: proves internal DTD processing, NOT external entity resolution (XXE)
            candidate.confidence = XxeConfidence.OBSERVED
            candidate.lifecycle_state = "OBSERVED"
            candidate.callback_token = canary_token
            summary = (
                f"Observed internal XML entity processing via harmless synthetic entity expansion on '{candidate.endpoint}'. "
                f"Defined internal entity '&{entity_name};' which resolved and reflected marker '{canary_marker}' "
                f"in HTTP {test_status} response. External entity resolution (XXE) was NOT established; zero sensitive files accessed."
            )
            evidence = XxeEvidence(
                test_id=f"xxe-test-{canary_token}",
                canary_token=canary_token,
                category=XxeCategory.INTERNAL_ENTITY_REFLECTION,
                interaction_type=XxeInteractionType.INTERNAL_ENTITY_REFLECTED,
                status_code=test_status,
                reflected_marker=canary_marker,
                evidence_summary=summary,
            )
            candidate.evidence = evidence
            candidate.notes = summary

            finding = Finding(
                title=f"Internal XML Entity Processing Observation on {candidate.endpoint}",
                summary=summary,
                affected_asset=urlparse(candidate.endpoint).netloc or candidate.application,
                affected_endpoint=candidate.endpoint,
                vulnerability_type="XML Entity Processing Observation",
                severity="INFORMATIONAL",
                confidence="MEDIUM",
                lifecycle_state=FindingLifecycle.OBSERVATION,
                description=(
                    f"The endpoint '{candidate.endpoint}' parses XML documents with internal DTD and entity "
                    f"expansion enabled. Controlled security testing confirmed that internal entities are resolved "
                    f"and reflected back in the HTTP response. External entity resolution (XXE) was NOT established. "
                    f"A harmless synthetic canary marker was injected and observed in the server response body "
                    f"without file extraction or network disruption."
                ),
                root_cause="XML parser is configured to allow internal DTD entity definitions.",
                prerequisites="Endpoint accepts XML requests or parses XML input bodies.",
                reproduction_steps=[
                    f"1. Send {candidate.method} request to '{candidate.endpoint}' with XML payload containing DOCTYPE entity declaration.",
                    f"2. Reference internal entity &{entity_name}; in request body.",
                    f"3. Observe resolved entity marker in HTTP response body.",
                ],
                expected_result="Endpoint disallows DOCTYPE declarations or parses XML in strict secure mode.",
                observed_result=f"Server resolved and reflected synthetic internal entity marker '{canary_marker}'. External entity resolution unconfirmed.",
                security_impact=(
                    "Internal entity expansion is enabled. While this does not prove external entity resolution (XXE), "
                    "allowing DTD processing may indicate insufficient XML parser hardening."
                ),
                remediation=(
                    "Disable DTD (Document Type Definitions) completely in the XML parser if not strictly required: "
                    "In Python defusedxml or disallow_dtd=True, in Java setFeature 'http://apache.org/xml/features/disallow-doctype-decl' to true."
                ),
                scope_reference=f"Target {candidate.endpoint} in authorized scope.",
                parameter=candidate.parameter,
            )

        else:
            # Check for explicit secure rejection / hardening against DTD
            secure_indicators = [
                "doctype declarations are prohibited",
                "doctype is not allowed",
                "doctype not allowed",
                "disallowed doctype",
                "prohibited on this endpoint",
                "disallow-doctype-decl",
            ]
            is_secure_reject = any(ind in resp_body.lower() for ind in secure_indicators)

            # Check for parser errors suggesting active XML parser
            parser_error_indicators = [
                "xml syntax error",
                "entity expansion",
                "parser error",
                "saxparseexception",
                "xmlstreamexception",
            ]
            has_parser_error = any(ind in resp_body.lower() for ind in parser_error_indicators)

            if is_secure_reject:
                candidate.confidence = XxeConfidence.CANDIDATE
                candidate.lifecycle_state = "TESTED"
                candidate.notes = f"Endpoint explicitly prohibits DOCTYPE declarations (securely hardened against XXE); HTTP {test_status}."
            elif has_parser_error and test_status != baseline_resp.status_code:
                candidate.confidence = XxeConfidence.SUSPECTED
                candidate.lifecycle_state = "TESTED"
                candidate.notes = f"XML parser error detected in HTTP {test_status} response; DTD processing could not be confirmed."
            else:
                candidate.confidence = XxeConfidence.CANDIDATE
                candidate.lifecycle_state = "TESTED"
                candidate.notes = f"No entity expansion observed; endpoint responded with HTTP {test_status}."

        # 6. Finding Deduplication and Persistence
        if finding:
            existing_findings = list(self.state_mgr._read_json().get("findings", {}).values())
            is_dup, _ = FindingDeduplicator.check_duplicate(
                candidate_asset=finding.affected_asset,
                candidate_endpoint=finding.affected_endpoint,
                candidate_vuln=finding.vulnerability_type,
                candidate_root_cause=finding.root_cause,
                existing_findings=existing_findings,
                candidate_parameter=finding.parameter,
            )
            if not is_dup:
                self.state_mgr.save_finding(finding.finding_id, finding.to_dict())

        self.state_mgr.save_candidate(candidate)
        return candidate, finding

    def validate_oob_candidate(
        self,
        candidate: XxeCandidate,
        force_approved: bool = False,
    ) -> Tuple[XxeCandidate, Optional[Finding]]:
        """
        Executes controlled out-of-band (OOB) external entity verification if provider is available.
        Strictly distinguishes test harness mock callbacks from live target external callbacks:
        - Mock provider interactions yield SIMULATED (INFORMATIONAL) observations.
        - Only live, configured external providers with attributable interaction yield VALIDATED findings.
        """
        if not candidate.is_approved_for_execution() and not force_approved:
            candidate.notes = "Execution halted: awaiting explicit human approval gate."
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        if self.validation_engine:
            try:
                self.validation_engine.check_request_scope(candidate.endpoint)
            except Exception as e:
                candidate.lifecycle_state = "OUT_OF_SCOPE"
                candidate.notes = f"Target endpoint {candidate.endpoint} is out of authorized scope: {e}"
                self.state_mgr.save_candidate(candidate)
                return candidate, None

        # Verify OOB provider availability
        if not self.oob_provider:
            candidate.notes = "OOB probe skipped: no OOB provider available."
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        prov_status = self.oob_provider.registration_status()
        prov_name = self.oob_provider.name()

        # If provider requires configuration or is unavailable (e.g. live wire polling not operational)
        if prov_status != OobProviderStatus.AVAILABLE:
            candidate.notes = (
                f"OOB external entity verification unavailable: provider '{prov_name}' status is {prov_status.value} "
                f"(live polling not operational)."
            )
            candidate.lifecycle_state = "TESTED"
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        # Generate unique canary token and URL
        canary_token, canary_url = self.oob_provider.generate_canary(
            prefix="bb-xxe",
            test_id=candidate.candidate_id,
        )

        # Explicitly validate generated canary destination against dedicated trusted-provider policy before dispatch
        validate_fn = getattr(self.policy, "validate_oob_destination", None)
        if not hasattr(self.policy, "validate_oob_destination"):
            candidate.lifecycle_state = "POLICY_VIOLATION"
            candidate.notes = (
                "SecurityTestPolicy is missing required validate_oob_destination method. "
                "Zero network requests dispatched."
            )
            self.state_mgr.save_candidate(candidate)
            raise PolicyViolationError(
                "SecurityTestPolicy is missing required validate_oob_destination method."
            )
        if not callable(validate_fn):
            candidate.lifecycle_state = "POLICY_VIOLATION"
            candidate.notes = (
                "SecurityTestPolicy validate_oob_destination attribute is not callable. "
                "Zero network requests dispatched."
            )
            self.state_mgr.save_candidate(candidate)
            raise PolicyViolationError(
                "SecurityTestPolicy validate_oob_destination attribute is not callable."
            )
        try:
            validate_fn(canary_url)
        except (PolicyViolationError, ValueError) as e:
            candidate.lifecycle_state = "POLICY_VIOLATION"
            candidate.notes = f"OOB canary destination rejected by policy: {e}"
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        headers = dict(candidate.headers) if candidate.headers else {}
        if "Content-Type" not in headers and "content-type" not in headers:
            headers["Content-Type"] = "application/xml"

        # Build safe non-destructive external entity canary payload
        test_payload = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE test [\n'
            f'  <!ENTITY % oob SYSTEM "{canary_url}">\n'
            f'  %oob;\n'
            f']>\n'
            f'<test><canary>probe</canary></test>'
        )
        self._validate_payload_safety(test_payload)

        test_req = ControlledRequest(
            url=candidate.endpoint,
            method=candidate.method,
            headers=headers,
            body=test_payload,
            mutated_target="oob_system_entity",
            mutated_value=canary_url,
        )
        test_resp = self.validation_engine.send_request(test_req)

        # Poll for attributable OOB callback
        interactions = self.oob_provider.poll(token=canary_token, timeout=2.0)
        finding: Optional[Finding] = None

        if interactions:
            is_mock = (
                prov_name == "mock"
                or isinstance(self.oob_provider, MockOobProvider)
                or getattr(self.oob_provider, "is_simulation", False)
            )
            if is_mock:
                # Mock harness verification: MUST NOT claim live target callback
                candidate.confidence = XxeConfidence.SIMULATED
                candidate.lifecycle_state = "SIMULATED"
                candidate.callback_token = canary_token
                summary = (
                    f"[LOCAL HARNESS SIMULATION] Out-of-band external entity callback correlated via Mock provider "
                    f"for endpoint '{candidate.endpoint}'. This confirms integration flow in local test harness "
                    f"and does NOT prove an attributable remote target callback."
                )
                evidence = XxeEvidence(
                    test_id=f"xxe-oob-{canary_token}",
                    canary_token=canary_token,
                    category=XxeCategory.BLIND_OOB,
                    interaction_type=XxeInteractionType.SIMULATED_CALLBACK,
                    status_code=test_resp.status_code,
                    evidence_summary=summary,
                )
                candidate.evidence = evidence
                candidate.notes = summary

                finding = Finding(
                    title=f"Simulated Out-of-Band XML External Entity Interaction on {candidate.endpoint}",
                    summary=summary,
                    affected_asset=urlparse(candidate.endpoint).netloc or candidate.application,
                    affected_endpoint=candidate.endpoint,
                    vulnerability_type="Simulated XML External Entity Interaction",
                    severity="INFORMATIONAL",
                    confidence="LOW",
                    lifecycle_state=FindingLifecycle.SIMULATED,
                    description=summary,
                    root_cause="Local test harness simulation.",
                    prerequisites="Local test environment with MockOobProvider.",
                    reproduction_steps=["Simulated harness test."],
                    expected_result="Mock provider callback received in simulation.",
                    observed_result=f"Mock callback correlated for token '{canary_token}'.",
                    security_impact="Informational simulation only.",
                    remediation="None required for simulated test.",
                    scope_reference=f"Target {candidate.endpoint} in authorized scope.",
                    parameter="oob_system_entity",
                )
            else:
                # Genuine live attributable external entity callback
                candidate.confidence = XxeConfidence.VALIDATED
                candidate.lifecycle_state = "VALIDATED"
                candidate.callback_token = canary_token
                summary = (
                    f"Verified out-of-band XML External Entity (XXE) vulnerability on '{candidate.endpoint}'. "
                    f"Server resolved external SYSTEM entity and dispatched callback to authorized canary '{canary_url}'."
                )
                evidence = XxeEvidence(
                    test_id=f"xxe-oob-{canary_token}",
                    canary_token=canary_token,
                    category=XxeCategory.BLIND_OOB,
                    interaction_type=XxeInteractionType.HTTP_CALLBACK,
                    status_code=test_resp.status_code,
                    evidence_summary=summary,
                )
                candidate.evidence = evidence
                candidate.notes = summary

                finding = Finding(
                    title=f"Blind XML External Entity (XXE) Vulnerability on {candidate.endpoint}",
                    summary=summary,
                    affected_asset=urlparse(candidate.endpoint).netloc or candidate.application,
                    affected_endpoint=candidate.endpoint,
                    vulnerability_type="XML External Entity (XXE)",
                    severity="HIGH",
                    confidence="HIGH",
                    lifecycle_state=FindingLifecycle.VALIDATED,
                    description=(
                        f"Controlled security testing confirmed that the XML parser on '{candidate.endpoint}' "
                        f"fetches external DTD SYSTEM entities over the network. An attributable out-of-band "
                        f"HTTP interaction was received by the authorized canary listener with matching token."
                    ),
                    root_cause="XML parser is configured without disabling external entity resolution or external DTD fetching.",
                    prerequisites="Endpoint accepts XML input and parses external DTD references.",
                    reproduction_steps=[
                        f"1. Send {candidate.method} request to '{candidate.endpoint}' with XML containing external parameter entity.",
                        f"2. Observe server HTTP/DNS callback to canary listener.",
                    ],
                    expected_result="Endpoint disallows external DTD entities.",
                    observed_result=f"Server fetched external entity from canary '{canary_url}'.",
                    security_impact="Server can be induced to initiate network requests (SSRF) or exfiltrate data via external DTDs.",
                    remediation="Disable external DTD and entity resolution (e.g. disallow_dtd=True).",
                    scope_reference=f"Target {candidate.endpoint} in authorized scope.",
                    parameter="oob_system_entity",
                )
        else:
            candidate.confidence = XxeConfidence.CANDIDATE
            candidate.lifecycle_state = "TESTED"
            candidate.notes = "No out-of-band interaction observed for external entity probe."

        if finding:
            existing_findings = list(self.state_mgr._read_json().get("findings", {}).values())
            is_dup, _ = FindingDeduplicator.check_duplicate(
                candidate_asset=finding.affected_asset,
                candidate_endpoint=finding.affected_endpoint,
                candidate_vuln=finding.vulnerability_type,
                candidate_root_cause=finding.root_cause,
                existing_findings=existing_findings,
                candidate_parameter=finding.parameter,
            )
            if not is_dup:
                self.state_mgr.save_finding(finding.finding_id, finding.to_dict())

        self.state_mgr.save_candidate(candidate)
        return candidate, finding

    # ---------------- Top-Level Workflow Pipeline ----------------

    def run_evaluation(
        self,
        asset: Optional[str] = None,
        endpoint: Optional[str] = None,
        parameter: Optional[str] = None,
        approve_all: bool = False,
        passive_only: bool = False,
        dry_run: bool = False,
        resume: bool = False,
        max_tests: int = 30,
    ) -> Dict[str, Any]:
        """Orchestrates complete XXE research workflow."""
        candidates = self.discover_candidates(
            asset_filter=asset,
            endpoint_filter=endpoint,
            param_filter=parameter,
        )

        if approve_all:
            for c in candidates:
                self.state_mgr.approve_candidate(c.candidate_id, approver="security-researcher-cli")
                c.approval_status = "APPROVED"
                c.lifecycle_state = "APPROVED"
                self.state_mgr.save_candidate(c)

        if passive_only or dry_run:
            return {
                "program": os.path.basename(self.program_dir),
                "mode": "dry-run" if dry_run else "passive-only",
                "total_candidates": len(candidates),
                "candidates": [c.to_dict() for c in candidates[:max_tests]],
                "total_bytes_transferred": self.total_bytes_transferred,
                "summary": self.state_mgr.get_summary(),
            }

        executed: List[XxeCandidate] = []
        verified_findings: List[Finding] = []

        count = 0
        for c in candidates:
            if count >= max_tests:
                break
            if resume and c.lifecycle_state in ("VALIDATED", "OBSERVED", "TESTED"):
                continue
            if not c.is_approved_for_execution() and not approve_all:
                continue

            cand_res, finding_res = self.validate_candidate(candidate=c, force_approved=approve_all)
            executed.append(cand_res)
            if finding_res:
                verified_findings.append(finding_res)
            count += 1

        return {
            "program": os.path.basename(self.program_dir),
            "mode": "active",
            "total_candidates": len(candidates),
            "executed_tests": len(executed),
            "verified_findings": len(verified_findings),
            "findings": [f.to_dict() for f in verified_findings],
            "total_bytes_transferred": self.total_bytes_transferred,
            "summary": self.state_mgr.get_summary(),
        }
