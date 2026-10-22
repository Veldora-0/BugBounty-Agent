"""
SSRF & Out-of-Band Interaction Orchestration Engine (Phase 9).

Orchestrates passive candidate discovery, sink intelligence, canary issuance,
human approval gating, controlled baseline dispatch, and OOB correlation.
Converts verified server-side callbacks into deduplicated, non-exaggerated findings.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.scope.engine import ScopeEngine
from framework.ssrf.approval import HumanApprovalGate
from framework.ssrf.canary import CanaryManager
from framework.ssrf.comparator import SsrfComparator, SsrfComparisonResult
from framework.ssrf.intelligence import SsrfIntelligenceAnalyzer
from framework.ssrf.model import (
    OobInteractionType,
    SsrfCandidate,
    SsrfCategory,
    SsrfConfidence,
    SsrfEvidence,
)
from framework.ssrf.provider import (
    MockOobProvider,
    OobProvider,
    OobProviderFactory,
    OobProviderStatus,
)
from framework.ssrf.state import SsrfStateManager
from framework.state.dedup import FindingDeduplicator
from framework.validation.engine import SecurityValidationEngine
from framework.validation.policy import PolicyViolationError, SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse


class SsrfIntelligenceEngine:
    """
    Primary orchestrator for Server-Side Request Forgery intelligence,
    out-of-band canary correlation, and baseline verification.
    """

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
        self.policy = policy or SecurityTestPolicy()
        self.validation_engine = validation_engine or SecurityValidationEngine(
            program_dir=self.program_dir,
            scope_engine=self.scope_engine,
            policy=self.policy,
            send_request_hook=send_request_hook,
        )
        self.send_request_hook = send_request_hook
        self.state_mgr = SsrfStateManager(self.program_dir)
        self.approval_gate = HumanApprovalGate(self.state_mgr)

        program_name = os.path.basename(self.program_dir)
        self.oob_provider = oob_provider or OobProviderFactory.get_provider(provider_name="auto")
        self.canary_mgr = CanaryManager(
            provider=self.oob_provider,
            program_id=program_name,
            correlation_window_seconds=correlation_window_seconds,
        )

        # Scanner / client host IPs to exclude from server-side callback correlation
        self.excluded_source_ips: Set[str] = {"127.0.0.1", "::1", "192.168.1.50"}

    @property
    def total_bytes(self) -> int:
        """Global accepted response bytes accounted for during validation."""
        return getattr(self.validation_engine, "total_bytes", 0)

    @property
    def total_bytes_transferred(self) -> int:
        """Total network bytes transferred across all requests including partial and failed reads."""
        return getattr(self.validation_engine, "total_bytes_transferred", 0)

    # ---------------- Passive Discovery Pipeline ----------------

    def discover_candidates(
        self,
        asset_filter: Optional[str] = None,
        endpoint_filter: Optional[str] = None,
        param_filter: Optional[str] = None,
    ) -> List[SsrfCandidate]:
        """
        Discovers SSRF candidates from Phase 3 (WebApps), Phase 4 (JS),
        and Phase 5 (API) states. Merges with existing recorded candidates.
        """
        discovered = SsrfIntelligenceAnalyzer.discover_from_program_state(
            program_dir=self.program_dir,
            asset_filter=asset_filter,
            endpoint_filter=endpoint_filter,
        )

        existing = self.state_mgr.list_candidates()
        all_map: Dict[str, SsrfCandidate] = {}

        for c in existing:
            all_map[c.compute_fingerprint()] = c

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

    # ---------------- Controlled Request Builders ----------------

    def _build_mutated_request(
        self,
        candidate: SsrfCandidate,
        injected_value: str,
    ) -> ControlledRequest:
        """Constructs a request with parameter mutated to the canary or baseline value."""
        endpoint = candidate.endpoint
        param = candidate.parameter
        loc = (candidate.param_location or "QUERY").upper().strip()

        # Build base headers preserving candidate custom headers
        headers: Dict[str, str] = {
            "User-Agent": "BugBounty-Agent/1.0 (SSRF-Intelligence)",
        }
        if getattr(candidate, "headers", None):
            headers.update(candidate.headers)
        elif candidate.provenance and isinstance(candidate.provenance.get("headers"), dict):
            headers.update(candidate.provenance["headers"])

        def _get_header(hdr_dict: Dict[str, str], name: str) -> Optional[str]:
            for k, v in hdr_dict.items():
                if k.lower() == name.lower():
                    return v
            return None

        def _set_header(hdr_dict: Dict[str, str], name: str, val: str) -> None:
            for k in list(hdr_dict.keys()):
                if k.lower() == name.lower():
                    hdr_dict[k] = val
                    return
            hdr_dict[name] = val

        # 1. PATH mutation
        if loc == "PATH":
            mutated_path = endpoint
            replaced = False
            for tpl in (f"{{{param}}}", f":{param}", f"<{param}>"):
                if tpl in mutated_path:
                    mutated_path = mutated_path.replace(tpl, quote(injected_value, safe=""))
                    replaced = True
            if not replaced and endpoint.rstrip("/").endswith(f"/{param}"):
                mutated_path = endpoint.rstrip("/")[:-len(param)] + quote(injected_value, safe="")

            return ControlledRequest(
                url=mutated_path,
                method=candidate.method,
                headers=headers,
                mutated_target=param,
                mutated_value=injected_value,
            )

        # 2. JSON_BODY mutation
        if loc in ("JSON_BODY", "JSON"):
            _set_header(headers, "Content-Type", _get_header(headers, "Content-Type") or "application/json")
            orig_body = getattr(candidate, "body", None) or (
                candidate.provenance.get("body") if candidate.provenance else None
            )

            parsed_json: Dict[str, Any] = {}
            if orig_body:
                try:
                    loaded = json.loads(orig_body) if isinstance(orig_body, str) else orig_body
                    if isinstance(loaded, dict):
                        parsed_json = loaded
                except Exception:
                    parsed_json = {}

            # Handle dotted path keys e.g. "config.webhook_url"
            parts = param.split(".")
            curr = parsed_json
            for p in parts[:-1]:
                if p not in curr or not isinstance(curr[p], dict):
                    curr[p] = {}
                curr = curr[p]

            curr[parts[-1]] = injected_value
            new_body = json.dumps(parsed_json)

            return ControlledRequest(
                url=endpoint,
                method=candidate.method,
                headers=headers,
                body=new_body,
                mutated_target=param,
                mutated_value=injected_value,
            )

        # 3. FORM_BODY mutation
        if loc in ("FORM_BODY", "FORM", "FORM_DATA", "URLENCODED"):
            _set_header(headers, "Content-Type", _get_header(headers, "Content-Type") or "application/x-www-form-urlencoded")
            orig_body = getattr(candidate, "body", None) or (
                candidate.provenance.get("body") if candidate.provenance else None
            )

            new_qsl: List[Tuple[str, str]] = []
            replaced = False
            if orig_body and isinstance(orig_body, str):
                try:
                    qsl = parse_qsl(orig_body, keep_blank_values=True)
                    for k, v in qsl:
                        if k == param:
                            new_qsl.append((k, injected_value))
                            replaced = True
                        else:
                            new_qsl.append((k, v))
                except Exception:
                    new_qsl = []

            if not replaced:
                new_qsl.append((param, injected_value))

            new_body = urlencode(new_qsl)
            return ControlledRequest(
                url=endpoint,
                method=candidate.method,
                headers=headers,
                body=new_body,
                mutated_target=param,
                mutated_value=injected_value,
            )

        # 4. XML_BODY mutation
        if loc in ("XML_BODY", "XML", "XML_ENTITY"):
            _set_header(headers, "Content-Type", _get_header(headers, "Content-Type") or "application/xml")
            orig_body = getattr(candidate, "body", None) or (
                candidate.provenance.get("body") if candidate.provenance else None
            )

            escaped_val = (
                injected_value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&apos;")
            )

            new_body = ""
            if orig_body and isinstance(orig_body, str) and orig_body.strip():
                try:
                    import xml.etree.ElementTree as ET
                    from framework.common.xml_safe import SafeXMLParseError, safe_parse_xml
                    root = safe_parse_xml(orig_body.encode("utf-8"), disallow_dtd=False, max_expanded_chars=20_000)
                    found = False
                    for el in root.iter():
                        tag = el.tag.split("}")[-1] if "}" in el.tag else el.tag
                        if tag.lower() == param.lower():
                            el.text = injected_value
                            found = True
                            break
                    if not found:
                        sub = ET.SubElement(root, param)
                        sub.text = injected_value
                    new_body = ET.tostring(root, encoding="utf-8").decode("utf-8")
                except SafeXMLParseError:
                    # Input violates XML security bounds; do not regex-substitute into dangerous body
                    new_body = f'<?xml version="1.0" encoding="UTF-8"?><root><{param}>{escaped_val}</{param}></root>'
                except Exception:
                    import re
                    pattern = re.compile(rf"(<{re.escape(param)}[^>]*>)(.*?)(</{re.escape(param)}>)", re.IGNORECASE | re.DOTALL)
                    if pattern.search(orig_body):
                        new_body = pattern.sub(rf"\g<1>{escaped_val}\g<3>", orig_body)
                    else:
                        new_body = f'<?xml version="1.0" encoding="UTF-8"?><root><{param}>{escaped_val}</{param}></root>'
            else:
                new_body = f'<?xml version="1.0" encoding="UTF-8"?><root><{param}>{escaped_val}</{param}></root>'

            return ControlledRequest(
                url=endpoint,
                method=candidate.method,
                headers=headers,
                body=new_body,
                mutated_target=param,
                mutated_value=injected_value,
            )

        # 5. Default QUERY parameter mutation
        parsed = urlparse(endpoint)
        qsl = parse_qsl(parsed.query, keep_blank_values=True)
        new_qsl = []
        replaced = False
        for k, v in qsl:
            if k == param:
                new_qsl.append((k, injected_value))
                replaced = True
            else:
                new_qsl.append((k, v))
        if not replaced:
            new_qsl.append((param, injected_value))

        new_query = urlencode(new_qsl)
        mutated_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        ))

        return ControlledRequest(
            url=mutated_url,
            method=candidate.method,
            headers=headers,
            mutated_target=param,
            mutated_value=injected_value,
        )

    # ---------------- Active Controlled Validation ----------------

    def validate_candidate(
        self,
        candidate: SsrfCandidate,
        force_approved: bool = False,
        poll_wait_seconds: float = 3.0,
    ) -> Tuple[SsrfCandidate, Optional[Finding]]:
        """
        Executes controlled, non-destructive SSRF verification for a candidate:
        1. Human approval check
        2. Scope boundary check (Agent-side safety)
        3. Policy check (Safe methods only: GET, HEAD, OPTIONS)
        4. Canary issuance
        5. Benign Baseline capture
        6. Canary Probe dispatch
        7. OOB Provider polling & correlation
        8. Differential analysis & false-positive elimination
        9. Finding deduplication
        """
        # 1. Human Approval Gate
        if not candidate.is_approved_for_execution() and not force_approved:
            candidate.notes = "Execution halted: awaiting explicit human approval gate."
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        # 2. Scope Validation (Agent Network Safety)
        if self.validation_engine:
            try:
                self.validation_engine.check_request_scope(candidate.endpoint)
            except Exception as e:
                candidate.lifecycle_state = "OUT_OF_SCOPE"
                candidate.notes = f"Target endpoint {candidate.endpoint} is out of authorized scope: {e}"
                self.state_mgr.save_candidate(candidate)
                return candidate, None

        # 3. Policy Verification (Safe HTTP methods only)
        if candidate.method not in ("GET", "HEAD", "OPTIONS"):
            candidate.lifecycle_state = "REJECTED_METHOD"
            candidate.notes = f"Method {candidate.method} rejected: only non-destructive safe methods permitted."
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        # 4. OOB Provider Availability Verification (Fail closed before canary issuance and any request dispatch)
        if not self.oob_provider:
            candidate.lifecycle_state = "UNAVAILABLE"
            candidate.notes = "SSRF OOB probe skipped: no OOB provider configured. Zero network requests dispatched."
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        prov_status = self.oob_provider.registration_status()
        prov_name = self.oob_provider.name()

        if prov_status != OobProviderStatus.AVAILABLE:
            candidate.lifecycle_state = prov_status.value
            candidate.notes = (
                f"SSRF OOB verification unavailable: provider '{prov_name}' status is {prov_status.value} "
                f"(live polling not operational). Zero network requests dispatched."
            )
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        # 5. Canary Issuance
        canary_token, canary_url = self.canary_mgr.issue_canary(candidate.candidate_id)
        candidate.callback_token = canary_token

        # 6. Explicit OOB Destination Trust Validation (Must not silently skip)
        if not hasattr(self.policy, "validate_oob_destination"):
            raise PolicyViolationError(
                "SecurityTestPolicy is missing required validate_oob_destination method."
            )
        try:
            self.policy.validate_oob_destination(canary_url)
        except (PolicyViolationError, ValueError) as e:
            candidate.lifecycle_state = "POLICY_VIOLATION"
            candidate.notes = f"OOB canary destination rejected by policy: {e}"
            self.state_mgr.save_candidate(candidate)
            return candidate, None

        # 7. Baseline Capture (Normal input / Benign control)
        baseline_resp: Optional[ControlledResponse] = None
        try:
            baseline_req = self._build_mutated_request(candidate, injected_value="https://example.com/favicon.ico")
            baseline_resp = self.validation_engine.send_request(baseline_req)
        except Exception:
            pass

        # 8. Canary Probe Dispatch
        probe_req = self._build_mutated_request(candidate, injected_value=canary_url)
        test_resp = self.validation_engine.send_request(probe_req)

        # 9. OOB Interaction Polling & Correlation
        time.sleep(poll_wait_seconds)
        interactions = self.canary_mgr.correlate_interactions(
            canary_token=canary_token,
            timeout=poll_wait_seconds,
            exclude_source_ips=self.excluded_source_ips,
        )

        # Record interactions in state
        for inter in interactions:
            self.state_mgr.save_interaction(inter)

        # 10. Comparison & False-Positive Elimination
        comp = SsrfComparator.evaluate(
            candidate=candidate,
            canary_token=canary_token,
            test_response=test_resp,
            baseline_response=baseline_resp,
            interactions=interactions,
            provider_name=self.oob_provider.name(),
        )

        candidate.evidence = comp.evidence
        candidate.notes = comp.summary

        # 11. Finding Generation & Deduplication
        is_mock = (
            prov_name == "mock"
            or isinstance(self.oob_provider, MockOobProvider)
            or getattr(self.oob_provider, "is_simulation", False)
        )

        finding: Optional[Finding] = None
        if comp.is_confirmed:
            if is_mock:
                # Mock harness verification: MUST NOT claim live target callback
                candidate.confidence = SsrfConfidence.SIMULATED
                candidate.lifecycle_state = "SIMULATED"
                summary = (
                    f"[LOCAL HARNESS SIMULATION] Out-of-band SSRF interaction correlated via Mock provider "
                    f"for endpoint '{candidate.endpoint}'. This confirms integration flow in local test harness "
                    f"and does NOT prove an attributable remote target callback."
                )
                if candidate.evidence:
                    candidate.evidence.evidence_summary = summary
                candidate.notes = summary

                finding = Finding(
                    title=f"Simulated Server-Side Request Forgery on {candidate.endpoint} ({candidate.parameter})",
                    summary=summary,
                    affected_asset=urlparse(candidate.endpoint).netloc or candidate.application,
                    affected_endpoint=candidate.endpoint,
                    vulnerability_type="Simulated Server-Side Request Forgery (SSRF)",
                    severity="INFORMATIONAL",
                    confidence="LOW",
                    lifecycle_state=FindingLifecycle.SIMULATED,
                    description=summary,
                    root_cause="Local test harness simulation.",
                    prerequisites="Local test environment with MockOobProvider.",
                    reproduction_steps=["Local test harness simulation."],
                    expected_result="Mock provider callback received in simulation.",
                    observed_result=f"Mock callback correlated for token '{canary_token}'.",
                    security_impact="Informational simulation only; does not represent a validated vulnerability.",
                    remediation="None required for simulated test.",
                    scope_reference=f"Target {candidate.endpoint} in authorized scope.",
                    parameter=candidate.parameter,
                )
            elif comp.interaction_type == OobInteractionType.DNS_ONLY:
                candidate.lifecycle_state = "OBSERVED"
                candidate.confidence = SsrfConfidence.OBSERVED
                vuln_type = "Server-Side DNS Resolution (Blind SSRF Primitive)"
                title = f"Server-Side DNS Resolution on {candidate.endpoint} ({candidate.parameter})"
                root_cause = "Application resolves remote hostnames supplied in user-controlled parameter."

                finding = Finding(
                    title=title,
                    summary=comp.summary,
                    affected_asset=urlparse(candidate.endpoint).netloc or candidate.application,
                    affected_endpoint=candidate.endpoint,
                    vulnerability_type=vuln_type,
                    severity=candidate.severity,
                    confidence="MEDIUM",
                    lifecycle_state=FindingLifecycle.OBSERVATION,
                    description=(
                        f"Controlled out-of-band verification confirmed server-side DNS resolution. "
                        f"Injected canary URL '{canary_url}' into parameter '{candidate.parameter}' at '{candidate.endpoint}'. "
                        f"The OOB callback provider '{self.oob_provider.name()}' recorded a DNS query without an HTTP connection. "
                        f"No internal network probing or cloud metadata was accessed."
                    ),
                    root_cause=root_cause,
                    prerequisites="Endpoint accessible over HTTP/HTTPS with URL parameter acceptance.",
                    reproduction_steps=[
                        f"1. Generate a unique canary identifier.",
                        f"2. Send {candidate.method} request to '{candidate.endpoint}' with parameter '{candidate.parameter}' set to canary URL.",
                        f"3. Observe asynchronous DNS callback on OOB provider.",
                    ],
                    expected_result="Endpoint validates and rejects arbitrary remote destination URLs.",
                    observed_result=f"Server initiated DNS resolution to external canary.",
                    security_impact="Server resolves arbitrary remote hostnames; may be chained for blind SSRF or DNS exfiltration.",
                    remediation="Implement strict domain whitelisting and disable resolution of user-supplied hostnames.",
                    scope_reference=f"Target {candidate.endpoint} in authorized scope.",
                    parameter=candidate.parameter,
                )
            else:
                candidate.lifecycle_state = "VALIDATED"
                candidate.confidence = SsrfConfidence.VALIDATED
                vuln_type = "Server-Side Request Forgery (SSRF)"
                title = f"Blind Server-Side Request Forgery on {candidate.endpoint} ({candidate.parameter})"
                root_cause = "Application initiates outbound server-side HTTP connections to user-controlled URLs."

                finding = Finding(
                    title=title,
                    summary=comp.summary,
                    affected_asset=urlparse(candidate.endpoint).netloc or candidate.application,
                    affected_endpoint=candidate.endpoint,
                    vulnerability_type=vuln_type,
                    severity=candidate.severity,
                    confidence="HIGH",
                    lifecycle_state=FindingLifecycle.VALIDATED,
                    description=(
                        f"Controlled out-of-band verification confirmed server-side network interaction. "
                        f"Injected canary URL '{canary_url}' into parameter '{candidate.parameter}' at '{candidate.endpoint}'. "
                        f"The OOB callback provider '{self.oob_provider.name()}' recorded a matching {comp.interaction_type.value} interaction. "
                        f"No internal network probing or cloud metadata was accessed."
                    ),
                    root_cause=root_cause,
                    prerequisites="Endpoint accessible over HTTP/HTTPS with URL parameter acceptance.",
                    reproduction_steps=[
                        f"1. Generate a unique canary identifier.",
                        f"2. Send {candidate.method} request to '{candidate.endpoint}' with parameter '{candidate.parameter}' set to canary URL.",
                        f"3. Observe asynchronous {comp.interaction_type.value} callback on OOB provider.",
                    ],
                    expected_result="Endpoint validates and rejects arbitrary remote destination URLs.",
                    observed_result=f"Server initiated {comp.interaction_type.value} interaction to external canary.",
                    security_impact="Unauthorized outbound network requests may allow internal reconnaissance or protocol abuse.",
                    remediation="Implement strict domain whitelisting, disable HTTP redirects to external hosts, and enforce egress firewall rules.",
                    scope_reference=f"Target {candidate.endpoint} in authorized scope.",
                    parameter=candidate.parameter,
                )

            # Deduplication
            existing_findings_list = list(self.state_mgr._read_json().get("findings", {}).values())
            is_dup, _ = FindingDeduplicator.check_duplicate(
                candidate_asset=finding.affected_asset,
                candidate_endpoint=finding.affected_endpoint,
                candidate_vuln=finding.vulnerability_type,
                candidate_root_cause=finding.root_cause,
                existing_findings=existing_findings_list,
            )
            if not is_dup:
                self.state_mgr.save_finding(finding.finding_id, finding.to_dict())
        else:
            candidate.lifecycle_state = "TESTED"
            candidate.confidence = SsrfConfidence.CANDIDATE

        self.state_mgr.save_candidate(candidate)
        return candidate, finding

    # ---------------- Top-Level Workflow Pipeline ----------------

    def run_evaluation(
        self,
        asset: Optional[str] = None,
        endpoint: Optional[str] = None,
        parameter: Optional[str] = None,
        category: Optional[str] = None,
        approve_all: bool = False,
        passive_only: bool = False,
        dry_run: bool = False,
        resume: bool = False,
        max_tests: int = 30,
        poll_wait_seconds: float = 3.0,
    ) -> Dict[str, Any]:
        """
        Orchestrates complete SSRF intelligence workflow.
        """
        candidates = self.discover_candidates(
            asset_filter=asset,
            endpoint_filter=endpoint,
            param_filter=parameter,
        )

        if category:
            candidates = [c for c in candidates if c.category.value == category.lower()]

        # Apply approval if requested
        if approve_all:
            for c in candidates:
                self.approval_gate.approve(c.candidate_id, approver="security-researcher-cli")
                c.approval_status = "APPROVED"
                c.lifecycle_state = "APPROVED"
                self.state_mgr.save_candidate(c)

        if passive_only or dry_run:
            return {
                "program": os.path.basename(self.program_dir),
                "mode": "dry-run" if dry_run else "passive-only",
                "provider": self.oob_provider.name(),
                "provider_status": self.oob_provider.registration_status().value,
                "total_candidates": len(candidates),
                "candidates": [c.to_dict() for c in candidates[:max_tests]],
                "summary": self.state_mgr.get_summary(),
            }

        # Active evaluation
        executed: List[SsrfCandidate] = []
        verified_findings: List[Finding] = []

        count = 0
        for c in candidates:
            if count >= max_tests:
                break

            if resume and c.lifecycle_state in (
                "VALIDATED",
                "OBSERVED",
                "TESTED",
                "SIMULATED",
                "UNAVAILABLE",
                "CONFIG_REQUIRED",
                "ERROR",
                "OUT_OF_SCOPE",
                "POLICY_VIOLATION",
            ):
                continue

            if not c.is_approved_for_execution() and not approve_all:
                continue

            cand_res, finding_res = self.validate_candidate(
                candidate=c,
                force_approved=approve_all,
                poll_wait_seconds=poll_wait_seconds,
            )
            executed.append(cand_res)
            if finding_res:
                verified_findings.append(finding_res)
            count += 1

        return {
            "program": os.path.basename(self.program_dir),
            "mode": "active",
            "provider": self.oob_provider.name(),
            "provider_status": self.oob_provider.registration_status().value,
            "total_candidates": len(candidates),
            "executed_tests": len(executed),
            "verified_findings": len(verified_findings),
            "findings": [f.to_dict() for f in verified_findings],
            "total_bytes_transferred": self.total_bytes_transferred,
            "summary": self.state_mgr.get_summary(),
        }
