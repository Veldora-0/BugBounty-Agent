"""
XSS Intelligence & Validation Engine for BugBounty-Agent.

Unifies Reflected XSS context analysis, DOM source-to-sink intelligence,
stored candidate correlation, and optional headless browser confirmation
into a cohesive, non-destructive security research engine.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from framework.findings.schema import Finding
from framework.scope.engine import ScopeEngine
from framework.validation.engine import SecurityValidationEngine
from framework.validation.policy import SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse
from framework.xss.browser import BrowserXssAssistant
from framework.xss.context import HtmlContextAnalyzer
from framework.xss.dom import DomXssEngine
from framework.xss.model import (
    ReflectionState,
    XssCandidate,
    XssCategory,
    XssConfidence,
    XssContextType,
    XssEvidence,
)
from framework.xss.state import XssStateManager
from framework.xss.stored import StoredXssEngine


class XssIntelligenceEngine:
    """
    Primary orchestrator for Cross-Site Scripting intelligence,
    context analysis, false-positive elimination, and candidate tracking.
    """

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[SecurityTestPolicy] = None,
        validation_engine: Optional[SecurityValidationEngine] = None,
        send_request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        browser_enabled: bool = False,
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
        self.state_mgr = XssStateManager(self.program_dir)
        self.browser_assistant = BrowserXssAssistant(
            enabled=browser_enabled,
            scope_validator=self.validation_engine.check_request_scope if self.validation_engine else None,
        )

    # ---------------- Active Reflected XSS Evaluation ----------------

    def evaluate_reflected_candidate(
        self,
        target_asset: str,
        endpoint: str,
        parameter: str,
        canary_token: Optional[str] = None,
        probe_suffix: str = "\"'<>",
        dry_run: bool = False,
    ) -> Tuple[Optional[XssCandidate], Optional[Finding]]:
        """
        Dispatches a controlled benign canary test to verify contextual reflection
        and determine whether characters are properly neutralized.
        """
        import uuid
        token = canary_token or f"bbxss_{uuid.uuid4().hex[:8]}"
        test_value = f"{token}{probe_suffix}"

        if dry_run:
            cand = XssCandidate(
                category=XssCategory.REFLECTED,
                target_asset=target_asset,
                endpoint=endpoint,
                parameter=parameter,
                method="GET",
                canary_token=token,
                confidence=XssConfidence.OBSERVED,
                lifecycle_state="TESTING",
                notes=f"Dry run plan: would dispatch probe '{test_value}' on '{parameter}'",
            )
            return cand, None

        # Build mutated request
        parsed = urlparse(endpoint)
        query_dict = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query_dict[parameter] = test_value
        new_query = urlencode(query_dict)
        mutated_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

        req = ControlledRequest(
            method="GET",
            url=mutated_url,
            headers={"User-Agent": "BugBounty-Agent/1.0 (XSS-Intelligence)"},
        )

        resp = self.validation_engine.send_request(req)
        content_type = resp.headers.get("content-type", "text/html")

        # Lexical context analysis
        analysis = HtmlContextAnalyzer.analyze(
            response_body=resp.body,
            canary_token=token,
            content_type=content_type,
            probe_chars=probe_suffix,
        )

        if not analysis.canary_reflected:
            return None, None

        # False-positive elimination: defended by encoding
        if analysis.is_defended:
            cand = XssCandidate(
                category=XssCategory.REFLECTED,
                target_asset=target_asset,
                endpoint=endpoint,
                parameter=parameter,
                method="GET",
                context_type=analysis.context_type,
                reflection_state=analysis.reflection_state,
                confidence=XssConfidence.REJECTED,
                lifecycle_state="REJECTED",
                severity="INFORMATIONAL",
                canary_token=token,
                evidence=XssEvidence(
                    canary_token=token,
                    context_snippet=analysis.context_snippet,
                    transformations_observed=analysis.transformations,
                ),
                notes=f"Reflected canary is properly neutralized ({analysis.reflection_state.value}) in {analysis.context_type.value}.",
            )
            self.state_mgr.save_candidate(cand)
            return cand, None

        # Reflected without proper defensive encoding
        is_exploitable = analysis.is_exploitable_context
        conf = XssConfidence.SUSPECTED if is_exploitable else XssConfidence.OBSERVED
        sev = "HIGH" if analysis.context_type in (XssContextType.SCRIPT_BLOCK, XssContextType.EVENT_HANDLER) else "MEDIUM"

        cand = XssCandidate(
            category=XssCategory.REFLECTED,
            target_asset=target_asset,
            endpoint=endpoint,
            parameter=parameter,
            method="GET",
            context_type=analysis.context_type,
            reflection_state=analysis.reflection_state,
            confidence=conf,
            lifecycle_state="OBSERVED",
            severity=sev,
            canary_token=token,
            evidence=XssEvidence(
                canary_token=token,
                context_snippet=analysis.context_snippet,
                transformations_observed=analysis.transformations,
            ),
            notes=f"Unencoded reflection observed in {analysis.context_type.value} context with status {analysis.reflection_state.value}.",
        )
        self.state_mgr.save_candidate(cand)

        finding_confidence = "HIGH" if conf == XssConfidence.SUSPECTED else ("CONFIRMED" if conf == XssConfidence.VALIDATED else "MEDIUM")
        finding = Finding(
            title=f"Potential Reflected XSS Context on {endpoint} ({parameter})",
            summary=f"Unencoded reflection observed in {analysis.context_type.value} context.",
            affected_asset=target_asset,
            affected_endpoint=endpoint,
            vulnerability_type="Cross-Site Scripting (Reflected)",
            severity=sev,
            confidence=finding_confidence,
            lifecycle_state="OBSERVED",
            description=(
                f"Canary probe injected into parameter '{parameter}' was reflected in HTTP response in "
                f"context '{analysis.context_type.value}' with unescaped active characters. Remains OBSERVED."
            ),
            root_cause="User input reflected in HTTP response without context-sensitive output encoding.",
            prerequisites="Target endpoint accessible over HTTP/HTTPS.",
            reproduction_steps=[
                f"Inject harmless probe '{test_value}' into parameter '{parameter}' at '{endpoint}'.",
                f"Observe unencoded reflection in HTTP response in context '{analysis.context_type.value}'.",
            ],
            expected_result="Input is sanitized, escaped, or omitted.",
            observed_result=f"Reflected with state {analysis.reflection_state.value}.",
            security_impact="Untrusted script execution in victim browser context if combined with interactive payload.",
            remediation="Apply context-aware output encoding (HTML, JS, attribute) and enforce strict CSP.",
            scope_reference=f"Target {target_asset} authorized in scope",
        )

        return cand, finding

    # ---------------- DOM XSS Intelligence Pipeline ----------------

    def run_dom_intelligence(
        self,
        target_asset: str,
        script_sources: Optional[List[Dict[str, str]]] = None,
    ) -> List[XssCandidate]:
        """
        Runs DOM XSS intelligence across provided scripts or Phase 4 state/javascript.json.
        """
        candidates: List[XssCandidate] = []

        # If scripts explicitly provided
        if script_sources:
            for s in script_sources:
                content = s.get("content", "")
                url = s.get("url", "inline")
                cands = DomXssEngine.analyze_script_text(
                    script_content=content,
                    file_path=url,
                    target_asset=target_asset,
                    endpoint=url,
                )
                for c in cands:
                    self.state_mgr.save_candidate(c)
                candidates.extend(cands)
            return candidates

        # Otherwise read Phase 4 state/javascript.json
        js_file = os.path.join(self.program_dir, "state", "javascript.json")
        if os.path.exists(js_file):
            try:
                with open(js_file, "r", encoding="utf-8") as f:
                    js_data = json.load(f)
                cands = DomXssEngine.analyze_javascript_intelligence(js_data, target_asset=target_asset)
                for c in cands:
                    self.state_mgr.save_candidate(c)
                candidates.extend(cands)
            except Exception:
                pass

        return candidates

    # ---------------- Stored XSS Correlation Pipeline ----------------

    def run_stored_correlation(
        self,
        target_asset: str,
        endpoints_data: Optional[List[Dict[str, Any]]] = None,
    ) -> List[XssCandidate]:
        """
        Correlates stored candidate injection/retrieval pairs from webapp and API discovery.
        """
        candidates: List[XssCandidate] = []

        if endpoints_data is None:
            # Load from webapp.json and api.json if present
            endpoints_data = []
            webapp_file = os.path.join(self.program_dir, "state", "webapp.json")
            if os.path.exists(webapp_file):
                try:
                    with open(webapp_file, "r", encoding="utf-8") as f:
                        w_data = json.load(f)
                        endpoints_data.extend(w_data.get("endpoints", []))
                except Exception:
                    pass

            api_file = os.path.join(self.program_dir, "state", "api.json")
            if os.path.exists(api_file):
                try:
                    with open(api_file, "r", encoding="utf-8") as f:
                        a_data = json.load(f)
                        endpoints_data.extend(a_data.get("endpoints", []))
                except Exception:
                    pass

        cands = StoredXssEngine.identify_candidate_pairs(endpoints_data, target_asset=target_asset)
        for c in cands:
            self.state_mgr.save_candidate(c)
        candidates.extend(cands)
        return candidates

    # ---------------- Comprehensive Pipeline ----------------

    def run_full_pipeline(
        self,
        target_asset: str,
        endpoints_to_test: Optional[List[Dict[str, Any]]] = None,
        passive_only: bool = False,
        dry_run: bool = False,
        max_tests: int = 20,
    ) -> Dict[str, Any]:
        """
        Runs comprehensive Phase 7 XSS intelligence:
        1. DOM XSS source-to-sink intelligence
        2. Stored candidate correlation
        3. Active Reflected XSS context evaluation (if not passive_only)
        """
        dom_cands = self.run_dom_intelligence(target_asset=target_asset)
        stored_cands = self.run_stored_correlation(target_asset=target_asset)
        reflected_cands: List[XssCandidate] = []
        findings: List[Finding] = []

        tests_run = 0
        if not passive_only and endpoints_to_test:
            for ep_info in endpoints_to_test:
                if tests_run >= max_tests:
                    break
                url = ep_info.get("url") or ep_info.get("endpoint") or ""
                params = ep_info.get("parameters") or ep_info.get("params") or []
                for p in params:
                    if tests_run >= max_tests:
                        break
                    p_name = p.get("name") if isinstance(p, dict) else str(p)
                    cand, finding = self.evaluate_reflected_candidate(
                        target_asset=target_asset,
                        endpoint=url,
                        parameter=p_name,
                        dry_run=dry_run,
                    )
                    tests_run += 1
                    if cand:
                        reflected_cands.append(cand)
                    if finding:
                        findings.append(finding)

        summary = self.state_mgr.get_summary()

        return {
            "target_asset": target_asset,
            "dom_candidates": len(dom_cands),
            "stored_candidates": len(stored_cands),
            "reflected_candidates": len(reflected_cands),
            "findings_recorded": len(findings),
            "state_summary": summary,
        }
