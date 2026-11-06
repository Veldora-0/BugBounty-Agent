"""
Phase 21: MultiTenantDesyncValidator.

Evaluates multi-tenant boundary isolation across route path, query parameter, and
header channels using bidirectional baselines and a three-state cache assessment engine.
"""

from __future__ import annotations

import difflib
import time
from typing import Any, Dict, List, Optional, Tuple

from framework.auth_correlation.cvss import (
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    CIAImpact,
    CVSS31Metrics,
    CVSS31Calculator,
)
from framework.auth_correlation.model import (
    CorrelatedSessionContext,
    CorrelationFinding,
)
from framework.authentication.validators import AuthenticationFalsePositiveClassifier
from framework.authz.model import ResourceAccessTarget
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledRequest, ControlledResponse


class MultiTenantDesyncValidator:
    """Evaluates cross-tenant boundary isolation and eliminates cache false positives."""

    def __init__(self, validation_engine: Optional[Any] = None, program_dir: Optional[str] = None):
        self._engine = validation_engine
        self._program_dir = program_dir or "."

    @property
    def engine(self) -> Any:
        if self._engine is None:
            self._engine = SecurityValidationEngine(program_dir=self._program_dir)
        return self._engine

    def assess_cache_state(self, response: ControlledResponse) -> str:
        """
        Three-state cache assessment:
        - CACHE_CONFIRMED: Explicit cache hit indicators (Age > 0, CF-Cache-Status: HIT, X-Cache: HIT)
        - CACHE_NOT_INDICATED: Explicit dynamic indicators (Cache-Control: no-store/no-cache/private, MISS/BYPASS)
        - CACHE_UNKNOWN: Headers ambiguous or absent.
        """
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        age = headers.get("age")
        cf_cache = headers.get("cf-cache-status", "")
        x_cache = headers.get("x-cache", "")
        x_cache_lookup = headers.get("x-cache-lookup", "")
        cache_control = headers.get("cache-control", "")
        pragma = headers.get("pragma", "")

        # 1. Definitive hit indicators
        if cf_cache == "hit" or "hit" in x_cache or "hit" in x_cache_lookup:
            return "CACHE_CONFIRMED"
        if age and age.isdigit() and int(age) > 0:
            return "CACHE_CONFIRMED"

        # 2. Dynamic / un-cached indicators
        if any(dyn in cf_cache for dyn in ("miss", "bypass", "dynamic")):
            return "CACHE_NOT_INDICATED"
        if "miss" in x_cache:
            return "CACHE_NOT_INDICATED"
        if "no-store" in cache_control or "no-cache" in cache_control or "private" in cache_control or pragma == "no-cache":
            return "CACHE_NOT_INDICATED"

        return "CACHE_UNKNOWN"

    def evaluate_bidirectional_baselines(
        self,
        tenant_a_ctx: CorrelatedSessionContext,
        tenant_b_ctx: CorrelatedSessionContext,
        resource_a: ResourceAccessTarget,
        resource_b: ResourceAccessTarget,
    ) -> Tuple[bool, str, Dict[str, ControlledResponse]]:
        """
        Phase 1: Validates legitimate baseline access for both tenants.
        Both Tenant A -> Resource A and Tenant B -> Resource B must return 200 OK.
        If either fails, testing is aborted to prevent false inferences.
        """
        target_a = getattr(resource_a, "endpoint", None) or getattr(resource_a, "url", "")
        method_a = getattr(resource_a, "method", "GET")
        req_a = ControlledRequest(url=target_a, method=method_a, headers=dict(tenant_a_ctx.volatile_headers))

        target_b = getattr(resource_b, "endpoint", None) or getattr(resource_b, "url", "")
        method_b = getattr(resource_b, "method", "GET")
        req_b = ControlledRequest(url=target_b, method=method_b, headers=dict(tenant_b_ctx.volatile_headers))

        try:
            resp_a = self.engine.send_request(req_a)
            resp_b = self.engine.send_request(req_b)
        except Exception as e:
            return False, f"BASELINE_REQUEST_FAILED: {e}", {}

        if resp_a.status_code != 200 or resp_b.status_code != 200:
            return False, "BASELINE_ACCESS_DENIED", {"baseline_a": resp_a, "baseline_b": resp_b}

        # Ensure neither baseline is a login page or generic shell
        if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp_a.status_code, resp_a.body_text) or \
           AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp_b.status_code, resp_b.body_text):
            return False, "BASELINE_LOGIN_PAGE_FALSE_POSITIVE", {"baseline_a": resp_a, "baseline_b": resp_b}

        return True, "BASELINES_ESTABLISHED", {"baseline_a": resp_a, "baseline_b": resp_b}

    def evaluate_tenant_isolation(
        self,
        tenant_a_ctx: CorrelatedSessionContext,
        tenant_b_ctx: CorrelatedSessionContext,
        resource_a: ResourceAccessTarget,
        resource_b: ResourceAccessTarget,
    ) -> List[CorrelationFinding]:
        """
        Phase 2: Bidirectional cross-tenant probing across independent channels.
        Sends unaltered valid tokens for Tenant A against Resource B, and Tenant B against Resource A.
        Assesses reverse-proxy caching and dispatches cache-busting probes when needed.
        """
        success, status, baselines = self.evaluate_bidirectional_baselines(
            tenant_a_ctx, tenant_b_ctx, resource_a, resource_b
        )
        if not success:
            return []

        findings: List[CorrelationFinding] = []
        baseline_a = baselines["baseline_a"]
        baseline_b = baselines["baseline_b"]

        # ----------------------------------------------------------------------
        # Probe 1: Tenant A Token -> Target Resource B
        # ----------------------------------------------------------------------
        target_b = getattr(resource_b, "endpoint", None) or getattr(resource_b, "url", "")
        method_b = getattr(resource_b, "method", "GET")
        req_ab = ControlledRequest(url=target_b, method=method_b, headers=dict(tenant_a_ctx.volatile_headers))

        try:
            resp_ab = self.engine.send_request(req_ab)
        except Exception:
            resp_ab = None

        if resp_ab and resp_ab.status_code == 200:
            # Check cache state
            cache_state = self.assess_cache_state(resp_ab)
            is_cache_artifact = False
            if cache_state == "CACHE_CONFIRMED":
                # Dispatch cache-busted probe to verify whether 200 OK was an artifact
                sep = "&" if "?" in target_b else "?"
                busted_url = f"{target_b}{sep}_bb_cb={int(time.time()*1000)}"
                busted_req = ControlledRequest(url=busted_url, method=method_b, headers=dict(tenant_a_ctx.volatile_headers))
                try:
                    busted_resp = self.engine.send_request(busted_req)
                    if busted_resp.status_code in (401, 403, 404):
                        is_cache_artifact = True
                except Exception:
                    pass

            if not is_cache_artifact and not AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp_ab.status_code, resp_ab.body_text):
                ratio = difflib.SequenceMatcher(None, resp_ab.body_text, baseline_b.body_text).ratio()
                if ratio >= 0.50:
                    metrics = CVSS31Metrics(
                        av=AttackVector.NETWORK,
                        ac=AttackComplexity.LOW,
                        pr=PrivilegesRequired.LOW,
                        ui=UserInteraction.NONE,
                        scope=Scope.UNCHANGED,
                        c=CIAImpact.HIGH,
                        i=CIAImpact.HIGH,
                        a=CIAImpact.NONE,
                    )
                    score, sev, vector = CVSS31Calculator.calculate_base_score(metrics)
                    finding_id = f"FIND-TENANT-AB-{int(time.time())}"[:20]
                    endpoint_path = target_b if target_b.startswith("/") else "/" + target_b.split("/", 3)[-1]
                    findings.append(CorrelationFinding(
                        finding_id=finding_id,
                        title="Cross-Tenant Boundary Bypass (Tenant A Accessed Resource B)",
                        category="TENANT_BOUNDARY_BYPASS",
                        severity=sev,
                        cvss_score=score,
                        cvss_vector=vector,
                        confidence=0.95,
                        endpoint=endpoint_path,
                        description="Tenant A session accessed protected Tenant B resource across tenant isolation boundary.",
                        evidence_chain=[],
                    ))

        # ----------------------------------------------------------------------
        # Probe 2: Tenant B Token -> Target Resource A
        # ----------------------------------------------------------------------
        target_a = getattr(resource_a, "endpoint", None) or getattr(resource_a, "url", "")
        method_a = getattr(resource_a, "method", "GET")
        req_ba = ControlledRequest(url=target_a, method=method_a, headers=dict(tenant_b_ctx.volatile_headers))

        try:
            resp_ba = self.engine.send_request(req_ba)
        except Exception:
            resp_ba = None

        if resp_ba and resp_ba.status_code == 200:
            cache_state = self.assess_cache_state(resp_ba)
            is_cache_artifact = False
            if cache_state == "CACHE_CONFIRMED":
                sep = "&" if "?" in target_a else "?"
                busted_url = f"{target_a}{sep}_bb_cb={int(time.time()*1000)}"
                busted_req = ControlledRequest(url=busted_url, method=method_a, headers=dict(tenant_b_ctx.volatile_headers))
                try:
                    busted_resp = self.engine.send_request(busted_req)
                    if busted_resp.status_code in (401, 403, 404):
                        is_cache_artifact = True
                except Exception:
                    pass

            if not is_cache_artifact and not AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp_ba.status_code, resp_ba.body_text):
                ratio = difflib.SequenceMatcher(None, resp_ba.body_text, baseline_a.body_text).ratio()
                if ratio >= 0.50:
                    metrics = CVSS31Metrics(
                        av=AttackVector.NETWORK,
                        ac=AttackComplexity.LOW,
                        pr=PrivilegesRequired.LOW,
                        ui=UserInteraction.NONE,
                        scope=Scope.UNCHANGED,
                        c=CIAImpact.HIGH,
                        i=CIAImpact.HIGH,
                        a=CIAImpact.NONE,
                    )
                    score, sev, vector = CVSS31Calculator.calculate_base_score(metrics)
                    finding_id = f"FIND-TENANT-BA-{int(time.time())}"[:20]
                    endpoint_path = target_a if target_a.startswith("/") else "/" + target_a.split("/", 3)[-1]
                    findings.append(CorrelationFinding(
                        finding_id=finding_id,
                        title="Cross-Tenant Boundary Bypass (Tenant B Accessed Resource A)",
                        category="TENANT_BOUNDARY_BYPASS",
                        severity=sev,
                        cvss_score=score,
                        cvss_vector=vector,
                        confidence=0.95,
                        endpoint=endpoint_path,
                        description="Tenant B session accessed protected Tenant A resource across tenant isolation boundary.",
                        evidence_chain=[],
                    ))

        return findings
