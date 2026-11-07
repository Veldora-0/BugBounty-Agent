"""
Phase 21: MultiTenantDesyncValidator.

Evaluates multi-tenant boundary isolation across route path, query parameter, and
header channels using bidirectional baselines and a three-state cache assessment engine.
"""

from __future__ import annotations

import difflib
import hashlib
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

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
    EvidencePersistenceError,
)
from framework.authentication.validators import AuthenticationFalsePositiveClassifier
from framework.authz.model import ResourceAccessTarget
from framework.common.evidence import sanitize_sensitive_data
from framework.validation.engine import SecurityValidationEngine
from framework.validation.request import ControlledRequest, ControlledResponse


class MultiTenantDesyncValidator:
    """Evaluates cross-tenant boundary isolation and eliminates cache false positives."""

    def __init__(
        self,
        validation_engine: Optional[Any] = None,
        program_dir: Optional[str] = None,
        evidence_store: Optional[Any] = None,
    ):
        self._engine = validation_engine
        self._program_dir = program_dir or "."
        self._evidence_store = evidence_store

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
        If either fails or returns ambiguous content, testing is aborted to prevent false inferences.
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

        if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp_a.status_code, resp_a.body_text) or \
           AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp_b.status_code, resp_b.body_text):
            return False, "BASELINE_GENERIC_SHELL_FALSE_POSITIVE", {"baseline_a": resp_a, "baseline_b": resp_b}

        return True, "BASELINES_ESTABLISHED", {"baseline_a": resp_a, "baseline_b": resp_b}

    def _verify_cache_and_evaluate_probe(
        self,
        resp: Optional[ControlledResponse],
        baseline_target: ControlledResponse,
        request_url: str,
        method: str,
        request_headers: Dict[str, str],
        tenant_label: str,
        channel_name: str,
    ) -> Optional[CorrelationFinding]:
        """Verifies candidate response against caching artifacts and generates finding if confirmed."""
        if not resp or resp.status_code != 200:
            return None

        # Safe error / challenge elimination
        if AuthenticationFalsePositiveClassifier.is_login_page_false_positive(resp.status_code, resp.body_text):
            return None
        if AuthenticationFalsePositiveClassifier.is_public_landing_or_generic_shell(resp.status_code, resp.body_text):
            return None
        if AuthenticationFalsePositiveClassifier.is_generic_status_or_empty_response(resp.status_code, resp.body_text):
            return None

        cache_state = self.assess_cache_state(resp)
        cache_busted_evidence = "N/A"

        if cache_state in ("CACHE_CONFIRMED", "CACHE_UNKNOWN"):
            sep = "&" if "?" in request_url else "?"
            busted_url = f"{request_url}{sep}_bb_cb={int(time.time()*1000)}"
            busted_req = ControlledRequest(url=busted_url, method=method, headers=request_headers)
            try:
                busted_resp = self.engine.send_request(busted_req)
            except Exception:
                return None  # Failed cache-busting request cannot confirm vulnerability

            if busted_resp.status_code in (401, 403, 404):
                return None  # Cache artifact eliminated
            elif busted_resp.status_code == 200:
                b_ratio = difflib.SequenceMatcher(None, busted_resp.body_text, baseline_target.body_text).ratio()
                if b_ratio < 0.50:
                    return None  # Cache busted probe did not return cross-tenant data
                cache_busted_evidence = f"Corroborated via cache-busting probe (status 200, similarity {b_ratio:.2f})"
            else:
                return None  # Ambiguous/inconclusive cache response

        ratio = difflib.SequenceMatcher(None, resp.body_text, baseline_target.body_text).ratio()
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

            clean_req = f"{method} {request_url}\nChannel: {channel_name}\nDirection: {tenant_label}\nHeaders: [REDACTED]"
            clean_res = f"HTTP {resp.status_code}\n{sanitize_sensitive_data(resp.body_text[:500])}"
            content_digest = hashlib.sha256((clean_req + clean_res).encode("utf-8")).hexdigest()

            evidence_chain: List[str] = []
            if self._evidence_store is not None:
                try:
                    evid_meta = self._evidence_store.save_http_capture(
                        request_text=clean_req,
                        response_text=clean_res,
                        metadata={
                            "hypothesis_category": "TENANT_ISOLATION",
                            "channel": channel_name,
                            "direction": tenant_label,
                            "cache_state": cache_state,
                        },
                        prefix=f"tenant_{channel_name.lower()}",
                    )
                    if not isinstance(evid_meta, dict) or not evid_meta.get("evidence_id"):
                        raise EvidencePersistenceError("EvidenceStore failed to return valid persisted evidence ID")
                    evidence_chain = [evid_meta["evidence_id"]]
                except Exception as e:
                    if isinstance(e, EvidencePersistenceError):
                        raise
                    raise EvidencePersistenceError(f"Failed to persist cross-tenant evidence: {e}")

            ep_hash = hashlib.sha256(f"{tenant_label}_{channel_name}_{request_url}".encode("utf-8")).hexdigest()[:10].upper()
            finding_id = f"FIND-TENANT-{ep_hash}"
            endpoint_path = request_url if request_url.startswith("/") else "/" + request_url.split("/", 3)[-1]
            desc_prefix = "" if self._evidence_store is not None else "[EVIDENCE_NOT_PERSISTED] "
            return CorrelationFinding(
                finding_id=finding_id,
                title=f"Cross-Tenant Boundary Bypass ({channel_name} Channel: {tenant_label})",
                category="TENANT_BOUNDARY_BYPASS",
                severity=sev,
                cvss_score=score,
                cvss_vector=vector,
                confidence=0.95,
                endpoint=endpoint_path,
                description=f"{desc_prefix}Cross-tenant access achieved via {channel_name} substitution ({tenant_label}) without valid tenant authorization. Cache state: {cache_state}. {cache_busted_evidence}. Content match ratio: {ratio:.2f}.",
                evidence_chain=evidence_chain,
            )

        return None

    def evaluate_tenant_isolation(
        self,
        tenant_a_ctx: CorrelatedSessionContext,
        tenant_b_ctx: CorrelatedSessionContext,
        resource_a: ResourceAccessTarget,
        resource_b: ResourceAccessTarget,
    ) -> List[CorrelationFinding]:
        """
        Phase 2: Bidirectional cross-tenant probing across path, query, and header channels.
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

        target_b = getattr(resource_b, "endpoint", None) or getattr(resource_b, "url", "")
        method_b = getattr(resource_b, "method", "GET")
        target_a = getattr(resource_a, "endpoint", None) or getattr(resource_a, "url", "")
        method_a = getattr(resource_a, "method", "GET")

        # ----------------------------------------------------------------------
        # Probe 1: Direct Path/URL Substitution (Tenant A -> Resource B)
        # ----------------------------------------------------------------------
        req_ab = ControlledRequest(url=target_b, method=method_b, headers=dict(tenant_a_ctx.volatile_headers))
        try:
            resp_ab = self.engine.send_request(req_ab)
        except Exception:
            resp_ab = None

        f_ab = self._verify_cache_and_evaluate_probe(
            resp_ab, baseline_b, target_b, method_b, dict(tenant_a_ctx.volatile_headers), "A_TO_B", "PATH"
        )
        if f_ab:
            findings.append(f_ab)

        # ----------------------------------------------------------------------
        # Probe 2: Direct Path/URL Substitution (Tenant B -> Resource A)
        # ----------------------------------------------------------------------
        req_ba = ControlledRequest(url=target_a, method=method_a, headers=dict(tenant_b_ctx.volatile_headers))
        try:
            resp_ba = self.engine.send_request(req_ba)
        except Exception:
            resp_ba = None

        f_ba = self._verify_cache_and_evaluate_probe(
            resp_ba, baseline_a, target_a, method_a, dict(tenant_b_ctx.volatile_headers), "B_TO_A", "PATH"
        )
        if f_ba:
            findings.append(f_ba)

        # ----------------------------------------------------------------------
        # Probe 3: Query Parameter Substitution (A -> B)
        # ----------------------------------------------------------------------
        tid_b = tenant_b_ctx.metadata.get("tenant_id")
        tid_a = tenant_a_ctx.metadata.get("tenant_id")
        if tid_b:
            sep = "&" if "?" in target_a else "?"
            query_url_ab = f"{target_a}{sep}tenant_id={tid_b}"
            req_q_ab = ControlledRequest(url=query_url_ab, method=method_a, headers=dict(tenant_a_ctx.volatile_headers))
            try:
                resp_q_ab = self.engine.send_request(req_q_ab)
                f_q_ab = self._verify_cache_and_evaluate_probe(
                    resp_q_ab, baseline_b, query_url_ab, method_a, dict(tenant_a_ctx.volatile_headers), "A_TO_B", "QUERY"
                )
                if f_q_ab:
                    findings.append(f_q_ab)
            except Exception:
                pass

        # ----------------------------------------------------------------------
        # Probe 4: Query Parameter Substitution (B -> A)
        # ----------------------------------------------------------------------
        if tid_a:
            sep = "&" if "?" in target_b else "?"
            query_url_ba = f"{target_b}{sep}tenant_id={tid_a}"
            req_q_ba = ControlledRequest(url=query_url_ba, method=method_b, headers=dict(tenant_b_ctx.volatile_headers))
            try:
                resp_q_ba = self.engine.send_request(req_q_ba)
                f_q_ba = self._verify_cache_and_evaluate_probe(
                    resp_q_ba, baseline_a, query_url_ba, method_b, dict(tenant_b_ctx.volatile_headers), "B_TO_A", "QUERY"
                )
                if f_q_ba:
                    findings.append(f_q_ba)
            except Exception:
                pass

        # ----------------------------------------------------------------------
        # Probe 5: Header Substitution (A -> B)
        # ----------------------------------------------------------------------
        if tid_b:
            hdr_headers_a = dict(tenant_a_ctx.volatile_headers)
            hdr_headers_a["X-Tenant-ID"] = tid_b
            req_h_ab = ControlledRequest(url=target_a, method=method_a, headers=hdr_headers_a)
            try:
                resp_h_ab = self.engine.send_request(req_h_ab)
                f_h_ab = self._verify_cache_and_evaluate_probe(
                    resp_h_ab, baseline_b, target_a, method_a, hdr_headers_a, "A_TO_B", "HEADER"
                )
                if f_h_ab:
                    findings.append(f_h_ab)
            except Exception:
                pass

        # ----------------------------------------------------------------------
        # Probe 6: Header Substitution (B -> A)
        # ----------------------------------------------------------------------
        if tid_a:
            hdr_headers_b = dict(tenant_b_ctx.volatile_headers)
            hdr_headers_b["X-Tenant-ID"] = tid_a
            req_h_ba = ControlledRequest(url=target_b, method=method_b, headers=hdr_headers_b)
            try:
                resp_h_ba = self.engine.send_request(req_h_ba)
                f_h_ba = self._verify_cache_and_evaluate_probe(
                    resp_h_ba, baseline_a, target_b, method_b, hdr_headers_b, "B_TO_A", "HEADER"
                )
                if f_h_ba:
                    findings.append(f_h_ba)
            except Exception:
                pass

        return findings
