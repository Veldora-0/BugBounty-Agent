"""
Stored XSS Intelligence & Retrieval Correlation Foundation for BugBounty-Agent.

Identifies potential stored XSS injection/retrieval candidate pairs, models
correlation pathways between state-changing inputs and reading endpoints,
and produces structured human-verification plans without executing automated
state-changing form submissions.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from framework.xss.model import (
    ReflectionState,
    XssCandidate,
    XssCategory,
    XssConfidence,
    XssContextType,
    XssEvidence,
)


# Common parameter names that store user-controlled persistent data
STORED_INPUT_PARAMS: Set[str] = {
    "comment", "message", "bio", "about", "description", "title", "content",
    "notes", "address", "nickname", "display_name", "first_name", "last_name",
    "company", "status", "feedback", "post", "review", "headline", "summary",
}

# Resource path keywords associated with data entry vs retrieval
STORAGE_INPUT_PATHS = re.compile(
    r"/(?:comment|feedback|profile|user|review|post|message|ticket|setting|account|bio)(?:/edit|/update|/create|/add|/save)?",
    re.IGNORECASE,
)
RETRIEVAL_PATHS = re.compile(
    r"/(?:comment|feedback|profile|user|review|post|message|ticket|setting|account|view|display|feed|timeline)",
    re.IGNORECASE,
)


class StoredXssEngine:
    """
    Models storage and retrieval candidate relationships across web application
    and API surfaces. Strictly non-disruptive: does not perform automated form posting.
    """

    @classmethod
    def identify_candidate_pairs(
        cls,
        endpoints: List[Dict[str, Any]],
        target_asset: str = "",
    ) -> List[XssCandidate]:
        """
        Analyzes discovered endpoints and parameters from webapp and API discovery
        to find candidate pairs where an input mutation is likely reflected on retrieval.
        """
        candidates: List[XssCandidate] = []

        # Partition endpoints into potential storage mutations and potential retrievals
        input_endpoints: List[Dict[str, Any]] = []
        retrieval_endpoints: List[Dict[str, Any]] = []

        for ep in endpoints:
            method = ep.get("method", "GET").upper()
            url = ep.get("url") or ep.get("path") or ""
            params = ep.get("parameters") or ep.get("params") or []

            # Check if input candidate
            if method in ("POST", "PUT", "PATCH") or STORAGE_INPUT_PATHS.search(url):
                # Check if has stored parameter keywords
                param_names = [p.get("name") if isinstance(p, dict) else str(p) for p in params]
                matching_params = [p for p in param_names if p.lower() in STORED_INPUT_PARAMS]
                if matching_params or method in ("POST", "PUT", "PATCH"):
                    input_endpoints.append({
                        "url": url,
                        "method": method,
                        "params": matching_params or param_names,
                    })

            # Check if retrieval candidate
            if method == "GET" and RETRIEVAL_PATHS.search(url):
                retrieval_endpoints.append({
                    "url": url,
                    "method": method,
                })

        # Correlate input and retrieval endpoints by resource keyword
        for inp in input_endpoints:
            inp_path = urlparse(inp["url"]).path.lower()
            for ret in retrieval_endpoints:
                ret_path = urlparse(ret["url"]).path.lower()

                # Check if paths share common resource entity (e.g. /profile, /comments)
                shared_tokens = set(re.findall(r"[a-z0-9]+", inp_path)) & set(re.findall(r"[a-z0-9]+", ret_path))
                meaningful_tokens = {t for t in shared_tokens if len(t) > 3 and t not in ("api", "v1", "v2", "json", "html")}

                if meaningful_tokens:
                    token = sorted(list(meaningful_tokens))[0]
                    params_to_flag = inp["params"] or [token]

                    for p in params_to_flag:
                        verification_plan = [
                            f"Step 1: Authenticate with a low-privileged test account.",
                            f"Step 2: Submit a benign canary marker (e.g. bbxss_stored_test) to '{inp['url']}' via {inp['method']} in parameter '{p}'.",
                            f"Step 3: Navigate to '{ret['url']}' via GET using a separate session or browser.",
                            f"Step 4: Inspect page source to verify whether the canary is rendered verbatim without context-aware HTML entity encoding.",
                            f"Constraint: Zero destructive or state-corrupting data entry permitted.",
                        ]

                        cand = XssCandidate(
                            category=XssCategory.STORED,
                            target_asset=target_asset,
                            endpoint=inp["url"],
                            parameter=p,
                            method=inp["method"],
                            context_type=XssContextType.HTML_BODY,
                            reflection_state=ReflectionState.ABSENT,
                            confidence=XssConfidence.OBSERVED,
                            lifecycle_state="CANDIDATE",
                            severity="LOW",
                            retrieval_endpoint=ret["url"],
                            retrieval_method=ret["method"],
                            evidence=XssEvidence(
                                canary_token=f"stored_candidate_{p}",
                                context_snippet=f"Input: {inp['method']} {inp['url']} ({p}) -> Retrieval: {ret['method']} {ret['url']}",
                                details={"verification_plan": verification_plan},
                            ),
                            notes=f"Candidate stored XSS pair identified across resource token '{token}'. Automated submission skipped per non-destructive policy.",
                        )
                        candidates.append(cand)

        return candidates

    @classmethod
    def passively_inspect_response(
        cls,
        response_body: str,
        retrieval_url: str,
        canary_token: str,
        target_asset: str = "",
    ) -> Optional[XssCandidate]:
        """
        Passively detects if a previously injected test canary token is present
        in a retrieval response without modifying any backend state.
        """
        if not canary_token or canary_token not in response_body:
            return None

        from framework.xss.context import HtmlContextAnalyzer

        analysis = HtmlContextAnalyzer.analyze(response_body, canary_token)
        if not analysis.canary_reflected:
            return None

        conf = XssConfidence.SUSPECTED if analysis.is_exploitable_context else XssConfidence.OBSERVED
        lifecycle = "OBSERVED" if analysis.canary_reflected else "CANDIDATE"

        return XssCandidate(
            category=XssCategory.STORED,
            target_asset=target_asset,
            endpoint=retrieval_url,
            parameter="stored_data",
            method="GET",
            context_type=analysis.context_type,
            reflection_state=analysis.reflection_state,
            confidence=conf,
            lifecycle_state=lifecycle,
            severity="HIGH" if analysis.is_exploitable_context else "MEDIUM",
            canary_token=canary_token,
            retrieval_endpoint=retrieval_url,
            retrieval_method="GET",
            evidence=XssEvidence(
                canary_token=canary_token,
                context_snippet=analysis.context_snippet,
                transformations_observed=analysis.transformations,
            ),
            notes=f"Stored canary token observed passively on retrieval endpoint {retrieval_url}.",
        )
