"""
Authentication Surface Discovery Engine for BugBounty-Agent (Phase 14).

Discovers authentication endpoints, forms, API schemes, and session management surfaces
by consuming intelligence from previous phases (Phases 3, 4, 5, 8, and 12).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Set

from framework.authentication.models import (
    AuthenticationFlowType,
    AuthenticationStep,
)


class AuthenticationSurfaceDiscoverer:
    """Discovers and catalogs authentication endpoints across web, API, and client surfaces."""

    # Deterministic indicators for flow classification
    FLOW_PATTERNS = {
        AuthenticationFlowType.LOGIN: [
            r"/login", r"/signin", r"/auth/login", r"/api/v\d+/login",
            r"/authenticate", r"/oauth/token", r"/api/v\d+/auth/token",
        ],
        AuthenticationFlowType.LOGOUT: [
            r"/logout", r"/signout", r"/auth/logout", r"/api/v\d+/logout",
        ],
        AuthenticationFlowType.PASSWORD_CHANGE: [
            r"/password/change", r"/account/password", r"/change-password",
            r"/api/v\d+/password/change",
        ],
        AuthenticationFlowType.PASSWORD_RESET: [
            r"/password/reset", r"/forgot-password", r"/reset-password",
            r"/api/v\d+/password/reset", r"/account/recovery",
        ],
        AuthenticationFlowType.MFA_VERIFICATION: [
            r"/mfa", r"/2fa", r"/otp", r"/verify-mfa", r"/two-factor",
            r"/api/v\d+/mfa/verify",
        ],
        AuthenticationFlowType.TOKEN_REFRESH: [
            r"/token/refresh", r"/auth/refresh", r"/refresh-token",
            r"/api/v\d+/auth/refresh",
        ],
    }

    @classmethod
    def classify_endpoint(cls, endpoint: str) -> Optional[AuthenticationFlowType]:
        """Classifies a URL path into an authentication flow type based on deterministic heuristics."""
        clean_path = endpoint.lower().split("?")[0]
        for flow_type, patterns in cls.FLOW_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, clean_path):
                    return flow_type
        return None

    @classmethod
    def discover_from_workspace(
        cls,
        workspace_dir: str,
    ) -> List[AuthenticationStep]:
        """
        Consumes saved state from previous phases in the workspace directory.
        Reads web_applications.json, javascript.json, api_spec.json, and authz.json.
        """
        discovered_steps: List[AuthenticationStep] = []
        state_dir = os.path.join(workspace_dir, "state")
        if not os.path.isdir(state_dir):
            return discovered_steps

        # 1. Ingest Phase 3 WebApp intelligence
        webapp_file = os.path.join(state_dir, "web_applications.json")
        if os.path.isfile(webapp_file):
            try:
                with open(webapp_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for form in data.get("forms", []):
                        action = form.get("action", "")
                        flow = cls.classify_endpoint(action)
                        if flow:
                            discovered_steps.append(
                                AuthenticationStep(
                                    step_id=f"step_web_{len(discovered_steps)+1}",
                                    flow_type=flow,
                                    method=form.get("method", "POST").upper(),
                                    endpoint=action,
                                    parameter_names=list(form.get("inputs", {}).keys()),
                                    request_source="WEB_FORM",
                                    response_indicators=[],
                                )
                            )
            except Exception:
                pass

        # 2. Ingest Phase 4 JavaScript routes
        js_file = os.path.join(state_dir, "javascript.json")
        if os.path.isfile(js_file):
            try:
                with open(js_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for route in data.get("routes", []):
                        path = route if isinstance(route, str) else route.get("path", "")
                        flow = cls.classify_endpoint(path)
                        if flow:
                            discovered_steps.append(
                                AuthenticationStep(
                                    step_id=f"step_js_{len(discovered_steps)+1}",
                                    flow_type=flow,
                                    method="POST" if flow != AuthenticationFlowType.LOGOUT else "GET",
                                    endpoint=path,
                                    parameter_names=[],
                                    request_source="JS_ROUTE",
                                    response_indicators=[],
                                )
                            )
            except Exception:
                pass

        # 3. Ingest Phase 5 API specifications
        api_file = os.path.join(state_dir, "api_spec.json")
        if os.path.isfile(api_file):
            try:
                with open(api_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for path, path_obj in data.get("paths", {}).items():
                        flow = cls.classify_endpoint(path)
                        if flow and isinstance(path_obj, dict):
                            for method, op in path_obj.items():
                                if method.upper() in ("GET", "POST", "PUT", "DELETE"):
                                    params = [p.get("name") for p in op.get("parameters", []) if "name" in p]
                                    discovered_steps.append(
                                        AuthenticationStep(
                                            step_id=f"step_api_{len(discovered_steps)+1}",
                                            flow_type=flow,
                                            method=method.upper(),
                                            endpoint=path,
                                            parameter_names=params,
                                            request_source="OPENAPI_SPEC",
                                            response_indicators=[],
                                        )
                                    )
            except Exception:
                pass

        return discovered_steps
