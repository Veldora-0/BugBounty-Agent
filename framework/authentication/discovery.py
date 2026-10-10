"""
Authentication Surface Discovery Engine for BugBounty-Agent (Phase 14.1).

Discovers authentication endpoints, forms, API schemes, and session management surfaces
by consuming real serialized intelligence from previous phases:
- state/webapps.json (Phase 3)
- state/javascript.json (Phase 4)
- state/api.json (Phase 5)
- state/assets.json (Phase 1)
- state/recon.json (Phase 2)
- state/authorization.json (Phase 8)
- state/workflows.json (Phase 12)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from framework.authentication.models import (
    AuthenticationFlow,
    AuthenticationFlowType,
    AuthenticationStep,
    AuthenticationTransition,
)


class AuthenticationSurfaceDiscoverer:
    """Discovers and catalogs authentication endpoints across web, API, and client surfaces."""

    # Deterministic indicators for flow classification
    FLOW_PATTERNS = {
        AuthenticationFlowType.LOGIN: [
            r"/login", r"/signin", r"/auth/login", r"/api/v\d+/login",
            r"/authenticate", r"/oauth/token", r"/api/v\d+/auth/token",
            r"/auth/token", r"/session/new", r"/sessions",
            r"/dashboard", r"/portal", r"/account", r"/profile", r"/admin",
            r"/user", r"/settings", r"/sso", r"/do-login", r"login",
        ],
        AuthenticationFlowType.LOGOUT: [
            r"/logout", r"/signout", r"/auth/logout", r"/api/v\d+/logout",
            r"/session/delete", r"/invalidate",
        ],
        AuthenticationFlowType.PASSWORD_CHANGE: [
            r"/password/change", r"/account/password", r"/change-password",
            r"/api/v\d+/password/change", r"/user/password",
        ],
        AuthenticationFlowType.PASSWORD_RESET: [
            r"/password/reset", r"/forgot-password", r"/reset-password",
            r"/api/v\d+/password/reset", r"/account/recovery", r"/recover",
        ],
        AuthenticationFlowType.MFA_VERIFICATION: [
            r"/mfa", r"/2fa", r"/otp", r"/verify-mfa", r"/two-factor",
            r"/api/v\d+/mfa/verify", r"/totp/verify", r"/mfa/challenge",
        ],
        AuthenticationFlowType.TOKEN_REFRESH: [
            r"/token/refresh", r"/auth/refresh", r"/refresh-token",
            r"/api/v\d+/auth/refresh", r"/oauth/refresh",
        ],
    }

    @classmethod
    def classify_endpoint(cls, endpoint: str) -> Optional[AuthenticationFlowType]:
        """Classifies a URL path into an authentication flow type based on deterministic heuristics."""
        if not endpoint:
            return None
        clean_path = endpoint.lower().split("?")[0]
        for flow_type, patterns in cls.FLOW_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, clean_path):
                    return flow_type
        return None

    @classmethod
    def _read_json_safe(cls, filepath: str) -> Optional[Dict[str, Any]]:
        """Safely reads a JSON file; returns None if missing or corrupted."""
        if not os.path.isfile(filepath):
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, (dict, list)) else None
        except (json.JSONDecodeError, OSError):
            return None

    @classmethod
    def discover_from_webapps(cls, program_dir: str) -> List[AuthenticationStep]:
        """
        Ingests real serialized state from state/webapps.json (or web_applications.json).
        Schema: 'endpoints' (list of dicts/strings), 'forms' (list of dicts), 'cookies' (list of dicts).
        """
        discovered: List[AuthenticationStep] = []
        filepath = os.path.join(program_dir, "state", "webapps.json")
        if not os.path.isfile(filepath):
            filepath = os.path.join(program_dir, "state", "web_applications.json")
        if not os.path.isfile(filepath):
            filepath = os.path.join(program_dir, "webapps.json")
        if not os.path.isfile(filepath):
            filepath = os.path.join(program_dir, "web_applications.json")

        raw_data = cls._read_json_safe(filepath)
        if not raw_data:
            return discovered

        data_items = raw_data if isinstance(raw_data, list) else ([raw_data] if isinstance(raw_data, dict) else [])

        for data in data_items:
            if not isinstance(data, dict):
                continue

            # 1. Forms
            for form in data.get("forms", []):
                if not isinstance(form, dict):
                    continue
                action = form.get("action") or form.get("target_url") or ""
                method = form.get("method", "POST").upper()
                fields = form.get("fields", [])
                field_names = [f.get("name") for f in fields if isinstance(f, dict) and "name" in f]
                if not field_names and isinstance(form.get("inputs"), dict):
                    field_names = list(form["inputs"].keys())

                flow = cls.classify_endpoint(action)
                # Check fields for password/username
                if not flow:
                    lower_fields = [fn.lower() for fn in field_names if fn]
                    if any("pass" in fn or "pwd" in fn for fn in lower_fields):
                        flow = AuthenticationFlowType.LOGIN

                if flow and action:
                    discovered.append(
                        AuthenticationStep(
                            step_id=f"step_web_form_{len(discovered)+1}",
                            flow_type=flow,
                            method=method,
                            endpoint=action,
                            parameter_names=field_names,
                            request_source="WEB_FORM",
                            response_indicators=[],
                        )
                    )

            # 2. Endpoints
            for ep in data.get("endpoints", []):
                if isinstance(ep, str):
                    url = ep
                    method = "GET"
                elif isinstance(ep, dict):
                    url = ep.get("url") or ep.get("path") or ""
                    method = ep.get("method", "GET").upper()
                else:
                    continue

                flow = cls.classify_endpoint(url)
                if flow and url:
                    discovered.append(
                        AuthenticationStep(
                            step_id=f"step_web_ep_{len(discovered)+1}",
                            flow_type=flow,
                            method=method,
                            endpoint=url,
                            parameter_names=[],
                            request_source="WEB_ENDPOINT",
                            response_indicators=[],
                        )
                    )

        return discovered

    @classmethod
    def discover_from_api(cls, program_dir: str) -> List[AuthenticationStep]:
        """
        Ingests real serialized state from state/api.json.
        Schema: 'endpoints' (list of dicts), 'parameters' (list of dicts),
                'auth_observations' (list of dicts), 'specifications' (list of dicts).
        """
        discovered: List[AuthenticationStep] = []
        filepath = os.path.join(program_dir, "state", "api.json")
        if not os.path.isfile(filepath):
            filepath = os.path.join(program_dir, "api.json")

        raw_data = cls._read_json_safe(filepath)
        if not raw_data:
            return discovered

        data_items = raw_data if isinstance(raw_data, list) else ([raw_data] if isinstance(raw_data, dict) else [])

        for data in data_items:
            if not isinstance(data, dict):
                continue

            # 1. API Endpoints
            for ep in data.get("endpoints", []):
                if isinstance(ep, str):
                    path = ep
                    method = "GET"
                    params = []
                elif isinstance(ep, dict):
                    path = ep.get("path") or ep.get("url") or ""
                    method = ep.get("method", "GET").upper()
                    params = [p.get("name") for p in ep.get("parameters", []) if isinstance(p, dict) and "name" in p]
                else:
                    continue

                flow = cls.classify_endpoint(path)
                if flow and path:
                    discovered.append(
                        AuthenticationStep(
                            step_id=f"step_api_{len(discovered)+1}",
                            flow_type=flow,
                            method=method,
                            endpoint=path,
                            parameter_names=params,
                            request_source="API_ENDPOINT",
                            response_indicators=[],
                        )
                    )

            # 2. API Authentication Observations
            for auth_obs in data.get("auth_observations", []):
                if not isinstance(auth_obs, dict):
                    continue
                ep_url = auth_obs.get("endpoint_url") or ""
                flow = cls.classify_endpoint(ep_url) or AuthenticationFlowType.LOGIN
                if ep_url:
                    discovered.append(
                        AuthenticationStep(
                            step_id=f"step_api_auth_{len(discovered)+1}",
                            flow_type=flow,
                            method="POST",
                            endpoint=ep_url,
                            parameter_names=[auth_obs.get("header_name", "Authorization")],
                            request_source="API_AUTH_OBSERVATION",
                            response_indicators=[auth_obs.get("auth_type", "BEARER")],
                        )
                    )

        return discovered

    @classmethod
    def discover_from_javascript(cls, program_dir: str) -> List[AuthenticationStep]:
        """
        Ingests real serialized state from state/javascript.json.
        Schema: 'routes' (list of dicts), 'endpoints' (list of dicts), 'interesting_strings' (list of dicts).
        """
        discovered: List[AuthenticationStep] = []
        filepath = os.path.join(program_dir, "state", "javascript.json")
        if not os.path.isfile(filepath):
            filepath = os.path.join(program_dir, "javascript.json")

        raw_data = cls._read_json_safe(filepath)
        if not raw_data:
            return discovered

        data_items = raw_data if isinstance(raw_data, list) else ([raw_data] if isinstance(raw_data, dict) else [])

        for data in data_items:
            if not isinstance(data, dict):
                continue

            # 1. Client-side routes
            for route in data.get("routes", []):
                path = route.get("path", "") if isinstance(route, dict) else str(route)
                flow = cls.classify_endpoint(path)
                if flow and path:
                    discovered.append(
                        AuthenticationStep(
                            step_id=f"step_js_route_{len(discovered)+1}",
                            flow_type=flow,
                            method="GET",
                            endpoint=path,
                            parameter_names=[],
                            request_source="JS_ROUTE",
                            response_indicators=[],
                        )
                    )

            # 2. Endpoints found in JS
            for ep in data.get("endpoints", []):
                path = ep.get("path") or ep.get("url") or "" if isinstance(ep, dict) else str(ep)
                flow = cls.classify_endpoint(path)
                if flow and path:
                    discovered.append(
                        AuthenticationStep(
                            step_id=f"step_js_ep_{len(discovered)+1}",
                            flow_type=flow,
                            method="POST" if flow != AuthenticationFlowType.LOGOUT else "GET",
                            endpoint=path,
                            parameter_names=[],
                            request_source="JS_ENDPOINT",
                            response_indicators=[],
                        )
                    )

        return discovered

    @classmethod
    def discover_from_assets_recon(cls, program_dir: str) -> List[str]:
        """
        Ingests authentication-relevant hostnames and TLS SANs from state/assets.json and state/recon.json.
        """
        auth_hosts: Set[str] = set()

        # 1. assets.json (both graph format and legacy map format)
        assets_path = os.path.join(program_dir, "state", "assets.json")
        if not os.path.isfile(assets_path):
            assets_path = os.path.join(program_dir, "assets.json")

        assets_data = cls._read_json_safe(assets_path)
        if isinstance(assets_data, dict):
            asset_dict = assets_data.get("assets", {}) if "assets" in assets_data and isinstance(assets_data["assets"], dict) else assets_data
            for key, val in asset_dict.items():
                host = ""
                if isinstance(val, dict):
                    host = val.get("hostname") or val.get("normalized") or val.get("value") or ""
                    for s in val.get("http_services", []):
                        u = s.get("url") if isinstance(s, dict) else str(s)
                        if u and any(p in u.lower() for p in ("auth.", "sso.", "login.", "id.", "accounts.")):
                            auth_hosts.add(u)
                elif isinstance(val, str):
                    host = val
                clean = host.lower().strip()
                if clean and any(p in clean for p in ("auth.", "sso.", "login.", "id.", "accounts.")):
                    auth_hosts.add(clean)

        # 2. recon.json
        recon_path = os.path.join(program_dir, "state", "recon.json")
        if not os.path.isfile(recon_path):
            recon_path = os.path.join(program_dir, "recon.json")

        recon_data = cls._read_json_safe(recon_path)
        if isinstance(recon_data, dict):
            for tls in recon_data.get("tls_records", []):
                if isinstance(tls, dict):
                    sans = tls.get("subject_alt_names", []) or tls.get("san", [])
                    for san in sans:
                        san_clean = str(san).lower().strip()
                        if any(p in san_clean for p in ("auth.", "sso.", "login.", "id.", "accounts.")):
                            auth_hosts.add(san_clean)

        return sorted(list(auth_hosts))

    @classmethod
    def discover_from_authorization(cls, program_dir: str) -> List[AuthenticationStep]:
        """
        Ingests protected resources from state/authorization.json.
        Schema: 'principals' (dict of {id: dict}), 'resources' (dict of {id: dict}).
        """
        discovered: List[AuthenticationStep] = []
        filepath = os.path.join(program_dir, "state", "authorization.json")
        if not os.path.isfile(filepath):
            filepath = os.path.join(program_dir, "authorization.json")

        data = cls._read_json_safe(filepath)
        if not data or not isinstance(data, dict):
            return discovered

        resources = data.get("resources", {})
        if isinstance(resources, dict):
            for res_id, res in resources.items():
                if not isinstance(res, dict):
                    continue
                ep = res.get("endpoint") or res.get("path") or ""
                method = res.get("method", "GET").upper()
                flow = cls.classify_endpoint(ep)
                if flow and ep:
                    discovered.append(
                        AuthenticationStep(
                            step_id=f"step_authz_{len(discovered)+1}",
                            flow_type=flow,
                            method=method,
                            endpoint=ep,
                            parameter_names=[],
                            request_source="AUTHZ_RESOURCE",
                            response_indicators=[],
                        )
                    )

        return discovered

    @classmethod
    def discover_from_workflows(cls, program_dir: str) -> List[AuthenticationFlow]:
        """
        Ingests workflows and transitions from state/workflows.json.
        Schema: 'workflows' (dict of {workflow_id: dict}).
        """
        discovered_flows: List[AuthenticationFlow] = []
        filepath = os.path.join(program_dir, "state", "workflows.json")
        if not os.path.isfile(filepath):
            filepath = os.path.join(program_dir, "workflows.json")

        data = cls._read_json_safe(filepath)
        if not data or not isinstance(data, dict):
            return discovered_flows

        workflows = data.get("workflows", {})
        if isinstance(workflows, dict):
            for wf_id, wf in workflows.items():
                if not isinstance(wf, dict):
                    continue
                wf_name = wf.get("name", wf_id)
                steps_data = wf.get("steps", [])
                steps: List[AuthenticationStep] = []
                for s in steps_data:
                    if isinstance(s, dict):
                        ep = s.get("endpoint", "")
                        flow_t = cls.classify_endpoint(ep) or AuthenticationFlowType.LOGIN
                        steps.append(
                            AuthenticationStep(
                                step_id=s.get("step_id", f"step_{len(steps)+1}"),
                                flow_type=flow_t,
                                method=s.get("method", "GET").upper(),
                                endpoint=ep,
                                parameter_names=[],
                                request_source="WORKFLOW_STEP",
                            )
                        )
                if steps:
                    flow_type = cls.classify_endpoint(wf_name) or steps[0].flow_type
                    discovered_flows.append(
                        AuthenticationFlow(
                            flow_id=wf_id,
                            flow_type=flow_type,
                            steps=steps,
                            success_indicators=[wf.get("name", "")],
                        )
                    )

        return discovered_flows

    @classmethod
    def discover_all(cls, program_dir: str) -> List[AuthenticationStep]:
        """
        Runs all state loaders across phases 1, 2, 3, 4, 5, 8, 12.
        Deduplicates surfaces by (canonical endpoint, HTTP method).
        Gracefully tolerates missing, empty, or corrupted state files.
        """
        all_steps: List[AuthenticationStep] = []

        all_steps.extend(cls.discover_from_webapps(program_dir))
        all_steps.extend(cls.discover_from_api(program_dir))
        all_steps.extend(cls.discover_from_javascript(program_dir))
        all_steps.extend(cls.discover_from_authorization(program_dir))

        # Assets & Recon hosts
        for h in cls.discover_from_assets_recon(program_dir):
            ep_url = h if (h.startswith("http://") or h.startswith("https://")) else f"https://{h}"
            all_steps.append(
                AuthenticationStep(
                    step_id=f"step_recon_{len(all_steps)+1}",
                    flow_type=AuthenticationFlowType.LOGIN,
                    method="GET",
                    endpoint=ep_url,
                    parameter_names=[],
                    request_source="RECON_ASSET",
                )
            )

        # Workflow steps
        wf_flows = cls.discover_from_workflows(program_dir)
        for wf in wf_flows:
            all_steps.extend(wf.steps)

        # Deduplicate
        deduped: List[AuthenticationStep] = []
        seen: Set[str] = set()
        for step in all_steps:
            clean_endpoint = step.endpoint.strip()
            key = f"{step.method.upper()}:{clean_endpoint}"
            if key not in seen and clean_endpoint:
                seen.add(key)
                deduped.append(step)

        return deduped

    @classmethod
    def discover_from_workspace(cls, workspace_dir: str) -> List[AuthenticationStep]:
        """Backwards-compatible convenience wrapper calling discover_all."""
        return cls.discover_all(workspace_dir)
