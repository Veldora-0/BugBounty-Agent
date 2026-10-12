"""
Security Validation & Vulnerability Analysis Engine for BugBounty-Agent.

Transforms recon, webapp, JS, and API intelligence into controlled, hypothesis-driven
security test cases and structured findings with empirical baseline comparison,
cryptographic evidence capture, strict scope enforcement, and zero destructive exploitation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
import re
import ssl
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse, urlunparse

from framework.common.evidence import EvidenceStore, sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.scope.engine import ScopeDecision, ScopeEngine, ScopeStatus
from framework.validation.baseline import BaselineComparison, BaselineObservation, compare_with_baseline
from framework.validation.model import RiskLevel, SecurityTestCase, ValidationResult, VulnerabilityFamily
from framework.validation.payload import PayloadRegistry
from framework.validation.policy import PolicyViolationError, SecurityTestPolicy
from framework.validation.request import ControlledRequest, ControlledResponse, RequestBuilder
from framework.validation.state import SecurityStateManager
from framework.validation.validator import (
    BaseValidator,
    OpenRedirectValidator,
    ReflectedXSSValidator,
    SqlInjectionValidator,
    SsrfValidator,
    CommandInjectionValidator,
    PathTraversalValidator,
    AuthorizationValidator,
)


import socket
import urllib.request
import urllib.error

from framework.common.transport import (
    PinnedHTTPConnection,
    PinnedHTTPSConnection,
    PinnedHTTPHandler,
    PinnedHTTPSHandler,
)


# Comprehensive IP ranges for SSRF prevention
PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # Carrier-grade NAT
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),   # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"), # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),    # Multicast
    ipaddress.ip_network("240.0.0.0/4"),    # Reserved
    ipaddress.ip_network("::1/128"),        # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),       # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),      # IPv6 link-local
]


def is_ssrf_prohibited_ip(ip_input: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address belongs to private, loopback, link-local,
    reserved, or IPv4-mapped private address space.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_input) if isinstance(ip_input, str) else ip_input
    except ValueError:
        return False, ""

    # Check IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        mapped = ip_obj.ipv4_mapped
        is_bad, reason = is_ssrf_prohibited_ip(mapped)
        if is_bad:
            return True, f"IPv4-mapped {mapped} is prohibited ({reason})"

    if ip_obj.is_loopback:
        return True, "Loopback address range"
    if ip_obj.is_private:
        return True, "Private address range"
    if ip_obj.is_link_local:
        return True, "Link-local address range"
    if ip_obj.is_reserved:
        return True, "Reserved address range"
    if ip_obj.is_multicast:
        return True, "Multicast address range"

    for net in PRIVATE_NETWORKS:
        if ip_obj in net:
            return True, f"Matched forbidden network {net}"

    return False, ""


class ScopeViolationError(ValueError):
    """Raised when a request target falls outside authorized scope."""
    pass


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    HTTP redirect handler that enforces scope, anti-SSRF policies, protocol downgrade prevention,
    and destination-IP pinning on each redirection hop.
    """

    def __init__(
        self,
        check_scope_fn: Callable[[str], Any],
        ip_map: Optional[Dict[str, Any]] = None,
        max_redirects: int = 5,
        original_url: Optional[str] = None,
    ):
        super().__init__()
        self.check_scope_fn = check_scope_fn
        self.ip_map = ip_map if ip_map is not None else {}
        self.max_redirects = max_redirects
        self.redirect_count = 0
        self.current_url = original_url

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        if self.redirect_count > self.max_redirects:
            raise ScopeViolationError(f"Too many redirects (exceeded maximum of {self.max_redirects})")

        # Validate URL input
        if not newurl or not isinstance(newurl, str):
            raise ScopeViolationError(f"Invalid redirect target URL: {newurl}")

        parsed_new = urlparse(newurl)
        new_scheme = (parsed_new.scheme or "").lower()
        if new_scheme not in ("http", "https"):
            raise ScopeViolationError(f"Redirect to unsupported scheme: {new_scheme}")

        # Determine original scheme for protocol downgrade verification
        orig_url = None
        if req is not None:
            if hasattr(req, "get_full_url"):
                orig_url = req.get_full_url()
            elif isinstance(req, str):
                orig_url = req
            else:
                raise ScopeViolationError(f"Unexpected request object type in redirect handler: {type(req).__name__}")
        elif self.current_url:
            orig_url = self.current_url

        if not orig_url:
            raise ScopeViolationError("Missing request context in redirect handler: protocol downgrade cannot be verified")

        orig_scheme = urlparse(orig_url).scheme.lower()
        if orig_scheme == "https" and new_scheme == "http":
            raise ScopeViolationError("Protocol downgrade from HTTPS to HTTP forbidden")

        # Revalidate redirect destination against scope and anti-SSRF rules; obtain pinned IP(s)
        pinned = self.check_scope_fn(newurl)
        new_host = (parsed_new.hostname or "").lower()
        if new_host and pinned:
            self.ip_map[new_host] = pinned

        # Track current URL for subsequent redirect hops
        self.current_url = newurl

        if req is None or isinstance(req, str):
            return urllib.request.Request(newurl)

        return super().redirect_request(req, fp, code, msg, headers, newurl)


class SecurityValidationEngine:
    """
    Primary orchestrator for security test case generation, baseline comparison,
    and safe non-destructive validation execution.
    """

    def __init__(
        self,
        program_dir: str,
        scope_engine: Optional[ScopeEngine] = None,
        policy: Optional[SecurityTestPolicy] = None,
        send_request_hook: Optional[Callable[[ControlledRequest], ControlledResponse]] = None,
        custom_ssl_context: Optional[ssl.SSLContext] = None,
    ):
        self.program_dir = os.path.abspath(program_dir)
        self.scope_engine = scope_engine
        self.policy = policy or SecurityTestPolicy()
        self.send_request_hook = send_request_hook
        self.custom_ssl_context = custom_ssl_context
        self.allowed_fixture_ports: set[int] = set()

        self.state_mgr = SecurityStateManager(self.program_dir)
        self.evidence_dir = os.path.join(self.program_dir, "evidence")
        self.evidence_store = EvidenceStore(self.evidence_dir)

        # Total active requests issued during this engine lifecycle
        self.request_count = 0
        self.endpoint_request_counts: Dict[str, int] = {}

        # Register standard validators
        self.validators: Dict[str, BaseValidator] = {
            "reflected-xss": ReflectedXSSValidator(),
            "open-redirect": OpenRedirectValidator(),
            "sql-injection": SqlInjectionValidator(),
            "ssrf": SsrfValidator(),
            "command-injection": CommandInjectionValidator(),
            "path-traversal": PathTraversalValidator(),
            "authorization": AuthorizationValidator(),
        }

    def allow_fixture_port(self, port: int) -> None:
        """Registers an ephemeral port for a local test fixture application during testing."""
        if not isinstance(port, int) or port < 1024 or port > 65535:
            raise ValueError(f"Invalid fixture port {port}: must be an unprivileged port (1024-65535)")
        self.allowed_fixture_ports.add(port)

    # ---------------- Scope & URL Validation ----------------

    def resolve_scope_ips(self, target_url: str) -> List[str]:
        """
        Validates target URL against scope rules and anti-SSRF network boundaries.
        Resolves destination IPs, verifies none are in prohibited networks, and returns
        the verified candidate IPs in order for destination pinning and bounded fallback.
        Raises ScopeViolationError if target is unauthorized or forbidden.
        """
        parsed = urlparse(target_url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ScopeViolationError(f"Protocol '{scheme}' is forbidden. Only HTTP/HTTPS permitted.")

        host = (parsed.hostname or "").lower()
        if not host:
            raise ScopeViolationError(f"Target URL has no valid hostname: {target_url}")

        port = parsed.port or (443 if scheme == "https" else 80)

        # Check if target is an explicitly allowed local test fixture
        is_fixture = (host in ("127.0.0.1", "localhost") and port in self.allowed_fixture_ports)
        if is_fixture:
            return ["127.0.0.1"]

        # Scope authorization enforcement: fail-closed if no ScopeEngine configured
        if not is_fixture and self.scope_engine is None:
            raise ScopeViolationError(
                "Active validation requires a valid, initialized ScopeEngine. No scope engine configured."
            )

        # Direct name checks and metadata hosts
        metadata_hosts = {
            "localhost",
            "metadata.google.internal",
            "instance-data",
            "169.254.169.254",
            "169.254.169.123",
        }
        if host in metadata_hosts or host.endswith(".metadata.google.internal"):
            raise ScopeViolationError(f"Target host '{host}' is forbidden.")

        # SSRF boundary check: evaluate if host is directly an IP
        try:
            ip_obj = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            ip_obj = None
            is_ip = False

        verified_ips: List[str] = []
        if is_ip and ip_obj is not None:
            prohibited, reason = is_ssrf_prohibited_ip(ip_obj)
            if prohibited:
                raise ScopeViolationError(
                    f"Target host '{host}' is in prohibited address space ({reason}). Blocked by safe policy."
                )
            verified_ips = [str(ip_obj)]
        else:
            # host is a domain name - pre-resolve destination IP to pin connection
            try:
                addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                candidate_ips: List[str] = []
                for _, _, _, _, sa in addr_info:
                    c_ip = sa[0]
                    if c_ip not in candidate_ips:
                        candidate_ips.append(c_ip)

                for c_ip in candidate_ips:
                    try:
                        resolved_ip = ipaddress.ip_address(c_ip)
                        prohibited, reason = is_ssrf_prohibited_ip(resolved_ip)
                        if prohibited:
                            raise ScopeViolationError(
                                f"Target host '{host}' resolves to prohibited address {c_ip} ({reason}). Blocked by safe policy."
                            )
                        verified_ips.append(c_ip)
                    except ValueError:
                        pass
            except ScopeViolationError:
                raise
            except (socket.gaierror, OSError):
                # Host may be unresolvable in offline test environments or offline scope checks
                verified_ips = []

        # Evaluate against ScopeEngine
        if self.scope_engine:
            decision = self.scope_engine.check(target_url)
            if decision.status != ScopeStatus.IN_SCOPE:
                raise ScopeViolationError(
                    f"Target '{target_url}' is OUT_OF_SCOPE: {decision.reason} (matched rule: {decision.matched_rule})"
                )

        return verified_ips

    def check_request_scope(self, target_url: str) -> str:
        """
        Validates target URL against scope rules and anti-SSRF network boundaries.
        Returns the primary verified destination IP (or first candidate IP) for destination pinning.
        Raises ScopeViolationError if target is unauthorized or forbidden.
        """
        ips = self.resolve_scope_ips(target_url)
        return ips[0] if ips else ""

    # ---------------- HTTP Request Dispatcher ----------------

    def send_request(self, request: ControlledRequest) -> ControlledResponse:
        """
        Dispatches a controlled HTTP request with strict budget, timeout, and response bounds.
        Reuses send_request_hook when present for deterministic offline test fixtures.
        """
        eff_url = request.build_effective_url()

        # Fail-closed scope check for active requests
        parsed_eff = urlparse(eff_url)
        eff_host = (parsed_eff.hostname or "").lower()
        eff_port = parsed_eff.port or (443 if parsed_eff.scheme.lower() == "https" else 80)
        is_fixture = (eff_host in ("127.0.0.1", "localhost") and eff_port in self.allowed_fixture_ports)
        if self.send_request_hook is None and self.scope_engine is None and not is_fixture:
            raise ScopeViolationError(
                "Active validation requires a valid, initialized ScopeEngine. No scope engine configured."
            )

        # 1. Scope boundary verification & destination-IP pinning resolution
        pinned_ips = self.resolve_scope_ips(eff_url)
        pinned_ip = pinned_ips[0] if pinned_ips else ""

        # 2. Safety policy checks
        payload_bytes = request.build_body_bytes()
        payload_size = len(payload_bytes) if payload_bytes else 0
        self.policy.validate_request_safety(
            method=request.method,
            url_or_path=eff_url,
            payload_size=payload_size,
        )

        # 3. Budget enforcement
        if self.request_count >= self.policy.max_requests_per_program:
            raise PolicyViolationError(
                f"Program request budget exhausted ({self.request_count}/{self.policy.max_requests_per_program})."
            )

        ep_key = f"{request.method} {urlparse(eff_url).path}"
        ep_count = self.endpoint_request_counts.get(ep_key, 0)
        if ep_count >= self.policy.max_requests_per_endpoint:
            raise PolicyViolationError(
                f"Endpoint request budget exhausted for '{ep_key}' ({ep_count}/{self.policy.max_requests_per_endpoint})."
            )

        # 4. Mock hook check (for tests)
        if self.send_request_hook:
            self.request_count += 1
            self.endpoint_request_counts[ep_key] = ep_count + 1
            return self.send_request_hook(request)

        # 5. Live standard library urllib execution with strict TLS & destination-IP pinning
        parsed_eff = urlparse(eff_url)
        eff_host = (parsed_eff.hostname or "").lower()
        eff_port = parsed_eff.port or (443 if parsed_eff.scheme == "https" else 80)
        eff_scheme = parsed_eff.scheme.lower()
        is_fixture = (eff_host in ("127.0.0.1", "localhost") and eff_port in self.allowed_fixture_ports)
        if not is_fixture and not pinned_ips:
            raise ScopeViolationError(f"DNS resolution failed for '{eff_host}': destination IP could not be pinned.")

        ip_map: Dict[str, Any] = {eff_host: pinned_ips} if pinned_ips else {}

        headers = request.build_effective_headers()
        host_hdr = f"{eff_host}:{eff_port}" if (eff_scheme == "http" and eff_port != 80) or (eff_scheme == "https" and eff_port != 443) else eff_host
        if "Host" not in headers and "host" not in headers:
            headers["Host"] = host_hdr

        req_obj = urllib.request.Request(
            eff_url,
            data=payload_bytes,
            headers=headers,
            method=request.method,
        )

        ctx: Optional[ssl.SSLContext] = None
        if eff_scheme == "https":
            if self.custom_ssl_context:
                ctx = self.custom_ssl_context
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED
                ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get("REQUESTS_CA_BUNDLE")
                if ca_bundle and os.path.isfile(ca_bundle):
                    ctx.load_verify_locations(cafile=ca_bundle)

        redirect_handler = SafeRedirectHandler(
            self.resolve_scope_ips,
            ip_map=ip_map,
            max_redirects=getattr(self.policy, "max_redirects", 5),
            original_url=eff_url,
        )
        http_handler = PinnedHTTPHandler(ip_map=ip_map)
        https_handler = PinnedHTTPSHandler(ip_map=ip_map, context=ctx, check_hostname=True if ctx else None)
        opener = urllib.request.build_opener(redirect_handler, http_handler, https_handler)

        # Optional delay
        if self.policy.delay_seconds > 0:
            time.sleep(self.policy.delay_seconds)

        start_time = time.time()
        self.request_count += 1
        self.endpoint_request_counts[ep_key] = ep_count + 1

        try:
            with opener.open(req_obj, timeout=self.policy.timeout) as resp:
                elapsed = time.time() - start_time
                status = resp.status
                resp_headers = dict(resp.headers)
                raw_body = resp.read(self.policy.max_response_bytes)
                body_text = raw_body.decode("utf-8", errors="replace")
                final_url = resp.geturl()
                return ControlledResponse(
                    status_code=status,
                    headers=resp_headers,
                    body=body_text,
                    size_bytes=len(raw_body),
                    elapsed_seconds=elapsed,
                    final_url=final_url,
                )
        except ScopeViolationError:
            raise
        except PolicyViolationError:
            raise
        except urllib.error.HTTPError as e:
            elapsed = time.time() - start_time
            raw_body = e.read(self.policy.max_response_bytes)
            body_text = raw_body.decode("utf-8", errors="replace")
            resp_headers = dict(e.headers)
            return ControlledResponse(
                status_code=e.code,
                headers=resp_headers,
                body=body_text,
                size_bytes=len(raw_body),
                elapsed_seconds=elapsed,
                final_url=eff_url,
            )
        except Exception as e:
            elapsed = time.time() - start_time
            return ControlledResponse(
                status_code=0,
                headers={},
                body=f"Connection Error: {str(e)}",
                size_bytes=0,
                elapsed_seconds=elapsed,
                final_url=eff_url,
            )

    # ---------------- Validation Execution Pipeline ----------------

    def execute_test_case(
        self,
        test_case: SecurityTestCase,
        validator: BaseValidator,
        baseline: Optional[BaselineObservation] = None,
        dry_run: bool = False,
    ) -> Tuple[ValidationResult, Optional[Finding]]:
        """
        Executes a single controlled security test case against an endpoint.
        Returns (ValidationResult, Optional[Finding]).
        """
        if dry_run:
            result = ValidationResult(
                test_id=test_case.test_id,
                lifecycle_state=FindingLifecycle.TESTING,
                signals_observed=["DRY_RUN_PLAN"],
                evidence_summary=f"Dry run plan: would execute {validator.validator_id} mutation on {test_case.endpoint}",
            )
            return result, None

        # Resolve full URL for request construction
        if "://" in test_case.endpoint:
            full_url = test_case.endpoint
        else:
            base_t = test_case.target if "://" in test_case.target else f"https://{test_case.target}"
            full_url = base_t.rstrip("/") + "/" + test_case.endpoint.lstrip("/")

        # Build baseline if not already provided
        ep_key = f"{test_case.method} {test_case.endpoint}"
        if not baseline:
            baseline = self.state_mgr.get_baseline(ep_key)
            if not baseline:
                base_req = RequestBuilder(full_url, test_case.method).build_baseline()
                base_resp = self.send_request(base_req)
                baseline = BaselineObservation.from_response(ep_key, base_resp)
                self.state_mgr.save_baseline(baseline)

        # Obtain payload definition
        payload_def = PayloadRegistry.get_payload(test_case.payload_identifier)
        test_value = payload_def.generate_value() if payload_def else "TEST_MARKER"

        # Construct mutated request
        builder = RequestBuilder(full_url, test_case.method)
        if test_case.parameter:
            mut_req = builder.mutate_query_param(test_case.parameter, test_value)
        else:
            mut_req = builder.build_baseline()

        # Send mutated request
        mut_resp = self.send_request(mut_req)

        # Baseline comparison
        comparison = compare_with_baseline(baseline, mut_resp, test_marker=test_value)

        # Validator analysis
        val_result, candidate_finding = validator.analyze(
            comparison=comparison,
            baseline=baseline,
            response=mut_resp,
            test_case=test_case,
        )

        # Evidence preservation if finding observed or candidate
        if candidate_finding or val_result.lifecycle_state in (FindingLifecycle.OBSERVED, FindingLifecycle.VALIDATED):
            req_text = mut_req.get_sanitized_representation()
            res_text = mut_resp.get_sanitized_representation()
            evid_meta = self.evidence_store.save_http_capture(
                request_text=req_text,
                response_text=res_text,
                metadata={
                    "test_id": test_case.test_id,
                    "target": test_case.target,
                    "endpoint": test_case.endpoint,
                    "parameter": test_case.parameter,
                    "validator": validator.validator_id,
                    "signals": val_result.signals_observed,
                },
                prefix=f"val_{validator.validator_id}",
            )
            val_result.evidence_reference = evid_meta.get("evidence_id")
            self.state_mgr.record_evidence_reference(evid_meta)

            if candidate_finding:
                candidate_finding.add_evidence(
                    evidence_type="HTTP_TRANSACTION",
                    content=res_text[:self.policy.max_evidence_size],
                    metadata={"evidence_id": evid_meta.get("evidence_id"), "sha256": evid_meta.get("sha256")},
                )

        return val_result, candidate_finding

    # ---------------- Passive Mode & Intake ----------------

    def passive_intake(self) -> List[SecurityTestCase]:
        """
        Discovers test candidate endpoints and parameters strictly offline from existing state
        (webapps.json, api.json, javascript.json, recon.json) with zero network traffic.
        """
        test_cases: List[SecurityTestCase] = []

        # 1. Ingest WebApp state
        webapps_file = os.path.join(self.program_dir, "state", "webapps.json")
        if os.path.exists(webapps_file):
            try:
                with open(webapps_file, "r", encoding="utf-8") as f:
                    wdata = json.load(f)
                ep_raw = wdata.get("endpoints", [])
                if isinstance(ep_raw, dict):
                    ep_list = list(ep_raw.values())
                else:
                    ep_list = list(ep_raw)
                for ep in ep_list:
                    url = ep.get("url", "")
                    method = ep.get("method", "GET").upper()
                    target = ep.get("app_id", "").replace("app:", "")
                    if not target and "://" in url:
                        target = urlparse(url).netloc
                    parsed = urlparse(url)
                    path = parsed.path or "/"

                    # Extract query parameters
                    q_params = [k for k, _ in parse_qsl(parsed.query)]
                    for q in q_params:
                        for val_id, val in self.validators.items():
                            if val.is_available and val.can_test(path, q):
                                cases = val.prepare_test_cases(
                                    target=target,
                                    endpoint=path,
                                    parameter=q,
                                    provenance={"source": "webapp_state", "url": url},
                                )
                                test_cases.extend(cases)
            except Exception:
                pass

        # 2. Ingest API state
        api_file = os.path.join(self.program_dir, "state", "api.json")
        if os.path.exists(api_file):
            try:
                from framework.api.state import ApiStateManager
                asm = ApiStateManager(self.program_dir)
                for ep in asm.get_endpoints():
                    path = ep.path
                    method = ep.method.upper()
                    target = ep.app_id.replace("api:", "")
                    for param in ep.parameters:
                        for val_id, val in self.validators.items():
                            if val.is_available and val.can_test(path, param.name):
                                cases = val.prepare_test_cases(
                                    target=target,
                                    endpoint=path,
                                    parameter=param.name,
                                    provenance={"source": "api_state", "role": param.role.value if param.role else "GENERIC"},
                                )
                                test_cases.extend(cases)
            except Exception:
                pass

        # Deduplicate generated test cases by fingerprint
        seen_fps: Set[str] = set()
        deduped: List[SecurityTestCase] = []
        for tc in test_cases:
            fp = tc.compute_fingerprint()
            if fp not in seen_fps:
                seen_fps.add(fp)
                deduped.append(tc)

        return deduped

    # ---------------- Orchestrated Run Entrypoint ----------------

    def run_validation(
        self,
        domain: Optional[str] = None,
        asset: Optional[str] = None,
        endpoint: Optional[str] = None,
        parameter: Optional[str] = None,
        category: Optional[str] = None,
        validator_name: Optional[str] = None,
        max_tests: int = 50,
        passive_only: bool = False,
        dry_run: bool = False,
        resume: bool = False,
    ) -> Dict[str, Any]:
        """
        Executes security validation pipeline based on options and boundaries.
        Returns execution summary dictionary.
        """
        # Resolve target
        target = asset or domain or "localhost"
        if "://" not in target and target != "localhost":
            target = f"https://{target}"

        # 1. Passive intake or manual test case generation
        candidate_tests: List[SecurityTestCase] = []
        if endpoint:
            # If endpoint is a full URL, extract target and path
            if "://" in endpoint:
                parsed_ep = urlparse(endpoint)
                resolved_target = f"{parsed_ep.scheme}://{parsed_ep.netloc}"
                resolved_endpoint = parsed_ep.path or "/"
                if not parameter and parsed_ep.query:
                    qs = parse_qsl(parsed_ep.query)
                    if qs:
                        parameter = qs[0][0]
            else:
                resolved_target = target
                resolved_endpoint = endpoint

            # Targeted test on specified endpoint
            chosen_validators = []
            if validator_name and validator_name in self.validators:
                chosen_validators.append(self.validators[validator_name])
            else:
                chosen_validators = [v for v in self.validators.values() if v.is_available]

            for val in chosen_validators:
                if val.can_test(resolved_endpoint, parameter):
                    cases = val.prepare_test_cases(
                        target=resolved_target,
                        endpoint=resolved_endpoint,
                        parameter=parameter,
                        provenance={"source": "cli_targeted"},
                    )
                    candidate_tests.extend(cases)
        else:
            # Discover candidate test cases from program intelligence state
            candidate_tests = self.passive_intake()

        # Filter by category if specified
        if category:
            cat_upper = category.strip().upper()
            candidate_tests = [c for c in candidate_tests if c.vulnerability_family.value == cat_upper]

        # Filter by validator if specified
        if validator_name:
            val_obj = self.validators.get(validator_name)
            if val_obj:
                fam = val_obj.vulnerability_family.value
                candidate_tests = [c for c in candidate_tests if c.vulnerability_family.value == fam]

        # Bound total test cases
        candidate_tests = candidate_tests[:max_tests]

        # If passive-only: persist discovered test cases and return summary
        if passive_only:
            for tc in candidate_tests:
                if not dry_run:
                    self.state_mgr.save_test_case(tc)
            return {
                "mode": "passive_only",
                "test_cases_identified": len(candidate_tests),
                "tests": [t.to_dict() for t in candidate_tests],
                "active_requests_sent": 0,
            }

        # Execution loop
        executed_count = 0
        skipped_resume = 0
        findings_created = []

        for tc in candidate_tests:
            fp = tc.compute_fingerprint()

            # Resume check
            if resume and self.state_mgr.is_test_completed(fp):
                skipped_resume += 1
                continue

            # Identify validator
            matching_vals = [v for v in self.validators.values() if v.vulnerability_family == tc.vulnerability_family]
            if not matching_vals:
                continue
            val = matching_vals[0]

            if not val.is_available:
                continue

            # Execute test
            try:
                res, finding = self.execute_test_case(tc, val, dry_run=dry_run)
                executed_count += 1

                if not dry_run:
                    self.state_mgr.save_test_case(tc)
                    self.state_mgr.save_validation_result(res, fp)

                    if finding:
                        saved_f, is_dup, dup_id = self.state_mgr.save_finding(finding)
                        findings_created.append(saved_f.to_dict())

            except (PolicyViolationError, ScopeViolationError) as e:
                # Recorded safety violation
                if not dry_run:
                    err_res = ValidationResult(
                        test_id=tc.test_id,
                        lifecycle_state=FindingLifecycle.REJECTED,
                        signals_observed=["POLICY_OR_SCOPE_BLOCKED"],
                        evidence_summary=str(e),
                    )
                    self.state_mgr.save_validation_result(err_res, fp)

        return {
            "mode": "dry_run" if dry_run else "active_validation",
            "tests_considered": len(candidate_tests),
            "tests_executed": executed_count,
            "tests_skipped_resume": skipped_resume,
            "findings_recorded": len(findings_created),
            "findings": findings_created,
            "active_requests_sent": self.request_count,
            "state_summary": self.state_mgr.get_state_summary(),
        }
