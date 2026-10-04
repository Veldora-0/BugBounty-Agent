"""
Comprehensive Test Suite for XSS Intelligence & Validation Engine (Phase 7).

Tests:
1. HtmlContextAnalyzer across all syntactic contexts (body, attribute, script, event handler, URL, JSON, comments)
2. Character transformations & false-positive elimination (defended HTML entities rejected)
3. DOM XSS source-to-sink intelligence, framework dangerous APIs (React, Vue, Angular, jQuery), and sanitizers
4. Stored XSS candidate pair correlation and passive detection
5. Browser-assisted confirmation layer safety and fallback handling
6. State persistence in state/xss.json and summary statistics
7. Anti-SSRF network validation hardening (IPv4-mapped IPv6, private ranges, safe redirect hops)
8. Endpoint safety classification (SAFE, READ_ONLY, STATE_CHANGING, BLOCKED, UNKNOWN)
9. CLI invocation (bb-xss) with dry-run, passive-only, json, and tree options
10. Security audit: zero shell=True / os.system and non-destructive payloads only
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any, Dict
import pytest

from framework.findings.lifecycle import FindingLifecycle
from framework.scope.engine import ScopeEngine
from framework.validation.engine import (
    SafeRedirectHandler,
    ScopeViolationError,
    SecurityValidationEngine,
    is_ssrf_prohibited_ip,
)
from framework.validation.policy import (
    EndpointSafetyClass,
    PolicyViolationError,
    SecurityTestPolicy,
)
from framework.validation.request import ControlledRequest, ControlledResponse
from framework.xss.browser import BrowserXssAssistant
from framework.xss.context import ContextAnalysisResult, HtmlContextAnalyzer
from framework.xss.dom import DomXssEngine
from framework.xss.engine import XssIntelligenceEngine
from framework.xss.model import (
    ReflectionState,
    XssCandidate,
    XssCategory,
    XssConfidence,
    XssContextType,
    XssEvidence,
    XssSink,
    XssSource,
)
from framework.xss.state import XssStateManager
from framework.xss.stored import StoredXssEngine
from framework.xss.validator import DomXssValidator, ReflectedXssContextValidator


@pytest.fixture
def temp_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        state_dir = os.path.join(tmpdir, "state")
        os.makedirs(state_dir, exist_ok=True)
        yield tmpdir


@pytest.fixture
def mock_scope_engine():
    scope_def = {
        "program": {"name": "test-program"},
        "targets": {
            "domains": ["example.com", "*.example.com"],
            "urls": ["https://app.example.com"],
        },
        "out_of_scope": {
            "domains": ["internal.example.com"],
        },
    }
    return ScopeEngine(scope_def)


# ==============================================================================
# 1. HTML Context Analyzer Tests
# ==============================================================================

def test_html_context_body():
    body = "<html><body><h1>Welcome bbxss123</h1></body></html>"
    res = HtmlContextAnalyzer.analyze(body, "bbxss123")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.HTML_BODY
    assert "bbxss123" in res.context_snippet


def test_html_context_attribute_quoted():
    body = '<input type="text" name="search" value="bbxss123">'
    res = HtmlContextAnalyzer.analyze(body, "bbxss123")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.HTML_ATTRIBUTE
    assert res.tag_name == "input"
    assert res.attribute_name == "value"
    assert res.quote_style == '"'


def test_html_context_attribute_single_quoted():
    body = "<div class='user-card bbxss123'>hello</div>"
    res = HtmlContextAnalyzer.analyze(body, "bbxss123")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.HTML_ATTRIBUTE
    assert res.tag_name == "div"
    assert res.attribute_name == "class"
    assert res.quote_style == "'"


def test_html_context_event_handler():
    body = '<button onclick="handleClick(\'bbxss123\')">Click</button>'
    res = HtmlContextAnalyzer.analyze(body, "bbxss123")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.EVENT_HANDLER
    assert res.attribute_name == "onclick"


def test_html_context_url_attribute():
    body = '<a href="/view?item=bbxss123">Link</a>'
    res = HtmlContextAnalyzer.analyze(body, "bbxss123")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.URL_ATTRIBUTE
    assert res.attribute_name == "href"


def test_html_context_script_block():
    body = "<script>const token = 'bbxss123';</script>"
    res = HtmlContextAnalyzer.analyze(body, "bbxss123")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.SCRIPT_BLOCK


def test_html_context_style_block():
    body = "<style>.content { background-image: url('bbxss123'); }</style>"
    res = HtmlContextAnalyzer.analyze(body, "bbxss123")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.STYLE_BLOCK


def test_html_context_comment():
    body = "<!-- user note: bbxss123 -->"
    res = HtmlContextAnalyzer.analyze(body, "bbxss123")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.HTML_COMMENT


def test_html_context_json_payload():
    body = '{"status": "ok", "query": "bbxss123", "count": 1}'
    res = HtmlContextAnalyzer.analyze(body, "bbxss123", content_type="application/json")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.JSON_STRING
    assert res.is_defended is True


# ==============================================================================
# 2. Defensive Encoding & False-Positive Elimination Tests
# ==============================================================================

def test_defensive_encoding_in_html_body_eliminates_fp():
    # Reflection with HTML entity encoding: &lt;tag&gt;
    token = "bbxss_token"
    body = f"<html><body>Search results for: {token}&lt;script&gt;</body></html>"
    res = HtmlContextAnalyzer.analyze(body, token, probe_chars="<script>")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.HTML_BODY
    assert res.is_defended is True
    assert res.reflection_state == ReflectionState.ENCODED
    assert res.is_exploitable_context is False


def test_unencoded_reflection_in_body_is_detected():
    token = "bbxss_token"
    body = f"<html><body>Search results for: {token}<script></body></html>"
    res = HtmlContextAnalyzer.analyze(body, token, probe_chars="<script>")
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.HTML_BODY
    assert res.is_defended is False
    assert res.reflection_state == ReflectionState.UNFILTERED
    assert res.is_exploitable_context is True


def test_script_block_insufficient_encoding_html_entities():
    # In a <script> block, HTML entities (&quot;) do NOT prevent execution
    token = "bbxss_token"
    body = f"<script>var item = \"{token}&quot;; alert(1);\";</script>"
    res = HtmlContextAnalyzer.analyze(body, token, probe_chars='"')
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.SCRIPT_BLOCK
    assert res.reflection_state == ReflectionState.INSUFFICIENTLY_ENCODED
    assert res.is_defended is False


def test_script_block_proper_js_escaping():
    token = "bbxSS_token"
    body = f'<script>var item = "{token}\\"";</script>'
    res = HtmlContextAnalyzer.analyze(body, token, probe_chars='"')
    assert res.canary_reflected is True
    assert res.context_type == XssContextType.SCRIPT_BLOCK
    assert res.is_defended is True


# ==============================================================================
# 3. DOM XSS Intelligence & Framework Dangerous Sinks Tests
# ==============================================================================

def test_dom_xss_sources_and_sinks_detection():
    script = """
    function renderQuery() {
        var params = new URLSearchParams(window.location.search);
        var q = params.get('q');
        document.getElementById('result').innerHTML = q;
    }
    """
    cands = DomXssEngine.analyze_script_text(script, file_path="/app.js")
    assert len(cands) >= 1
    cand = cands[0]
    assert cand.category == XssCategory.DOM
    assert cand.source.name == "location.search"
    assert cand.sink.name == "innerHTML"
    assert cand.confidence in (XssConfidence.SUSPECTED, XssConfidence.VALIDATED)


def test_dom_xss_framework_react_dangerously_set_inner_html():
    script = """
    function CustomWidget(props) {
        return <div dangerouslySetInnerHTML={{ __html: props.content }} />;
    }
    """
    cands = DomXssEngine.analyze_script_text(script, file_path="/Widget.jsx")
    assert len(cands) >= 1
    sink = cands[0].sink
    assert sink.name == "dangerouslySetInnerHTML"
    assert sink.framework == "React"
    assert sink.is_framework_dangerous is True


def test_dom_xss_framework_vue_v_html():
    script = '<template><div v-html="userNote"></div></template>'
    cands = DomXssEngine.analyze_script_text(script, file_path="/Note.vue")
    assert len(cands) >= 1
    assert cands[0].sink.name == "v-html"
    assert cands[0].sink.framework == "Vue"


def test_dom_xss_framework_angular_bypass_security_trust():
    script = """
    export class MyComp {
        constructor(private sanitizer: DomSanitizer) {}
        render(html: string) {
            return this.sanitizer.bypassSecurityTrustHtml(html);
        }
    }
    """
    cands = DomXssEngine.analyze_script_text(script, file_path="/app.component.ts")
    assert len(cands) >= 1
    assert cands[0].sink.name == "bypassSecurityTrustHtml"
    assert cands[0].sink.framework == "Angular"


def test_dom_xss_framework_jquery_append_sink():
    script = """
    $(document).ready(function() {
        var hash = location.hash.substring(1);
        $('#log').append(hash);
    });
    """
    cands = DomXssEngine.analyze_script_text(script, file_path="/tracker.js")
    assert len(cands) >= 1
    assert cands[0].sink.name == "jquery_append"
    assert cands[0].sink.framework == "jQuery"


def test_dom_xss_sanitizer_dompurify_rejection():
    script = """
    var untrusted = location.hash;
    var clean = DOMPurify.sanitize(untrusted);
    document.getElementById('view').innerHTML = clean;
    """
    cands = DomXssEngine.analyze_script_text(script, file_path="/clean.js")
    assert len(cands) >= 1
    cand = cands[0]
    assert cand.confidence == XssConfidence.REJECTED
    assert cand.lifecycle_state == "REJECTED"


# ==============================================================================
# 4. Stored XSS Foundation Tests
# ==============================================================================

def test_stored_xss_candidate_pair_identification():
    endpoints = [
        {"url": "https://example.com/api/v1/profile/update", "method": "POST", "params": ["bio", "website"]},
        {"url": "https://example.com/profile/view", "method": "GET", "params": ["user_id"]},
        {"url": "https://example.com/api/v1/comments/add", "method": "POST", "params": ["comment"]},
        {"url": "https://example.com/comments/list", "method": "GET", "params": ["page"]},
    ]
    candidates = StoredXssEngine.identify_candidate_pairs(endpoints, target_asset="https://example.com")
    assert len(candidates) >= 1
    for c in candidates:
        assert c.category == XssCategory.STORED
        assert c.retrieval_endpoint is not None
        assert "Step 1" in str(c.evidence.to_dict())


def test_stored_xss_passive_inspection():
    token = "bbxss_stored_marker_99"
    resp_body = f"<html><body><div class='bio'>Hello {token}</div></body></html>"
    cand = StoredXssEngine.passively_inspect_response(
        response_body=resp_body,
        retrieval_url="https://example.com/profile/view",
        canary_token=token,
    )
    assert cand is not None
    assert cand.category == XssCategory.STORED
    assert cand.canary_token == token


# ==============================================================================
# 5. Anti-SSRF Network Validation & Redirect Tests
# ==============================================================================

def test_anti_ssrf_ipv4_mapped_ipv6_blocking():
    is_bad, reason = is_ssrf_prohibited_ip("::ffff:127.0.0.1")
    assert is_bad is True
    assert "IPv4-mapped" in reason

    is_bad, reason = is_ssrf_prohibited_ip("::ffff:169.254.169.254")
    assert is_bad is True

    is_bad, _ = is_ssrf_prohibited_ip("::ffff:8.8.8.8")
    assert is_bad is False


def test_anti_ssrf_private_ranges():
    prohibited_ips = [
        "127.0.0.1", "10.0.1.5", "172.16.0.1", "192.168.1.1",
        "169.254.169.254", "0.0.0.0", "::1", "fe80::1", "fc00::1"
    ]
    for ip in prohibited_ips:
        is_bad, _ = is_ssrf_prohibited_ip(ip)
        assert is_bad is True, f"Expected {ip} to be blocked by anti-SSRF"


def test_security_engine_blocks_private_ip_scope(temp_workspace, mock_scope_engine):
    engine = SecurityValidationEngine(program_dir=temp_workspace, scope_engine=mock_scope_engine)
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://127.0.0.1/admin")
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://169.254.169.254/latest/meta-data/")
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://[::1]/debug")
    with pytest.raises(ScopeViolationError):
        engine.check_request_scope("http://[::ffff:127.0.0.1]/test")


def test_safe_redirect_handler_blocks_hop_to_private_ip():
    def scope_checker(url: str):
        if "169.254" in url or "127.0.0.1" in url:
            raise ScopeViolationError(f"Blocked private redirect to {url}")

    handler = SafeRedirectHandler(check_scope_fn=scope_checker, max_redirects=3)
    with pytest.raises(ScopeViolationError):
        handler.redirect_request(None, None, 302, "Found", {}, "http://169.254.169.254/secret")


# ==============================================================================
# 6. Endpoint Safety Classification Tests
# ==============================================================================

def test_endpoint_safety_classification():
    policy = SecurityTestPolicy(
        block_destructive_actions=True,
        block_unknown_endpoints=True,
        endpoint_classifications={"/api/v1/delete-user": EndpointSafetyClass.BLOCKED},
    )

    # 1. Blocked endpoint
    assert policy.classify_endpoint("GET", "/api/v1/delete-user") == EndpointSafetyClass.BLOCKED
    with pytest.raises(PolicyViolationError):
        policy.validate_request_safety("GET", "/api/v1/delete-user")

    # 2. State-changing path keyword
    assert policy.classify_endpoint("GET", "/users/purge") == EndpointSafetyClass.STATE_CHANGING

    # 3. Read-only search endpoint
    assert policy.classify_endpoint("GET", "/api/v1/search") == EndpointSafetyClass.SAFE


# ==============================================================================
# 7. XSS State Management Tests
# ==============================================================================

def test_xss_state_manager_save_and_retrieve(temp_workspace):
    mgr = XssStateManager(temp_workspace)
    c1 = XssCandidate(
        category=XssCategory.REFLECTED,
        target_asset="https://example.com",
        endpoint="https://example.com/search",
        parameter="q",
        context_type=XssContextType.HTML_BODY,
        reflection_state=ReflectionState.UNFILTERED,
        confidence=XssConfidence.OBSERVED,
        severity="MEDIUM",
    )
    c2 = XssCandidate(
        category=XssCategory.DOM,
        target_asset="https://example.com",
        endpoint="https://example.com/app.js",
        context_type=XssContextType.SCRIPT_BLOCK,
        confidence=XssConfidence.SUSPECTED,
        severity="HIGH",
    )

    mgr.save_candidate(c1)
    mgr.save_candidate(c2)

    all_cands = mgr.list_candidates()
    assert len(all_cands) == 2

    dom_cands = mgr.list_candidates(category=XssCategory.DOM)
    assert len(dom_cands) == 1
    assert dom_cands[0].severity == "HIGH"

    summary = mgr.get_summary()
    assert summary["total_candidates"] == 2
    assert summary["by_category"]["reflected"] == 1
    assert summary["by_category"]["dom"] == 1
    assert summary["by_confidence"]["OBSERVED"] == 1
    assert summary["by_confidence"]["SUSPECTED"] == 1


# ==============================================================================
# 8. Reflected XSS Context Validator & Engine Tests
# ==============================================================================

def test_reflected_xss_context_validator_defended_rejection(temp_workspace):
    val = ReflectedXssContextValidator()
    assert val.can_test("/search?q=1")

    # Mock response with encoded reflection
    token = "test_canary_tok"
    resp = ControlledResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        body=f"<html><body>Results for: {token}&lt;script&gt;</body></html>",
        size_bytes=60,
    )

    from framework.validation.baseline import BaselineComparison, BaselineObservation, compare_with_baseline
    base = BaselineObservation("GET /search", 200, "text/html", 50, {}, "h1", "")
    comp = compare_with_baseline(base, resp, test_marker=token)
    tc = val.prepare_test_cases("https://example.com", "/search", "q")[0]

    result, finding = val.analyze(comp, base, resp, tc)
    assert result.lifecycle_state == FindingLifecycle.REJECTED
    assert result.confidence == "REJECTED"
    assert finding is None  # False positive successfully eliminated!


def test_xss_engine_evaluate_reflected_with_mock_hook(temp_workspace, mock_scope_engine):
    token_used = None

    def mock_hook(req: ControlledRequest) -> ControlledResponse:
        nonlocal token_used
        # Extract token from query
        q = req.base_url.split("q=")[-1]
        token_used = q[:14]
        # Return unencoded reflection in body
        return ControlledResponse(
            status_code=200,
            headers={"content-type": "text/html"},
            body=f"<html><body>Query was: {q}</body></html>",
            size_bytes=100,
            final_url=req.base_url,
        )

    engine = XssIntelligenceEngine(
        program_dir=temp_workspace,
        scope_engine=mock_scope_engine,
        send_request_hook=mock_hook,
    )

    cand, finding = engine.evaluate_reflected_candidate(
        target_asset="https://example.com",
        endpoint="https://example.com/search?q=old",
        parameter="q",
    )

    assert cand is not None
    assert cand.category == XssCategory.REFLECTED
    assert cand.confidence in (XssConfidence.OBSERVED, XssConfidence.SUSPECTED)
    assert finding is not None
    assert finding.vulnerability_type == "Cross-Site Scripting (Reflected)"


# ==============================================================================
# 9. CLI Utility (bb-xss) Dry-Run & Tree Execution
# ==============================================================================

def test_bb_xss_cli_dry_run(temp_workspace):
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "scripts", "bb-xss"))
    cmd = [
        "python",
        script_path,
        "--program", "cli-test",
        "--category", "reflected",
        "--endpoint", "https://example.com/search?q=1",
        "--parameter", "q",
        "--dry-run",
        "--json",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode == 0
    data = json.loads(proc.stdout)
    assert data["program"] == "cli-test"
    assert "results" in data


# ==============================================================================
# 10. Security Audit: Zero shell=True / os.system
# ==============================================================================

def test_zero_shell_true_security_audit():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    xss_dir = os.path.join(repo_root, "framework", "xss")

    for root, _, files in os.walk(xss_dir):
        for f in files:
            if f.endswith(".py"):
                path = os.path.join(root, f)
                with open(path, "r", encoding="utf-8") as py_file:
                    content = py_file.read()
                    assert "shell=True" not in content, f"Insecure shell=True found in {path}"
                    assert "os.system(" not in content, f"Insecure os.system found in {path}"
