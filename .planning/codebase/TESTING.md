# Testing Patterns

**Analysis Date:** 2026-10-09

## Test Framework

**Runner:**
- Pytest 8.x
- Standard Python test execution across all 14 research capabilities.

**Assertion Library:**
- Standard Python assertions (`assert expr, "failure message"`).
- Pytest built-in assertion introspection with full diff rendering on failure.

**Run Commands:**
```bash
# Run entire test suite (all 32 test suites, 323 tests)
python -m pytest -q

# Run with verbose output and per-test timing
python -m pytest -v

# Run a specific subsystem test suite
python -m pytest tests/test_authentication_engine.py -v

# Run tests matching a specific expression
python -m pytest -k "test_scope or test_tokens"

# Run OpenCode runtime integration tests
python -m pytest tests/test_opencode_runtime.py tests/test_deploy.py -v
```

## Test File Organization

**Location:**
- Flat directory layout in `tests/` at the root of the repository.
- 32 dedicated test suites named `test_<subsystem>.py`.

**Structure:**
```
tests/
├── test_api_engine.py             # Phase 5 API & parameter testing
├── test_asset_engine.py           # Phase 1 Asset intelligence engine
├── test_asset_graph.py            # Phase 1 Graph data structure & edges
├── test_asset_model.py            # Phase 1 Domain models & provenance
├── test_authentication_engine.py  # Phase 14 Authentication & session engine
├── test_authz_engine.py           # Phase 8 Authorization & IDOR/BOLA testing
├── test_business_logic_engine.py  # Phase 12 Business logic & race conditions
├── test_capability_graph.py       # Tool capability mappings & fallbacks
├── test_cloud_security_engine.py  # Phase 13 Cloud security & bucket tests
├── test_deduplication.py         # Test fingerprinting & finding deduplication
├── test_dependencies.py          # System toolchain & dependency checks
├── test_deploy.py                # Global OpenCode deployment logic
├── test_doctor.py                # System health & 23 diagnostic categories
├── test_finding_schema.py        # Finding lifecycle & 17-section reporting
├── test_http_trust_engine.py     # Phase 11 HTTP header trust & smuggling
├── test_injection_engine.py      # Phase 10 Non-destructive injection tests
├── test_installer.py             # Tool installation logic
├── test_installer_security.py    # Installer safety & command sanitization
├── test_javascript_engine.py     # Phase 4 JavaScript analysis & DOM sinks
├── test_opencode_runtime.py      # OpenCode V2 schema, permissions, agent discovery
├── test_providers.py             # API provider credentials & secrets loading
├── test_recon_engine.py          # Phase 2 Reconnaissance engine
├── test_recursive_subdomains.py  # Arbitrary-depth recursive subdomain discovery
├── test_runtime_isolation.py     # Subprocess security (zero shell=True invariant)
├── test_scope.py                 # RFC DNS normalization, CIDR, scope engine
├── test_ssrf_engine.py           # Phase 9 SSRF & Out-of-band interaction tests
├── test_target_normalization.py  # Target normalization edge cases
├── test_tool_registry.py         # Tool registry YAML parsing & verification
├── test_validation_engine.py     # Phase 6 6-gate verification checklist
├── test_webapp_engine.py         # Phase 3 Web application surface mapping
└── test_xss_engine.py            # Phase 7 Context-aware XSS validation
```

## Test Structure

**Suite Organization:**
```python
from __future__ import annotations

import tempfile
import pytest
from framework.authentication.engine import AuthenticationSecurityEngine
from framework.authentication.lab import LocalAuthenticationSecurityLab
from framework.authentication.models import IdentityProfile, PrincipalType

class TestAuthenticationEngine:
    """Validates Phase 14 authentication and session security intelligence."""

    def test_session_fixation_detection(self, tmp_path):
        # Arrange
        lab = LocalAuthenticationSecurityLab()
        engine = AuthenticationSecurityEngine(program_dir=str(tmp_path))
        
        # Act
        results = lab.run_scenario("session-fixation")
        
        # Assert
        assert results["passed"] is True
        assert len(results["findings"]) >= 1
        finding = results["findings"][0]
        assert finding.family.value == "SESSION_FIXATION"
```

**Patterns:**
- Per-test temporary workspace directories created via Pytest's `tmp_path` fixture to ensure complete isolation.
- Clear Arrange-Act-Assert structure in every test case.
- Zero reliance on external network connectivity during automated tests.

## Mocking & Isolation

**Framework:**
- Built-in Mock / Test Double classes (`unittest.mock.patch`, `unittest.mock.MagicMock`).
- Self-contained offline labs (`Local*SecurityLab` in `framework/*/lab.py`) providing synthetic HTTP request/response fixtures, simulated DNS callbacks, and known-vulnerable mock endpoints.

**What is Mocked:**
- External network requests (`urllib.request.urlopen`, socket connections).
- External CLI tool execution (`subprocess.run` patched with synthetic stdout/stderr responses).
- System environment variables for API provider keys.

**What is NOT Mocked:**
- Internal parsing logic (DNS label normalization, CIDR matching, JWT structural decoding, Set-Cookie parsing).
- State persistence managers and atomic file write operations (tested against real temporary directories).
- Rule evaluation hierarchies and finding schema validation.

## Fixtures and Factories

**Test Fixtures:**
- Temporary directory isolation (`tmp_path`) for state file reading/writing.
- Synthetic `scope.yaml` fixtures for testing target boundary enforcement and exclusion precedence.
- Mock target response dictionaries for webapp and API parsing.

## Security Invariant Testing

The test suite includes dedicated security tests that assert foundational framework guarantees:

1. **Runtime Isolation (`test_runtime_isolation.py`):**
   - Scans all Python source files in `framework/` and `scripts/` using Python AST analysis.
   - Strictly asserts that `shell=True` is NEVER passed to `subprocess.run`, `subprocess.Popen`, or `subprocess.check_output`.
2. **OpenCode V2 Security Model (`test_opencode_runtime.py`):**
   - Asserts valid OpenCode V2 schema in `opencode.jsonc`.
   - Asserts `default_agent: "Bug-Bounty"` and `subagent_depth: 1`.
   - Asserts subagents are denied (`action: "subagent", resource: "*", effect: "deny"`).
   - Asserts dangerous commands (`git push *`, remote scripts `curl * | *sh*`, automated report submission `*submit*report*`) are denied or gated.
   - Asserts all 18 skills are discovered and conform to frontmatter specifications.

## Test Types

- **Unit Tests:** Fast, isolated tests of domain functions (DNS label boundary checks, token masking, JWT parsing, CVSS calculations).
- **Integration Tests:** Verifying interaction between engines and state managers (e.g. running an engine, verifying findings are written to `state/findings.json`, and verifying deduplication).
- **Offline Security Labs:** Comprehensive scenarios simulating real-world vulnerabilities (e.g. 21 scenarios in `LocalAuthenticationSecurityLab`, all running 100% offline).
- **Runtime & Deployment Tests:** Verifying OpenCode global deployment symlinks and `bb-doctor` diagnostic outputs.

---

*Testing analysis: 2026-10-09*
*Update when test patterns change*
