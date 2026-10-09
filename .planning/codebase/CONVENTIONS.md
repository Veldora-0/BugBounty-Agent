# Coding Conventions

**Analysis Date:** 2026-10-09

## Naming Patterns

**Files:**
- `snake_case.py` for all Python modules (`framework/scope/engine.py`, `framework/authentication/models.py`).
- `test_<subsystem>.py` for test files located in `tests/` (`tests/test_authentication_engine.py`).
- `bb-<subsystem>` for POSIX shell CLI scripts (`scripts/bb-auth`, `scripts/bb-recon`).
- `bb-<subsystem>.cmd` for Windows batch CLI launchers (`scripts/bb-auth.cmd`).
- `SKILL.md` (UPPERCASE) for OpenCode skill contracts within kebab-case directories (`skills/asset-intelligence/SKILL.md`).
- `UPPERCASE.md` for core repository root documentation (`README.md`, `AGENTS.md`, `CHANGELOG.md`, `SECURITY.md`).

**Classes and Types:**
- `PascalCase` for classes, dataclasses, and custom exceptions (`ScopeDecision`, `IdentityProfile`, `SystemDoctor`, `NormalizationError`).
- No `I` prefix for interfaces/protocols.
- `class Foo(str, Enum)` for serialization-friendly string enumerations with `UPPER_SNAKE_CASE` values (`ScopeStatus.IN_SCOPE`, `MFAState.COMPLETED`).

**Functions & Methods:**
- `snake_case` for all functions and methods (`calculate_subdomain_depth`, `render_tree`, `verify_finding`).
- Leading underscore `_private_method` for internal module helpers and non-public class members (`_init_files`, `_load_registry`).

**Variables & Constants:**
- `snake_case` for local variables and instance attributes (`target_url`, `is_active`, `root_domain`).
- `UPPER_SNAKE_CASE` for module-level constants and global configuration dictionaries (`DEFAULT_COVERAGE`, `KNOWN_PUBLIC_KEYS`, `CVSS_V31_BASE_SCORE`).

## Code Style

**Formatting:**
- Standard Python 4-space indentation.
- Maximum line length generally kept within 100–120 characters for clean terminal and diff reading.
- Double quotes for docstrings; double quotes or consistent single quotes for dictionary keys and strings.
- Standard ASCII box formatting (`\--`, `|--`) used in terminal tree outputs rather than Unicode characters to preserve compatibility with Windows `cp1252` console encoding.

**Type Annotations & Modern Syntax:**
- `from __future__ import annotations` at the top of every Python source file.
- Strict type hinting across all function signatures: `Optional[str]`, `Dict[str, Any]`, `List[Finding]`, `Tuple[bool, str]`, `Union[int, str]`.
- Standard library `@dataclass` used for data models (`@dataclass\nclass IdentityProfile:`).

## Import Organization

**Order:**
1. Future imports (`from __future__ import annotations`).
2. Standard library modules (`os`, `sys`, `json`, `hashlib`, `urllib.parse`, `ipaddress`, `dataclasses`, `typing`).
3. Third-party packages (`yaml`, `playwright`, `pytest`).
4. Framework internal imports (`from framework.common.config import get_workspace_root`).

**Grouping:**
- Blank line separating standard library, third-party, and framework-internal blocks.
- Explicit imports preferred over wildcard imports (`from typing import Any, Dict, List, Optional` — never `import *`).

## Error Handling

**Strategy:**
- Fail closed and fail early. Security boundaries must never silently succeed upon unrecognized or ambiguous input.
- Custom exception hierarchies:
  - `NormalizationError` for malformed target URLs, IPs, or CIDR blocks.
  - `ScopeError` for invalid or conflicting scope definitions.
  - `ValidationError` for malformed finding candidate schemas.

**Patterns:**
- Typed `try/except` blocks catching specific failure conditions (`except urllib.error.URLError:`, `except json.JSONDecodeError:`).
- Defensive fallback mechanisms when invoking external CLI binaries: check binary availability via `shutil.which` before execution and return structured fallback error dictionaries rather than uncaught tracebacks.
- Subprocess safety: NEVER use `shell=True`. All process invocations must pass command arguments as explicit lists:
  ```python
  # Correct & Safe:
  subprocess.run(["subfinder", "-d", domain, "-silent"], capture_output=True, text=True, check=False)
  
  # Strictly Prohibited:
  subprocess.run(f"subfinder -d {domain}", shell=True)
  ```

## Logging & CLI Output

**Framework:**
- Standardized command-line output using colored ASCII terminal indicators:
  - `[+]` Green/Standard - Successful discovery, healthy diagnostic, or validated finding.
  - `[*]` Blue/Standard - In-progress informational status, workflow phase notification.
  - `[!]` Yellow - Warning, rate limit encountered, ambiguous target, or missing optional dependency.
  - `[-]` Red - Error, out-of-scope target, verification failure, or rejected payload.

**Patterns:**
- Support for structured `--json` output across all CLI wrapper utilities (`bb-auth --json`, `bb-assets --json`) to enable machine parsing and automated pipeline composition.
- Interactive tree rendering (`--tree`) providing human-readable hierarchical visualizations of asset graphs, authentication flows, and validated findings.

## Comments & Documentation

**When to Comment:**
- Detailed module-level docstrings explaining subsystem responsibilities, security guarantees, and constraints.
- Inline comments explaining non-obvious security heuristics, RFC compliance nuances (e.g. DNS label boundaries, IPv6 zero-compression), and regular expressions.

**Docstring Format:**
- Triple-double-quoted docstrings on all classes, public methods, and top-level functions summarizing behavior, parameters, and return values.

## Function Design

**Size:**
- Single responsibility principle. Complex workflows broken down into dedicated helper functions or pipeline stages (e.g., `discover` $\to$ `analyze` $\to$ `hypothesize` $\to$ `validate`).

**Return Values:**
- Explicit typed returns. Functions that perform validation or safety checks return tuples or structured decision objects (e.g. `ScopeDecision`, `(bool, str)`).

## Module Design

**Packaging:**
- Every framework directory contains an `__init__.py` file providing clean, explicit exports via `__all__` or public symbol imports.
- Modular separation between pure data models (`models.py`), domain analyzers (`*.py`), policy enforcement (`policy.py`), state persistence (`storage.py`), and orchestrating engines (`engine.py`).

---

*Convention analysis: 2026-10-09*
*Update when patterns change*
