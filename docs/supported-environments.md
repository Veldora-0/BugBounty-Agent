# Supported Environments

- **Last reviewed:** 2026-11-27
- **Primary platform:** Kali Linux
- **Project status:** Beta; use only against targets that explicitly authorize the planned testing.

This page separates the Python package's declared compatibility from environments that have actually been exercised. A `requires-python` value says which interpreter versions the package accepts; it does not prove that every operating-system and Python combination has passed the complete test suite.

## Support matrix

| Environment | Support position | What is verified | Important limits |
|---|---|---|---|
| Kali Linux x86-64 | Primary research environment | At code commit `066e511`, the full suite passed: **1,363 passed** in 344.98 seconds. On `8d2ae37`, the installed systemd service passed controlled AUD-08 acceptance, including isolation, approved fixture dispatch, signed receipt/evidence digest verification, replay rejection, and cleanup. Its service-only group is `bbdispatcher-keys`. | Hosted Linux CI jobs passed for `7ac24ee` in [run 44891701876](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44891701876); CI is supplementary and does not replace Kali acceptance. The service is intentionally unconfigured after cleanup; provide a program scope and operator key before production dispatch. Optional OSINT tools and OOB services are not implied by the core install. |
| Other Linux distributions | Best effort | The project uses Python and POSIX facilities in several paths, but distribution-specific service setup is not generally tested. | Package names, service managers, permissions and browser dependencies can differ. Use Kali instructions only where they apply. |
| Windows desktop | Development only; not a current test target | Historical full-suite CI passed on Windows Server 2025 / Python 3.14 for `b6308e8` in [GitHub Actions run 44584566317](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44584566317). The two native Windows-only cases and Windows CI job have since been removed. The service-status check retains only Linux assertions; Linux-run mocked DACL failure cases remain. | Do not infer current Windows support from historical results. Linux systemd dispatcher isolation is not available on Windows; Windows production dispatcher isolation remains unsupported. |
| macOS | Unverified | No current full-suite result is recorded. | Do not infer support from Python portability alone. |

## Python and optional runtimes

`pyproject.toml` declares Python **3.10 or newer**. The core runtime dependencies are PyYAML and `cryptography`. Playwright is an optional extra (`.[browser]`); installing it does not install every browser binary. Install a browser only when using the browser capability and follow the current Playwright instructions for that environment.

Kali Linux is the primary research and local acceptance platform. GitHub Actions uses hosted Ubuntu Linux runners for supplementary Python 3.10 and 3.14 CI checks; Ubuntu is the CI runner, not the project's research-platform recommendation. Those jobs passed for `7ac24ee` in [run 44891701876](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44891701876). Hosted CI does not replace Kali acceptance or establish CleanShot testing. Earlier Windows full-suite results are retained as history, not as current platform support. macOS, browser binaries on every host, a production Windows dispatcher, live OOB services, third-party tool integrations, and live-target vulnerability detection are not established by the current suite.

## Linux-first setup

Use a virtual environment, install the package's declared dependencies, and run `bb-doctor` before setting up the global OpenCode agent. Optional tools are installed separately and should be treated as manual capabilities unless a phase guide and tests show that an engine invokes them.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest tests/ -ra
./scripts/bb-doctor
```

See the [installation guide](installation.md) for global deployment, rollback, config recovery, and safe removal.

## Reporting compatibility

When reporting a defect, include the operating system and release, architecture, Python version, install extras, exact command, commit, and full error. Do not include credentials, cookies, program evidence, or target-private data in public issue reports. A platform is promoted to supported only after its clean-install path and documented acceptance suite have passed.
