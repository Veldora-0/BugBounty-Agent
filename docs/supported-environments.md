# Supported Environments

**Last reviewed:** 2026-11-19  
**Primary platform:** Kali Linux  
**Project status:** Beta; use only against targets that explicitly authorize the planned testing.

This page separates the Python package's declared compatibility from environments that have actually been exercised. A `requires-python` value says which interpreter versions the package accepts; it does not prove that every operating-system and Python combination has passed the complete test suite.

## Support matrix

| Environment | Support position | What is verified | Important limits |
|---|---|---|---|
| Kali Linux x86-64 | Primary research environment | On commit `b6308e8`, Linux `7.2.15+kali-amd64`, Python 3.14.10: full suite **1,329 passed, 2 skipped** in 382.29 seconds; 46 focused dispatcher/provider regression tests passed in 2.45 seconds. | The updated dispatcher group permissions and successful authorized service dispatch still require privileged installed-service verification. Optional OSINT tools and OOB services are not implied by the core install. |
| Other Linux distributions | Best effort | The project uses Python and POSIX facilities in several paths, but distribution-specific service setup is not generally tested. | Package names, service managers, permissions and browser dependencies can differ. Use Kali instructions only where they apply. |
| Hosted Windows Server 2025 CI; Windows desktop development | Development and CLI use only; full-suite CI is the platform check | The `windows-latest / Python 3.14` job passed for `b6308e8` in [GitHub Actions run 44584566317](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44584566317). Native Windows CI runs DACL and path checks that are skipped on Kali. | Do not treat hosted CI as proof for every Windows 10/11 desktop configuration. Linux systemd dispatcher isolation is not available on Windows; Windows production dispatcher isolation remains unsupported. |
| macOS | Unverified | No current full-suite result is recorded. | Do not infer support from Python portability alone. |

## Python and optional runtimes

`pyproject.toml` declares Python **3.10 or newer**. The core runtime dependencies are PyYAML and `cryptography`. Playwright is an optional extra (`.[browser]`); installing it does not install every browser binary. Install a browser only when using the browser capability and follow the current Playwright instructions for that environment.

The release workflow tests Linux on Python 3.10 and 3.14, and Windows on Python 3.14. All three full-suite jobs passed for `b6308e8` in [GitHub Actions run 44584566317](https://github.com/Veldora-0/BugBounty-Agent/actions/runs/44584566317). This matrix does not verify macOS, browser binaries on every host, a production Windows dispatcher, live OOB services, third-party tool integrations, or live-target vulnerability detection.

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
