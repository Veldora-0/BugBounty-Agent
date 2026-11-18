# Supported Environments

**Last reviewed:** 2026-11-19  
**Primary platform:** Kali Linux  
**Project status:** Beta; use only against targets that explicitly authorize the planned testing.

This page separates the Python package's declared compatibility from environments that have actually been exercised. A `requires-python` value says which interpreter versions the package accepts; it does not prove that every operating-system and Python combination has passed the complete test suite.

## Support matrix

| Environment | Support position | What is verified | Important limits |
|---|---|---|---|
| Kali Linux x86-64 | Primary research environment | The latest previously recorded full-suite run used Kali Linux and Python 3.14.10. A new Phase 24 run will be recorded against its exact commit before acceptance. | The installed Linux dispatcher has separate live-service acceptance evidence and limits in Phase 21. Optional OSINT tools and OOB services are not implied by the core install. |
| Other Linux distributions | Best effort | The project uses Python and POSIX facilities in several paths, but distribution-specific service setup is not generally tested. | Package names, service managers, permissions and browser dependencies can differ. Use Kali instructions only where they apply. |
| Windows 10/11 | Development and CLI use only; current acceptance pending | Historical Windows test runs exist. The current Windows launcher was unavailable during the November 2026 audit, and Phase 22 ACL subprocess verification remains unresolved. | Linux systemd dispatcher isolation is not available on Windows. Do not treat Windows as a production-equivalent deployment. |
| macOS | Unverified | No current full-suite result is recorded. | Do not infer support from Python portability alone. |

## Python and optional runtimes

`pyproject.toml` declares Python **3.10 or newer**. The core runtime dependencies are PyYAML and `cryptography`. Playwright is an optional extra (`.[browser]`); installing it does not install every browser binary. Install a browser only when using the browser capability and follow the current Playwright instructions for that environment.

The release workflow is configured to test Linux on Python 3.10 and 3.14, and Windows on Python 3.14. Those jobs are acceptance evidence only after they have actually run successfully for the commit being evaluated. This matrix does not verify macOS, browser binaries, a production Windows dispatcher, live OOB services, third-party tool integrations, or live-target vulnerability detection.

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
