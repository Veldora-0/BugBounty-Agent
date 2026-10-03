# Contributing to BugBounty-Agent

Thank you for your interest in contributing to BugBounty-Agent! We welcome contributions that improve the quality, accuracy, safety, and modularity of the agent framework.

---

## Code of Conduct & Ethical Research Standard

BugBounty-Agent is strictly intended for authorized security research. We do not accept contributions that:
* Introduce automated denial-of-service or volumetric stress tools.
* Add destructive database commands or persistent system backdoors.
* Automate brute-force credential stuffing or password spraying.
* Bypass the Scope Engine or permit unauthorized third-party target interactions.

---

## Development Guidelines

1. **Keep Framework and Runtime Separate**:
   * Never commit target data, scan results, or credentials to Git.
   * Verify `.gitignore` before submitting a pull request.
2. **Standard Library First**:
   * Favor Python standard library components where feasible to ensure effortless deployment on Kali Linux.
3. **Automated Testing**:
   * All changes must include corresponding unit tests in `tests/`.
   * Ensure `python -m pytest` passes 100% before opening a PR.
4. **Code Quality**:
   * Adhere to PEP 8 styling conventions.
   * Include type hints on all public interfaces.
