# BugBounty-Agent — Installation & Setup Guide

This guide describes installing and maintaining BugBounty-Agent on an authorized research workstation. Kali Linux is the primary environment. See [Supported Environments](supported-environments.md) for the exact support and verification boundary.

---

## 1. System Requirements

* **OS**: Kali Linux is primary. Other Linux distributions may work but are not release-verified unless listed in the support matrix.
* **Python**: Python 3.10 or later is the declared minimum; see the support matrix for versions with current test evidence.
* **OpenCode**: Required for global agent/skill deployment, but not for standalone framework CLIs.
* **Go and other toolchains**: Optional. Install them only for a specific external tool; their presence does not mean every engine invokes that tool.

---

## 2. Clone the Framework

Clone the repository to your local machine:

```bash
git clone https://github.com/Veldora-0/BugBounty-Agent.git
cd BugBounty-Agent
```

---

## 3. Python Environment Setup

Install dependencies using the standard PEP 517/621 packaging specification (`pyproject.toml`):

```bash
# Create an isolated Python environment (recommended on Kali/Debian)
python3 -m venv .venv
source .venv/bin/activate

# Install the required runtime packages declared in pyproject.toml
python -m pip install -e .

# Install development and test dependencies
python -m pip install -e ".[dev]"

# Optional browser automation runtime (also install Playwright's browser separately if needed)
python -m pip install -e ".[browser]"
```

The required packages are PyYAML and `cryptography`. Playwright is optional and is not installed by the core extra. `.[all]` installs the optional browser package and pytest for development.

Add the `scripts/` directory to your shell `PATH` for convenience:

```bash
echo 'export PATH="$HOME/BugBounty-Agent/scripts:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Make scripts executable:

```bash
chmod +x scripts/bb-*
```

---

## 4. Kali Linux Security Tooling (Optional but Recommended)

External security tools are optional. The registry and doctor can report whether binaries are installed, but installation alone does not wire a tool into every research engine. Check the relevant phase guide and [open audit issues](PROJECT-AUDIT-ISSUES.md) before treating a listed tool as an automated capability. Run tools only against explicitly authorized scope.

```bash
# APT-packaged tools
sudo apt update
sudo apt install -y subfinder amass httpx-toolkit ffuf dirsearch wfuzz naabu nuclei

# Alternatively via Go if newer versions are desired
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/tomnomnom/assetfinder@latest
```

To verify which tools are detected:

```bash
python3 -c "from framework.tools.detector import ToolDetector; print(ToolDetector().get_summary())"
```

---

## 5. Verify the Installation

Run the automated test suite from the repository root:

```bash
python3 -m pytest -v
```

---

## 6. OpenCode Global Deployment

BugBounty-Agent deploys globally into your OpenCode environment:

* `agents/Bug-Bounty.md`: Canonical `Bug-Bounty` orchestrator agent definition.
* `skills/`: 18 modular methodology skills.
* `scripts/bb-deploy`: Synchronizes the global `Bug-Bounty` agent, 18 skills, `/Arise` command to `~/.config/opencode/`, and CLI tools to `~/.local/bin/`.

Deploy globally on Kali/Linux:

```bash
./scripts/bb-deploy
```

Verify deployment status:

```bash
./scripts/bb-deploy --status
```

Once deployed, `Bug-Bounty` is available globally in OpenCode from **any working directory**:

```bash
cd ~ && opencode
cd /tmp && opencode
cd ~/Desktop/BugBounty-Agent && opencode
```

### Safe updates, rollback, and removal

Update the Git checkout first, then synchronize the global deployment:

```bash
git pull --ff-only
python -m pip install -e .
./scripts/bb-doctor
./scripts/bb-deploy
./scripts/bb-deploy --status
```

`bb-update` is for optional external security tool versions. It does not update this repository. The deployer keeps an ownership manifest at `~/.config/opencode/.bugbounty-agent-deployment.json` and checks destination hashes before replacing copied files. It refuses unmanaged or user-modified collisions. Symlink mode is the default, so agent/skill changes in the checkout appear immediately; `--copy` creates a separately managed snapshot.

Use `./scripts/bb-coverage` to inspect the static vulnerability-class and tool coverage map, or `./scripts/bb-coverage --validate` to check its repository references. This command is offline and does not send target requests.

Before the first OpenCode config edit, the deployer stores the exact original `opencode.jsonc` bytes in a private backup beside the manifest. It accepts JSONC comments and trailing commas, preserves existing config keys and permission rules, and stops without writing when the config is invalid. The deployed config is written atomically. A later user edit is treated as intentional: uninstall preserves that edited file and reports a partial removal rather than restoring over it.

To roll back the repository to a known commit, start with a clean checkout, check out the known-good commit temporarily, and deploy again. No branch needs to be created:

```bash
git status --short
git checkout --detach <known-good-commit>
./scripts/bb-deploy
```

Return to the current branch after reviewing the rollback:

```bash
git switch main
```

Remove the global deployment with:

```bash
./scripts/bb-deploy --uninstall
```

Uninstall removes only files still matching the ownership manifest. User-modified, unmanaged, or legacy lowercase files are listed and preserved. If removal is partial, review those paths before manually deciding what to remove. Program workspaces, findings, evidence, credentials, installed external tools, and the repository itself are not removed by this command.
