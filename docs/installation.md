# BugBounty-Agent — Installation & Setup Guide

This guide describes how to install and configure BugBounty-Agent on an authorized **Kali Linux** system or general Unix/Linux environment.

---

## 1. System Requirements

* **OS**: Kali Linux 2023.x+ (or any Linux distribution with Python 3.10+)
* **Python**: Python 3.10 or later
* **OpenCode**: Installed and accessible in your shell environment
* **Go**: Go 1.21+ (recommended for ProjectDiscovery tools)

---

## 2. Clone the Framework

Clone the repository to your local machine:

```bash
git clone https://github.com/Veldora-0/BugBounty-Agent.git
cd BugBounty-Agent
```

---

## 3. Python Environment Setup

Install the lightweight framework dependencies:

```bash
# Optional: create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required packages
pip install pyyaml pytest
```

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

BugBounty-Agent gracefully detects installed tools on your `PATH`. For full reconnaissance capabilities on Kali Linux:

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
python3 -c "from framework.common.tools import ToolDetector; print(ToolDetector.get_summary())"
```

---

## 5. Verify the Installation

Run the automated test suite to ensure the scope engine, deduplication, and normalizers pass all checks:

```bash
python3 -m pytest -v
```

---

## 6. OpenCode Setup

BugBounty-Agent comes preconfigured for OpenCode:

* `.opencode/agents/`: Unified `Bug-Bounty` agent definition.
* `.opencode/skills/`: 17 modular methodology skills.
* `opencode.jsonc`: Default agent and permissions configuration.

Launch OpenCode within the repository:

```bash
opencode .
```

By default, OpenCode will load `Bug-Bounty` as the primary orchestrator.
