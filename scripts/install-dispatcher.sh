#!/usr/bin/env bash
#
# BugBounty-Agent — Isolated Execution Dispatcher Service Installer (Linux)
#
# Configures a dedicated, unprivileged system account (_bbdispatcher),
# sets up strict filesystem permissions, and registers the systemd service.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[!] Error: This installation script must be run as root (e.g. sudo ./scripts/install-dispatcher.sh)" >&2
   exit 1
fi

AGENT_USER="${SUDO_USER:-$(logname 2>/dev/null || echo "")}"
if [[ -z "$AGENT_USER" ]]; then
    echo "[!] Warning: Could not detect invoking non-root user. Specify AGENT_USER=username if needed."
fi

DISPATCHER_USER="_bbdispatcher"
DISPATCHER_GROUP="bbgroup"

echo "[*] 1. Creating dedicated service group: ${DISPATCHER_GROUP}..."
if ! getent group "${DISPATCHER_GROUP}" >/dev/null; then
    groupadd --system "${DISPATCHER_GROUP}"
    echo "[+] Group '${DISPATCHER_GROUP}' created."
else
    echo "[+] Group '${DISPATCHER_GROUP}' already exists."
fi

echo "[*] 2. Creating dedicated unprivileged service account: ${DISPATCHER_USER}..."
if ! id -u "${DISPATCHER_USER}" >/dev/null 2>&1; then
    useradd --system --gid "${DISPATCHER_GROUP}" --no-create-home --shell /usr/sbin/nologin "${DISPATCHER_USER}"
    echo "[+] User '${DISPATCHER_USER}' created."
else
    echo "[+] User '${DISPATCHER_USER}' already exists."
fi

if [[ -n "$AGENT_USER" ]]; then
    echo "[*] Adding agent user '${AGENT_USER}' to '${DISPATCHER_GROUP}'..."
    usermod -aG "${DISPATCHER_GROUP}" "${AGENT_USER}"
    echo "[+] User '${AGENT_USER}' added to '${DISPATCHER_GROUP}'."
fi

echo "[*] 3. Setting up secure directory hierarchy..."
mkdir -p /run/bugbounty
chown "${DISPATCHER_USER}:${DISPATCHER_GROUP}" /run/bugbounty
# Crucial security fix: 0750 prevents members of bbgroup from deleting or replacing the socket file
chmod 0750 /run/bugbounty

mkdir -p /var/lib/bugbounty/keys
chown "${DISPATCHER_USER}:${DISPATCHER_USER}" /var/lib/bugbounty/keys
chmod 0700 /var/lib/bugbounty/keys

mkdir -p /var/lib/bugbounty/state
chown "${DISPATCHER_USER}:${DISPATCHER_USER}" /var/lib/bugbounty/state
chmod 0700 /var/lib/bugbounty/state

mkdir -p /var/lib/bugbounty/evidence
chown "${DISPATCHER_USER}:${DISPATCHER_GROUP}" /var/lib/bugbounty/evidence
chmod 0750 /var/lib/bugbounty/evidence

echo "[*] 4. Installing systemd unit..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${REPO_DIR}/systemd/bugbounty-dispatcher.service" ]]; then
    cp "${REPO_DIR}/systemd/bugbounty-dispatcher.service" /etc/systemd/system/bugbounty-dispatcher.service
    # Update repository path if not in /opt
    sed -i "s|/opt/BugBounty-Agent|${REPO_DIR}|g" /etc/systemd/system/bugbounty-dispatcher.service
    systemctl daemon-reload
    echo "[+] systemd unit installed and daemon reloaded."
    echo "[*] To start service: sudo systemctl start bugbounty-dispatcher"
    echo "[*] To enable on boot: sudo systemctl enable bugbounty-dispatcher"
fi

echo "[+] Linux isolated execution dispatcher setup complete."
