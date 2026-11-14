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
INSTALL_DIR="/opt/BugBounty-Agent"

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
chown "${DISPATCHER_USER}:${DISPATCHER_GROUP}" /var/lib/bugbounty/keys
chmod 0700 /var/lib/bugbounty/keys

mkdir -p /var/lib/bugbounty/state
chown "${DISPATCHER_USER}:${DISPATCHER_GROUP}" /var/lib/bugbounty/state
chmod 0700 /var/lib/bugbounty/state

mkdir -p /var/lib/bugbounty/evidence
chown "${DISPATCHER_USER}:${DISPATCHER_GROUP}" /var/lib/bugbounty/evidence
chmod 0750 /var/lib/bugbounty/evidence

echo "[*] 4. Installing systemd unit..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ProtectHome=read-only still cannot traverse a user's 0700 home directory.
# Install a root-owned, read-only runtime copy outside /home for the service identity.
echo "[*] Installing dispatcher runtime into ${INSTALL_DIR}..."
install -d -o root -g root -m 0755 "${INSTALL_DIR}/framework" "${INSTALL_DIR}/scripts"
cp -a "${REPO_DIR}/framework/." "${INSTALL_DIR}/framework/"
install -o root -g root -m 0644 "${REPO_DIR}/scripts/bb-dispatcher" "${INSTALL_DIR}/scripts/bb-dispatcher"
chown -R root:root "${INSTALL_DIR}"
chmod -R a+rX,go-w "${INSTALL_DIR}"

if [[ -f "${REPO_DIR}/systemd/bugbounty-dispatcher.service" ]]; then
    cp "${REPO_DIR}/systemd/bugbounty-dispatcher.service" /etc/systemd/system/bugbounty-dispatcher.service
    systemctl daemon-reload
    echo "[+] systemd unit installed and daemon reloaded."
    echo "[*] Enabling and starting the isolated dispatcher..."
    systemctl enable bugbounty-dispatcher
    systemctl reset-failed bugbounty-dispatcher
    systemctl restart bugbounty-dispatcher
    if ! systemctl is-active --quiet bugbounty-dispatcher; then
        echo "[!] Dispatcher service failed to start; diagnostic output follows:" >&2
        systemctl status bugbounty-dispatcher --no-pager -l >&2 || true
        journalctl -u bugbounty-dispatcher -n 40 --no-pager >&2 || true
        exit 1
    fi

    # Publish only the Ed25519 public key to the agent's trust store.
    # The private key remains readable only by _bbdispatcher.
    if [[ ! -s /var/lib/bugbounty/keys/dispatcher_verification.pub ]]; then
        echo "[!] Dispatcher started without producing its public verification key." >&2
        exit 1
    fi
    install -d -o root -g root -m 0755 /etc/bugbounty
    install -o root -g root -m 0644 \
        /var/lib/bugbounty/keys/dispatcher_verification.pub \
        /etc/bugbounty/dispatcher.pub
    echo "[+] Agent verification key installed at /etc/bugbounty/dispatcher.pub."
    echo "[+] Service identity: $(systemctl show -p User --value bugbounty-dispatcher):$(systemctl show -p Group --value bugbounty-dispatcher)"
fi

echo "[+] Linux isolated execution dispatcher setup complete."
