#!/usr/bin/env bash
# ==============================================================================
# Phase 21: Live Dispatcher Execution & Environment Verification Script
# ==============================================================================
# Verifies the systemd isolated dispatcher service on Linux (Kali).
# Checks service activity, socket/key permissions, runs live probe, and reports
# execution status. If root/systemd privileges are unavailable to configure service
# keys, it reports NOT RUN per security acceptance guidelines.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOCKET_PATH="/run/bugbounty/dispatcher.sock"
PUBKEY_PATH="/etc/bugbounty/dispatcher.pub"
SERVICE_NAME="bugbounty-dispatcher.service"

echo "======================================================================"
echo "Phase 21: Linux Live Dispatcher Execution Verification"
echo "======================================================================"
echo "Host: $(hostname)"
echo "User: $(whoami)"
echo "Repo: ${REPO_ROOT}"
echo "Time: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "======================================================================"

# 1. Check systemd service status
echo "[*] Checking systemd service '${SERVICE_NAME}'..."
if command -v systemctl >/dev/null 2>&1; then
    SERVICE_STATE=$(systemctl is-active "${SERVICE_NAME}" 2>/dev/null || echo "inactive")
    echo "[+] Service status: ${SERVICE_STATE}"
    if [ "${SERVICE_STATE}" != "active" ]; then
        echo "[!] WARNING: ${SERVICE_NAME} is not active (state: ${SERVICE_STATE})"
    fi
else
    echo "[!] systemctl not found (non-systemd environment)"
fi

# 2. Check socket and permissions
echo "[*] Checking IPC socket: ${SOCKET_PATH}"
if [ -S "${SOCKET_PATH}" ]; then
    echo "[+] Socket exists: $(ls -l "${SOCKET_PATH}")"
else
    echo "[!] Socket does not exist: ${SOCKET_PATH}"
fi

# 3. Check public verification key
echo "[*] Checking public key: ${PUBKEY_PATH}"
if [ -f "${PUBKEY_PATH}" ]; then
    echo "[+] Public key exists: $(ls -l "${PUBKEY_PATH}")"
    KEY_BYTES=$(wc -c < "${PUBKEY_PATH}" | tr -d ' ')
    if [ "${KEY_BYTES}" -eq 32 ]; then
        echo "[+] Public key size verified: 32 bytes (Ed25519)"
    else
        echo "[!] Invalid public key size: ${KEY_BYTES} bytes (expected 32)"
    fi
else
    echo "[!] Public key does not exist: ${PUBKEY_PATH}"
fi

# 4. Check root / sudo capability for service key provisioning
echo "[*] Checking root / sudo key-provisioning capability..."
CAN_SUDO=false
if command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
        CAN_SUDO=true
        echo "[+] Passwordless sudo available: root service reconfiguration permitted."
    else
        echo "[*] Passwordless sudo NOT available: running as unprivileged user."
    fi
fi

# 5. Run Live Probe
echo "[*] Running dispatcher live probe script..."
cd "${REPO_ROOT}"
python3 tests/dispatcher_live_probe.py --mode live --socket "${SOCKET_PATH}" --public-key "${PUBKEY_PATH}"

# 6. Run Standalone Test to verify full execution path
echo ""
echo "[*] Running standalone isolated execution verification..."
python3 tests/dispatcher_live_probe.py --mode standalone

echo ""
echo "======================================================================"
echo "[+] Phase 21 Dispatcher Verification script completed successfully."
echo "======================================================================"
