#!/usr/bin/env bash
# Register one program's scope and operator key for the Linux system dispatcher.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run with sudo: bash scripts/configure-dispatcher-program.sh <program-id> <scope.yaml> <auth_approval.key>" >&2
    exit 1
fi

if [[ $# -ne 3 ]]; then
    echo "Usage: sudo bash scripts/configure-dispatcher-program.sh <program-id> <scope.yaml> <auth_approval.key>" >&2
    exit 2
fi

PROGRAM_ID="$1"
SCOPE_SOURCE="$2"
APPROVAL_KEY_SOURCE="$3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

UNIT_FILE="/etc/systemd/system/bugbounty-dispatcher.service"
if [[ ! -f "$UNIT_FILE" ]] || ! grep -Fq 'EnvironmentFile=-/etc/bugbounty/dispatcher.env' "$UNIT_FILE"; then
    echo "[!] Install the current dispatcher unit first: sudo bash scripts/install-dispatcher.sh" >&2
    exit 1
fi
if ! getent group bbdispatcher-keys >/dev/null \
    || ! id -nG _bbdispatcher | tr ' ' '\n' | grep -Fxq bbdispatcher-keys; then
    echo "[!] The dispatcher-only key group is missing. Reinstall with sudo bash scripts/install-dispatcher.sh first." >&2
    exit 1
fi

if [[ ! "$PROGRAM_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]]; then
    echo "[!] Program ID must be 1-64 safe ASCII letters, digits, dots, underscores, or hyphens." >&2
    exit 2
fi

for source_file in "$SCOPE_SOURCE" "$APPROVAL_KEY_SOURCE"; do
    if [[ ! -f "$source_file" || -L "$source_file" ]]; then
        echo "[!] Configuration sources must be regular, non-symlink files." >&2
        exit 1
    fi
done

# Validate both files before changing /etc. The key itself is never printed.
PYTHONPATH="$REPO_DIR" python3 - "$SCOPE_SOURCE" "$APPROVAL_KEY_SOURCE" <<'PY'
import sys
import os
import stat
from framework.auth_correlation.ipc.config import load_operator_approval_key, load_scope_engine

load_scope_engine(sys.argv[1])
load_operator_approval_key(sys.argv[2])
approval_mode = stat.S_IMODE(os.stat(sys.argv[2], follow_symlinks=False).st_mode)
if approval_mode & 0o077:
    raise SystemExit("Operator key source must be private to its owner (mode 0600 or stricter)")
PY

install -d -o root -g root -m 0755 /etc/bugbounty
install -d -o root -g bbgroup -m 0750 /etc/bugbounty/scopes

scope_tmp="$(mktemp /etc/bugbounty/scopes/.scope.XXXXXX)"
key_tmp="$(mktemp /etc/bugbounty/.approval.XXXXXX)"
env_tmp="$(mktemp /etc/bugbounty/.dispatcher.XXXXXX)"
cleanup() {
    rm -f -- "$scope_tmp" "$key_tmp" "$env_tmp"
}
trap cleanup EXIT

install -o root -g bbgroup -m 0640 -- "$SCOPE_SOURCE" "$scope_tmp"
install -o root -g bbdispatcher-keys -m 0640 -- "$APPROVAL_KEY_SOURCE" "$key_tmp"
cat > "$env_tmp" <<EOF
BUGBOUNTY_DISPATCHER_PROGRAM_ID=${PROGRAM_ID}
BUGBOUNTY_DISPATCHER_SCOPE_FILE=/etc/bugbounty/scopes/${PROGRAM_ID}.yaml
BUGBOUNTY_DISPATCHER_APPROVAL_KEY_FILE=/etc/bugbounty/operator_approval.key
EOF
chown root:root "$env_tmp"
chmod 0600 "$env_tmp"

mv -f -- "$scope_tmp" "/etc/bugbounty/scopes/${PROGRAM_ID}.yaml"
mv -f -- "$key_tmp" /etc/bugbounty/operator_approval.key
mv -f -- "$env_tmp" /etc/bugbounty/dispatcher.env
trap - EXIT

systemctl restart bugbounty-dispatcher.service
systemctl is-active --quiet bugbounty-dispatcher.service
status_ready=false
for _ in $(seq 1 75); do
    if systemctl is-active --quiet bugbounty-dispatcher.service && [[ -S /run/bugbounty/dispatcher.sock ]]; then
        status_json="$(python3 "${SCRIPT_DIR}/bb-dispatcher" --socket /run/bugbounty/dispatcher.sock --status 2>/dev/null)" || status_json=""
        if [[ -n "$status_json" ]] && printf '%s' "$status_json" | python3 -c '
import json
import sys

expected_program = sys.argv[1]
try:
    status = json.load(sys.stdin)
    receipt = status.get("receipt") or {}
except (json.JSONDecodeError, AttributeError):
    raise SystemExit(1)
if (
    status.get("status") != "SUCCESS"
    or receipt.get("production_dispatch_ready") is not True
    or receipt.get("program_id") != expected_program
):
    raise SystemExit(1)
print("[+] Dispatcher configuration loaded for program " + expected_program)
' "$PROGRAM_ID"; then
            status_ready=true
            break
        fi
    fi
    sleep 0.2
done

if [[ "$status_ready" != true ]]; then
    echo "[!] Dispatcher did not become ready with program '$PROGRAM_ID' within 15 seconds; diagnostics follow:" >&2
    systemctl status bugbounty-dispatcher.service --no-pager -l >&2 || true
    journalctl -u bugbounty-dispatcher.service -n 30 --no-pager >&2 || true
    exit 1
fi

echo "[+] Program scope and operator approval key installed with root-managed permissions."
