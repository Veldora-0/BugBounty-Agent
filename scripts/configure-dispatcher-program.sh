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
install -o root -g bbgroup -m 0640 -- "$APPROVAL_KEY_SOURCE" "$key_tmp"
cat > "$env_tmp" <<EOF
BUGBOUNTY_DISPATCHER_PROGRAM_ID=${PROGRAM_ID}
BUGBOUNTY_DISPATCHER_SCOPE_FILE=/etc/bugbounty/scopes/${PROGRAM_ID}.yaml
BUGBOUNTY_DISPATCHER_APPROVAL_KEY_FILE=/etc/bugbounty/operator_approval.key
EOF
chown root:bbgroup "$env_tmp"
chmod 0640 "$env_tmp"

mv -f -- "$scope_tmp" "/etc/bugbounty/scopes/${PROGRAM_ID}.yaml"
mv -f -- "$key_tmp" /etc/bugbounty/operator_approval.key
mv -f -- "$env_tmp" /etc/bugbounty/dispatcher.env
trap - EXIT

systemctl restart bugbounty-dispatcher.service
systemctl is-active --quiet bugbounty-dispatcher.service
python3 "${SCRIPT_DIR}/bb-dispatcher" --socket /run/bugbounty/dispatcher.sock --status \
    | python3 -c 'import json,sys; s=json.load(sys.stdin).get("receipt", {}); ok=s.get("production_dispatch_ready") is True and s.get("program_id"); print("[+] Dispatcher configuration loaded for program " + s["program_id"] if ok else "[!] Dispatcher is not production-dispatch-ready", file=sys.stdout if ok else sys.stderr); sys.exit(0 if ok else 1)'

echo "[+] Program scope and operator approval key installed with root-managed permissions."
