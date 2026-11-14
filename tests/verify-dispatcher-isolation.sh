#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0 <agent-user>" >&2
    exit 2
fi

AGENT_USER="${1:-${SUDO_USER:-}}"
if [[ -z "$AGENT_USER" ]] || [[ "$AGENT_USER" == root ]]; then
    echo "A non-root agent username is required." >&2
    exit 2
fi

SERVICE=bugbounty-dispatcher
SOCKET=/run/bugbounty/dispatcher.sock
KEY=/var/lib/bugbounty/keys/dispatcher_signing_key.bin
PUBLIC_KEY=/etc/bugbounty/dispatcher.pub
STATE=/var/lib/bugbounty/state
EVIDENCE=/var/lib/bugbounty/evidence

[[ "$(systemctl is-active "$SERVICE")" == active ]] || { echo "Dispatcher service is not active." >&2; exit 1; }
[[ "$(systemctl show -p User --value "$SERVICE")" == _bbdispatcher ]] || { echo "Unexpected dispatcher service user." >&2; exit 1; }
[[ "$(systemctl show -p Group --value "$SERVICE")" == bbgroup ]] || { echo "Unexpected dispatcher service group." >&2; exit 1; }

PID="$(systemctl show -p MainPID --value "$SERVICE")"
[[ "$PID" =~ ^[1-9][0-9]*$ ]] || { echo "Dispatcher has no live MainPID." >&2; exit 1; }
[[ "$(ps -o euid= -p "$PID" | xargs)" == "$(id -u _bbdispatcher)" ]] || { echo "Dispatcher process effective UID mismatch." >&2; exit 1; }
[[ "$(ps -o egid= -p "$PID" | xargs)" == "$(getent group bbgroup | cut -d: -f3)" ]] || { echo "Dispatcher process effective GID mismatch." >&2; exit 1; }

[[ -S "$SOCKET" ]] || { echo "Dispatcher socket is missing." >&2; exit 1; }
[[ "$(stat -c '%U:%G:%a' "$SOCKET")" == "_bbdispatcher:bbgroup:660" ]] || { echo "Unexpected dispatcher socket owner or mode." >&2; exit 1; }
[[ "$(stat -c '%U:%G:%a' "$PUBLIC_KEY")" == "root:root:644" ]] || { echo "Unexpected dispatcher public-key ownership or mode." >&2; exit 1; }
[[ "$(stat -c '%s' "$PUBLIC_KEY")" == 32 ]] || { echo "Dispatcher public key has an invalid size." >&2; exit 1; }

if runuser -u "$AGENT_USER" -- test -r "$KEY"; then
    echo "Agent can read the dispatcher private signing key." >&2
    exit 1
fi
for protected in "$STATE" "$EVIDENCE"; do
    if runuser -u "$AGENT_USER" -- test -w "$protected"; then
        echo "Agent can modify protected dispatcher data: $protected" >&2
        exit 1
    fi
done
runuser -u "$AGENT_USER" -- test -r "$PUBLIC_KEY" || { echo "Agent cannot read the pinned public verification key." >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runuser -u "$AGENT_USER" -- /usr/bin/python3 "$REPO_DIR/scripts/bb-dispatcher" \
    --ping --socket "$SOCKET"

echo "PASS: dispatcher identity, private-key isolation, protected data permissions, and agent IPC access verified."
