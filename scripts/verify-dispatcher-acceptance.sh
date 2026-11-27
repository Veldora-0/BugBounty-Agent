#!/usr/bin/env bash
# Verify the installed Kali dispatcher through a temporary, constrained HTTPS fixture.
# Cloudflare Quick Tunnel exposes it publicly only while this script is running.
set -Eeuo pipefail
umask 077

if [[ $EUID -ne 0 ]]; then
    echo "Run this script through sudo: sudo bash scripts/verify-dispatcher-acceptance.sh <agent-user>" >&2
    exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
AGENT_USER="${1:-${SUDO_USER:-}}"
SERVICE="bugbounty-dispatcher.service"
SOCKET="/run/bugbounty/dispatcher.sock"
APPROVAL_KEY="/etc/bugbounty/operator_approval.key"
CONFIG_FILE="/etc/bugbounty/dispatcher.env"
SCOPE_DIR="/etc/bugbounty/scopes"
STATE_DIR="/var/lib/bugbounty/state"
EVIDENCE_DIR="/var/lib/bugbounty/evidence"
CONFIG_MAY_HAVE_CHANGED=0
ARTIFACTS_CLEANED=0
TEMP_DIR=""
AGENT_TMP=""
ENDPOINT_FILE=""
FIXTURE_TOKEN_FILE=""
TUNNEL_PID=""
CLOUDFLARED_REPO_ADDED=0
VERIFY_DIR=""
PROBE_COPY=""
VERIFY_RESULT=""
PROGRAM_ID=""
SCOPE_DEST=""
RESULT_FILE=""

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ensure_cloudflared() {
    if command -v cloudflared >/dev/null 2>&1; then return 0; fi
    grep -q '^ID=kali$' /etc/os-release || fail "Automatic cloudflared installation is limited to Kali; install cloudflared manually on this Linux host."
    command -v curl >/dev/null 2>&1 || fail "curl is required to fetch Cloudflare's signing key."
    command -v apt-get >/dev/null 2>&1 || fail "apt-get is required to install cloudflared on Kali."

    local key_file=/usr/share/keyrings/cloudflare-main.gpg
    local repo_file=/etc/apt/sources.list.d/cloudflared.list
    if [[ ! -e "$key_file" && ! -L "$key_file" && ! -e "$repo_file" && ! -L "$repo_file" ]]; then
        echo "cloudflared is not installed. The next step adds Cloudflare's signed apt source and installs its tunnel client."
        echo "The apt source and signing key will remain so you can receive package updates."
        read -r -p "Type INSTALL-CLOUDFLARED-FROM-CLOUDFLARE to continue: " install_confirmation
        [[ "$install_confirmation" == "INSTALL-CLOUDFLARED-FROM-CLOUDFLARE" ]] || fail "cloudflared installation was not confirmed."
        CLOUDFLARED_REPO_ADDED=1
        local key_tmp repo_tmp
        key_tmp="$(mktemp /tmp/bb-aud08-cloudflare-key.XXXXXXXX)"
        repo_tmp="$(mktemp /tmp/bb-aud08-cloudflare-repo.XXXXXXXX)"
        if ! curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o "$key_tmp" || [[ ! -s "$key_tmp" ]]; then
            rm -f -- "$key_tmp" "$repo_tmp"
            fail "Could not download Cloudflare's package signing key."
        fi
        printf '%s\n' 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' >"$repo_tmp"
        install -d -o root -g root -m 0755 /usr/share/keyrings
        install -o root -g root -m 0644 "$key_tmp" "$key_file"
        install -o root -g root -m 0644 "$repo_tmp" "$repo_file"
        rm -f -- "$key_tmp" "$repo_tmp"
    elif [[ -L "$key_file" || -L "$repo_file" || ! -f "$key_file" || ! -f "$repo_file" ]]; then
        fail "A partial Cloudflare apt setup exists; inspect $key_file and $repo_file before continuing."
    elif ! grep -Fxq 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' "$repo_file"; then
        fail "Existing Cloudflare apt source does not match the expected signed repository entry."
    elif [[ "$(stat -c '%U:%a' "$key_file")" != root:644 || "$(stat -c '%U:%a' "$repo_file")" != root:644 ]]; then
        fail "Existing Cloudflare apt key/source must be root-owned and mode 0644."
    fi

    echo "[*] Installing cloudflared from Cloudflare's signed package repository..."
    apt-get update
    apt-get install -y cloudflared
    command -v cloudflared >/dev/null 2>&1 || fail "cloudflared package installation completed without an executable on PATH."
    CLOUDFLARED_REPO_ADDED=0
}

status_is_ready() {
    local expected="$1"
    /usr/bin/python3 "${REPO_DIR}/scripts/bb-dispatcher" --status --socket "$SOCKET" \
        | /usr/bin/python3 -c 'import json,sys; r=json.load(sys.stdin).get("receipt") or {}; ready=r.get("production_dispatch_ready") is True and r.get("is_lab") is False and bool(r.get("program_id")); expected=sys.argv[1] == "true"; sys.exit(0 if ready == expected else 1)' "$expected"
}

restore_dispatcher_configuration() {
    [[ "$CONFIG_MAY_HAVE_CHANGED" == 1 ]] || return 0
    echo "[*] Removing only this temporary program configuration and restoring unconfigured dispatcher status..."
    rm -f -- "$CONFIG_FILE" "$APPROVAL_KEY"
    if [[ -n "$SCOPE_DEST" ]]; then
        rm -f -- "$SCOPE_DEST"
    fi
    systemctl restart "$SERVICE"
    systemctl is-active --quiet "$SERVICE"
    status_is_ready false || return 1
    CONFIG_MAY_HAVE_CHANGED=0
    echo "[+] Dispatcher is back to its prior fail-closed, unconfigured state."
}

stop_tunnel() {
    [[ -n "$TUNNEL_PID" ]] || return 0
    if kill -0 "$TUNNEL_PID" 2>/dev/null; then
        echo "[*] Stopping the local fixture and temporary Cloudflare tunnel..."
        kill -TERM "$TUNNEL_PID" 2>/dev/null || true
        for _ in $(seq 1 30); do
            kill -0 "$TUNNEL_PID" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$TUNNEL_PID" 2>/dev/null; then
            kill -KILL "$TUNNEL_PID" 2>/dev/null || true
        fi
    fi
    wait "$TUNNEL_PID" 2>/dev/null || true
    TUNNEL_PID=""
}

on_exit() {
    local result=$?
    trap - EXIT INT TERM HUP
    stop_tunnel
    if [[ "$CONFIG_MAY_HAVE_CHANGED" == 1 ]]; then
        restore_dispatcher_configuration || {
            echo "[!] Could not fully restore the dispatcher configuration. Run the cleanup commands printed in the audit guide before using it." >&2
            result=1
        }
    fi
    if [[ "$CLOUDFLARED_REPO_ADDED" == 1 ]]; then
        echo "[!] cloudflared setup did not complete; removing only the apt source and key added by this run."
        rm -f -- /etc/apt/sources.list.d/cloudflared.list /usr/share/keyrings/cloudflare-main.gpg
    fi
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        case "$TEMP_DIR" in
            /tmp/bb-aud08-root.*) rm -rf -- "$TEMP_DIR" ;;
            *) echo "[!] Preserving unexpected temporary path: $TEMP_DIR" >&2; result=1 ;;
        esac
    fi
    if [[ "$result" -ne 0 && "$ARTIFACTS_CLEANED" != 1 ]]; then
        echo "[!] Acceptance did not complete. Protected dispatcher evidence/state will be preserved for manual review." >&2
    fi
    exit "$result"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

[[ -n "$AGENT_USER" && "$AGENT_USER" != root ]] || fail "A non-root agent username is required."
[[ $# -le 1 ]] || fail "Usage: sudo bash scripts/verify-dispatcher-acceptance.sh <agent-user>"
getent passwd "$AGENT_USER" >/dev/null || fail "Agent user '$AGENT_USER' does not exist."
[[ -n "${SUDO_USER:-}" && "$AGENT_USER" == "$SUDO_USER" ]] || fail "Run with sudo from the agent account and pass that same username."
id -nG "$AGENT_USER" | tr ' ' '\n' | grep -Fxq bbgroup || fail "Agent user must be in bbgroup; run the dispatcher installer first."

[[ "$(uname -s)" == Linux ]] || fail "This acceptance runner supports Linux only."

[[ -d "$REPO_DIR/.git" ]] || fail "Run from the Git checkout, not a copied directory."
[[ -z "$(git -C "$REPO_DIR" status --porcelain)" ]] || fail "Repository has local changes; commit or stash them before installing runtime code."
[[ -f "$REPO_DIR/systemd/bugbounty-dispatcher.service" ]] || fail "Repository systemd unit is missing."
[[ -f /etc/systemd/system/bugbounty-dispatcher.service ]] || fail "Dispatcher service is not installed. Install it first."
cmp -s "$REPO_DIR/systemd/bugbounty-dispatcher.service" /etc/systemd/system/bugbounty-dispatcher.service \
    || fail "Installed unit differs from the repository unit; reconcile it before acceptance."
systemctl is-active --quiet "$SERVICE" || fail "Dispatcher service is not active."
[[ ! -e "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]] || fail "Existing dispatcher.env found; refusing to overwrite existing program configuration."
[[ ! -e "$APPROVAL_KEY" && ! -L "$APPROVAL_KEY" ]] || fail "Existing operator key found; refusing to overwrite it."
[[ -d "$STATE_DIR" && -d "$EVIDENCE_DIR" ]] || fail "Protected dispatcher state/evidence directories are missing."
[[ -z "$(find "$STATE_DIR" -mindepth 1 -print -quit)" ]] || fail "Dispatcher state is not empty; refusing to mix acceptance state with existing state."
[[ -z "$(find "$EVIDENCE_DIR" -mindepth 1 -print -quit)" ]] || fail "Dispatcher evidence is not empty; refusing to mix acceptance evidence with existing data."
ensure_cloudflared

TEMP_DIR="$(mktemp -d /tmp/bb-aud08-root.XXXXXXXX)"
chmod 0711 "$TEMP_DIR"
AGENT_TMP="${TEMP_DIR}/agent"
VERIFY_DIR="${TEMP_DIR}/verify"
install -d -o "$AGENT_USER" -g "$(id -gn "$AGENT_USER")" -m 0700 "$AGENT_TMP"
install -d -o _bbdispatcher -g bbgroup -m 0750 "$VERIFY_DIR"
PROBE_COPY="${VERIFY_DIR}/dispatcher_acceptance_probe.py"
VERIFY_RESULT="${VERIFY_DIR}/result.json"
AGENT_GROUP="$(id -gn "$AGENT_USER")"
KEY_SOURCE="${AGENT_TMP}/operator_approval.key"
SCOPE_SOURCE="${AGENT_TMP}/scope.yaml"
RESULT_FILE="${AGENT_TMP}/result.json"
ENDPOINT_FILE="${AGENT_TMP}/endpoint.txt"
FIXTURE_TOKEN_FILE="${AGENT_TMP}/fixture.token"
PROGRAM_ID="bb-aud08-$(date -u +%Y%m%d%H%M%S)-$$"
SCOPE_DEST="${SCOPE_DIR}/${PROGRAM_ID}.yaml"
[[ ! -e "$SCOPE_DEST" && ! -L "$SCOPE_DEST" ]] || fail "Temporary scope path already exists."

/usr/bin/python3 - "$KEY_SOURCE" "$FIXTURE_TOKEN_FILE" <<'PY'
import os, secrets, sys
for path, value in ((sys.argv[1], secrets.token_bytes(32)), (sys.argv[2], ("AUD08-" + secrets.token_hex(16)).encode("ascii"))):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
PY
chown "$AGENT_USER:$AGENT_GROUP" "$KEY_SOURCE" "$FIXTURE_TOKEN_FILE"
chmod 0600 "$KEY_SOURCE" "$FIXTURE_TOKEN_FILE"

echo "[*] Updating the installed dispatcher runtime from this clean checkout..."
SUDO_USER="$AGENT_USER" bash "${REPO_DIR}/scripts/install-dispatcher.sh"
cmp -s "$REPO_DIR/framework/auth_correlation/ipc/service.py" /opt/BugBounty-Agent/framework/auth_correlation/ipc/service.py \
    || fail "Installed dispatcher service code does not match this checkout."
cmp -s "$REPO_DIR/framework/common/evidence.py" /opt/BugBounty-Agent/framework/common/evidence.py \
    || fail "Installed evidence code does not match this checkout."

echo "[*] Rechecking service identity, key/data separation, and invalid-approval rejection..."
bash "${REPO_DIR}/tests/verify-dispatcher-isolation.sh" "$AGENT_USER"

echo
echo "AUD-08 acceptance plan"
echo "  Program:  $PROGRAM_ID (temporary)"
echo "  Fixture:  a minimal service bound only to Kali loopback"
echo "  Tunnel:   temporary public Cloudflare Quick Tunnel, stopped automatically"
echo "  Requests: exactly one approved POST, one verification GET, then replay rejection"
echo "  Data:     synthetic one-use bearer only; no user account or bounty target"
echo "  Cleanup:  remove the temporary program, key, fixture state, and tunnel"
echo
echo "WARNING: anyone who learns the temporary trycloudflare.com URL can reach the fixture while the tunnel runs."
echo "The fixture responds only to the random AUD08 token and dispatch correlation headers."
echo
read -r -p "Type START-TEMPORARY-CLOUDFLARE-TUNNEL to expose this fixture briefly: " confirmation
[[ "$confirmation" == "START-TEMPORARY-CLOUDFLARE-TUNNEL" ]] || fail "Temporary tunnel exposure was not confirmed."

TUNNEL_LOG="${AGENT_TMP}/tunnel.log"
install -o "$AGENT_USER" -g "$AGENT_GROUP" -m 0600 /dev/null "$TUNNEL_LOG"
echo "[*] Starting the loopback-only fixture and temporary public tunnel..."
runuser -u "$AGENT_USER" -- /usr/bin/python3 "${REPO_DIR}/tests/dispatcher_acceptance_tunnel.py" \
    --cloudflared "$(command -v cloudflared)" --fixture-token-file "$FIXTURE_TOKEN_FILE" \
    --endpoint-file "$ENDPOINT_FILE" >>"$TUNNEL_LOG" 2>&1 &
TUNNEL_PID=$!
for _ in $(seq 1 300); do
    if [[ -s "$ENDPOINT_FILE" ]]; then break; fi
    if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
        cat "$TUNNEL_LOG" >&2
        fail "The local fixture/tunnel process stopped before producing its URL."
    fi
    sleep 0.2
done
[[ -s "$ENDPOINT_FILE" ]] || { cat "$TUNNEL_LOG" >&2; fail "Timed out waiting for the temporary tunnel URL."; }
ENDPOINT="$(cat "$ENDPOINT_FILE")"

ENDPOINT="$(/usr/bin/python3 - "$ENDPOINT" "$SCOPE_SOURCE" "$PROGRAM_ID" <<'PY'
import ipaddress
import re
import socket
import sys
import time
from urllib.parse import urlsplit, urlunsplit
import yaml

raw, scope_path, program_id = sys.argv[1:]
parsed = urlsplit(raw)
if parsed.scheme.lower() != "https" or not parsed.hostname:
    raise SystemExit("Endpoint must be an absolute HTTPS URL.")
if parsed.username or parsed.password or parsed.query or parsed.fragment:
    raise SystemExit("Endpoint must not contain credentials, query parameters, or a fragment.")
if parsed.port not in (None, 443):
    raise SystemExit("Endpoint must use standard HTTPS port 443.")
host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
if not host.endswith(".trycloudflare.com"):
    raise SystemExit("Tunnel endpoint is not a Cloudflare Quick Tunnel hostname.")
if "." not in host or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
    raise SystemExit("Endpoint must use a public fully-qualified DNS hostname.")
try:
    ipaddress.ip_address(host)
except ValueError:
    pass
else:
    raise SystemExit("Use a public DNS hostname with valid HTTPS, not an IP literal.")
labels = host.split(".")
if len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
    raise SystemExit("Endpoint hostname is not a valid DNS name.")
path = parsed.path or "/"
endpoint = urlunsplit(("https", host, path, "", ""))
addresses = set()
last_error = None
for _ in range(30):
    try:
        addresses = {ipaddress.ip_address(item[4][0].split("%", 1)[0]) for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
        if addresses:
            break
    except (OSError, ValueError) as exc:
        last_error = exc
    time.sleep(0.5)
if not addresses or any(not address.is_global for address in addresses):
    if not addresses:
        raise SystemExit(f"Could not resolve the temporary tunnel hostname: {last_error or 'no DNS answers'}")
    raise SystemExit("Every resolved address must be globally routable; private/reserved DNS answers are refused.")
scope = {
    "program": {"name": program_id},
    "authorization": {"source": "Researcher-operated loopback fixture through a temporary Cloudflare Quick Tunnel"},
    "targets": {"urls": [endpoint]},
    "out_of_scope": {"urls": []},
}
with open(scope_path, "x", encoding="utf-8") as stream:
    yaml.safe_dump(scope, stream, sort_keys=False)
print(endpoint)
PY
)" || fail "Could not validate the endpoint or create the temporary scope."
chown "$AGENT_USER:$AGENT_GROUP" "$SCOPE_SOURCE"
chmod 0600 "$SCOPE_SOURCE"
echo "[+] Temporary fixture URL: $ENDPOINT"
echo "[*] Provisioning the temporary exact-URL scope and disposable 32-byte operator key..."
CONFIG_MAY_HAVE_CHANGED=1
bash "${REPO_DIR}/scripts/configure-dispatcher-program.sh" "$PROGRAM_ID" "$SCOPE_SOURCE" "$KEY_SOURCE"
status_is_ready true || fail "Temporary dispatcher configuration did not reach production-ready status."

echo "[*] Verifying that a malformed operator approval is rejected before transport..."
runuser -u "$AGENT_USER" -- /usr/bin/python3 "${REPO_DIR}/tests/dispatcher_ipc_probe.py" "$SOCKET"

echo "[*] Running one approved action through the installed, non-lab systemd service..."
runuser -u "$AGENT_USER" -- env PYTHONPATH="$REPO_DIR" /usr/bin/python3 \
    "${REPO_DIR}/tests/dispatcher_acceptance_probe.py" execute \
    --program-id "$PROGRAM_ID" --endpoint "$ENDPOINT" --scope-file "$SCOPE_DEST" \
    --approval-key "$KEY_SOURCE" --fixture-token-file "$FIXTURE_TOKEN_FILE" --result-file "$RESULT_FILE"

stop_tunnel
[[ ! -e "$ENDPOINT_FILE" ]] || fail "Temporary tunnel supervisor did not remove its endpoint marker."

echo "[*] Preparing service-identity evidence verification..."
install -o _bbdispatcher -g bbgroup -m 0440 \
    "${REPO_DIR}/tests/dispatcher_acceptance_probe.py" "$PROBE_COPY"
install -o _bbdispatcher -g bbgroup -m 0600 "$RESULT_FILE" "$VERIFY_RESULT"

echo "[*] Independently verifying receipt, evidence bytes, approval consumption, and replay nonce state..."
runuser -u _bbdispatcher -- env PYTHONPATH=/opt/BugBounty-Agent /usr/bin/python3 "$PROBE_COPY" verify \
    --program-id "$PROGRAM_ID" --endpoint "$ENDPOINT" --result-file "$VERIFY_RESULT"

echo "[*] Removing only the verified temporary evidence and dispatcher state..."
runuser -u _bbdispatcher -- env PYTHONPATH=/opt/BugBounty-Agent /usr/bin/python3 "$PROBE_COPY" cleanup \
    --program-id "$PROGRAM_ID" --endpoint "$ENDPOINT" --result-file "$VERIFY_RESULT"
ARTIFACTS_CLEANED=1

restore_dispatcher_configuration || fail "Could not restore the dispatcher to its prior unconfigured status."
CONFIG_MAY_HAVE_CHANGED=0
bash "${REPO_DIR}/tests/verify-dispatcher-isolation.sh" "$AGENT_USER"

echo
echo "PASS: AUD-08 installed-service acceptance completed and temporary configuration/data were removed."
echo "PASS: service signing key and pre-existing dispatcher directories were preserved."
echo "No bounty target was contacted. The one-use local fixture was exposed only through the stopped temporary Cloudflare tunnel."
