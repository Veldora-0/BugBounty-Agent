#!/usr/bin/env python3
"""Serve the narrowly scoped AUD-08 fixture through an ephemeral Cloudflare tunnel."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


SESSION_RE = re.compile(r"sess_[a-f0-9]{32}\Z")
ACTION_RE = re.compile(r"ACT-[A-Fa-f0-9]{64}\Z")
DISPATCH_RE = re.compile(r"DISP-OP-[A-Fa-f0-9]{64}\Z")
TOKEN_RE = re.compile(r"AUD08-[a-f0-9]{32}\Z")
TUNNEL_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com\b")


def read_private_token(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Fixture token must be a regular, non-symlink file")
    if path.stat().st_mode & 0o077:
        raise ValueError("Fixture token must have private permissions (0600)")
    token = path.read_text(encoding="ascii").strip()
    if not TOKEN_RE.fullmatch(token):
        raise ValueError("Fixture token has an invalid format")
    return token


def make_handler(token: str):
    sessions: dict[str, tuple[str, str, str]] = {}
    lock = threading.Lock()
    post_count = 0

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *_args: object) -> None:
            # Do not log public URLs, correlation identifiers, or authorization headers.
            return

        def _matches(self, *, verification: bool = False) -> tuple[str, str, str] | None:
            auth = self.headers.get("Authorization", "")
            session = self.headers.get("X-Correlation-Session", "")
            action = self.headers.get("X-Correlation-Action", "")
            principal = self.headers.get("X-Correlation-Principal", "")
            dispatch = self.headers.get("X-Correlation-Dispatch", "")
            if auth != f"Bearer {token}" or not SESSION_RE.fullmatch(session):
                return None
            if not ACTION_RE.fullmatch(action) or principal != "aud08-acceptance":
                return None
            if verification:
                if not dispatch.endswith("-VERIFY") or not DISPATCH_RE.fullmatch(dispatch[:-7]):
                    return None
                dispatch = dispatch[:-7]
            elif not DISPATCH_RE.fullmatch(dispatch):
                return None
            return session, action, dispatch

        def _reply(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            if body:
                self.wfile.write(body)
            self.close_connection = True

        def do_POST(self) -> None:
            nonlocal post_count
            if self.path != "/":
                self._reply(404, b"not found")
                return
            identity = self._matches()
            try:
                body_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                body_length = -1
            if identity is None or body_length != 0:
                self._reply(404, b"not found")
                return
            with lock:
                if post_count != 0:
                    self._reply(409, b"fixture already used")
                    return
                post_count += 1
                sessions[identity[0]] = (token, identity[1], identity[2])
            body = json.dumps({"status": "logged_out", "revoked": True}).encode("ascii")
            self._reply(200, body, "application/json")

        def do_GET(self) -> None:
            if self.path != "/":
                self._reply(404, b"not found")
                return
            identity = self._matches(verification=True)
            if identity is None:
                self._reply(404, b"not found")
                return
            with lock:
                expected = sessions.pop(identity[0], None)
            if expected != (token, identity[1], identity[2]):
                self._reply(404, b"not found")
                return
            self._reply(403, b"session revoked")

        def do_HEAD(self) -> None:
            self._reply(404, b"")

        def do_PUT(self) -> None:
            self._reply(404, b"not found")

        def do_DELETE(self) -> None:
            self._reply(404, b"not found")

        def do_OPTIONS(self) -> None:
            self._reply(404, b"not found")

    return Handler


def _write_endpoint(path: Path, endpoint: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(endpoint + "\n")
    os.replace(temporary, path)


def run(args: argparse.Namespace) -> int:
    token = read_private_token(Path(args.fixture_token_file))
    endpoint_file = Path(args.endpoint_file)
    if endpoint_file.exists() or endpoint_file.is_symlink():
        raise ValueError("Endpoint output path already exists")

    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(token))
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    stopped = threading.Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    tunnel: subprocess.Popen[str] | None = None
    try:
        command = [
            args.cloudflared,
            "tunnel",
            "--no-autoupdate",
            "--url",
            f"http://127.0.0.1:{server.server_port}",
        ]
        tunnel = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        endpoint_ready = threading.Event()
        reader_errors: list[str] = []

        def read_tunnel_output() -> None:
            assert tunnel is not None and tunnel.stdout is not None
            try:
                for line in tunnel.stdout:
                    match = TUNNEL_RE.search(line)
                    if match and not endpoint_ready.is_set():
                        _write_endpoint(endpoint_file, match.group(0))
                        endpoint_ready.set()
            except Exception as exc:
                reader_errors.append(str(exc))

        reader = threading.Thread(target=read_tunnel_output, daemon=True)
        reader.start()
        print(f"[*] Local fixture listening on 127.0.0.1:{server.server_port}", flush=True)
        print("[*] Waiting for Cloudflare Quick Tunnel URL (up to 60 seconds)...", flush=True)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not stopped.is_set():
            if endpoint_ready.is_set():
                print("[+] Temporary HTTPS tunnel is ready.", flush=True)
                break
            if tunnel.poll() is not None:
                raise RuntimeError(f"cloudflared exited with status {tunnel.returncode}")
            if reader_errors:
                raise RuntimeError(f"Could not read cloudflared output: {reader_errors[0]}")
            time.sleep(0.2)
        if not endpoint_ready.is_set():
            raise RuntimeError("cloudflared did not provide a Quick Tunnel URL within 60 seconds")

        while not stopped.is_set() and tunnel.poll() is None:
            time.sleep(0.25)
    finally:
        if tunnel is not None and tunnel.poll() is None:
            tunnel.terminate()
            try:
                tunnel.wait(timeout=5)
            except subprocess.TimeoutExpired:
                tunnel.kill()
                tunnel.wait(timeout=5)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
        if endpoint_file.exists() and not endpoint_file.is_symlink():
            endpoint_file.unlink()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cloudflared", required=True)
    parser.add_argument("--fixture-token-file", required=True)
    parser.add_argument("--endpoint-file", required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
