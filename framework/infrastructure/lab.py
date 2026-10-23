"""
Local Infrastructure Test Lab for BugBounty-Agent.

Provides an isolated, in-process HTTP test server on an ephemeral loopback port
implementing all 16 deterministic scenarios specified in docs/PHASE-19-PLAN.md:
- 100% offline and deterministic.
- Zero external network dependencies.
- Instruments bytes transferred to verify stream stopping rules.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from framework.scope.engine import ScopeEngine


class InfrastructureLabHandler(BaseHTTPRequestHandler):
    """HTTP request handler supporting all 16 lab scenarios."""

    # Server-wide byte consumption tracking
    total_bytes_sent = 0

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress standard HTTP server logging during tests."""
        pass

    def do_GET(self) -> None:
        """Handles GET requests across the 16 scenarios."""
        path = self.path.split("?")[0]

        # Scenario 2: SCENARIO_GIT_HEAD_SPA_CATCHALL (Catch-all returns SPA HTML for any path)
        if path.startswith("/scenario/spa-catchall/"):
            self._send_spa_html()
            return

        # Scenario 3: SCENARIO_GIT_HEAD_SPA_DISTINCT
        if path == "/scenario/spa-distinct/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self._write_counted(b"ref: refs/heads/main\n")
            return
        elif path.startswith("/scenario/spa-distinct/"):
            self._send_spa_html()
            return

        # Scenario 6: SCENARIO_ENV_HTML_DYNAMIC_404
        if path.startswith("/scenario/dynamic-404/"):
            self._send_dynamic_404()
            return

        # Differential baseline path: /__bb_differential_baseline_...
        if "/__bb_differential_baseline_" in path:
            # Baseline behavior can be conditioned via custom header or path context
            if self.headers.get("X-Lab-Mode") == "spa_catchall":
                self._send_spa_html()
            elif self.headers.get("X-Lab-Mode") == "dynamic_404":
                self._send_dynamic_404()
            elif self.headers.get("X-Lab-Mode") == "redirect_catchall":
                self._send_redirect("/error-landing")
            else:
                self.send_response(404)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self._write_counted(b"404 Not Found")
            return

        # Scenario 1: SCENARIO_GIT_HEAD_EXPOSED
        if path == "/scenario/git-head/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self._write_counted(b"ref: refs/heads/main\n")
            return

        # Scenario 2: SCENARIO_GIT_HEAD_SPA_CATCHALL
        if path.startswith("/scenario/spa-catchall/"):
            self._send_spa_html()
            return

        # Scenario 3: SCENARIO_GIT_HEAD_SPA_DISTINCT
        if path == "/scenario/spa-distinct/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self._write_counted(b"ref: refs/heads/main\n")
            return
        elif path.startswith("/scenario/spa-distinct/"):
            self._send_spa_html()
            return

        # Scenario 4: SCENARIO_ENV_EXPOSED_SENSITIVE
        if path == "/scenario/env-sensitive/.env":
            content = (
                b"APP_NAME=SuperApp\n"
                b"DB_PASSWORD=SuperSecretSentinelP@ss123\n"
                b"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYSENTINELKEY\n"
                b"APP_ENV=production\n"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self._write_counted(content)
            return

        # Scenario 5: SCENARIO_ENV_NON_SENSITIVE
        if path == "/scenario/env-benign/.env":
            content = (
                b"APP_NAME=PublicDemo\n"
                b"APP_ENV=local\n"
                b"LOG_CHANNEL=stack\n"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self._write_counted(content)
            return

        # Scenario 6: SCENARIO_ENV_HTML_DYNAMIC_404
        if path.startswith("/scenario/dynamic-404/"):
            self._send_dynamic_404()
            return

        # Scenario 7: SCENARIO_BACKUP_ZIP_EXPOSED
        if path == "/scenario/backup/backup.zip":
            # ZIP header: PK\x03\x04 + 500 dummy bytes
            zip_content = b"PK\x03\x04" + b"\x14\x00\x00\x00" + (b"\x00" * 500)
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.end_headers()
            self._write_counted(zip_content)
            return

        # Scenario 8: SCENARIO_ACTUATOR_HEALTH_SAFE
        if path == "/scenario/actuator/actuator/health":
            body = json.dumps({"status": "UP", "components": {"diskSpace": {"status": "UP"}}}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._write_counted(body)
            return
        elif path == "/scenario/actuator/actuator/env":
            # Secret actuator endpoint: asserts that engine NEVER queries this!
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._write_counted(b'{"error":"UNAUTHORIZED_ACCESS_ATTEMPT"}')
            return

        # Scenario 9: SCENARIO_ADMIN_LOGIN_FORM
        if path == "/scenario/admin/login":
            form_html = (
                b"<!DOCTYPE html><html><body>"
                b"<h1>Administrative Portal</h1>"
                b'<form action="/admin/login" method="post">'
                b'<input type="text" name="username">'
                b'<input type="password" name="password">'
                b'<button type="submit">Sign In</button>'
                b"</form></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self._write_counted(form_html)
            return

        # Scenario 10: SCENARIO_HTTP_403_ACCESS_RESTRICTED
        if path == "/scenario/restricted/secret-admin":
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self._write_counted(b"<html><body><h1>403 Forbidden - Access Denied</h1></body></html>")
            return

        # Scenario 11: SCENARIO_DIRECTORY_LISTING
        if path == "/scenario/directory/uploads/":
            listing_html = (
                b"<!DOCTYPE html><html><head><title>Index of /uploads</title></head>"
                b"<body><h1>Index of /uploads</h1><hr><pre>"
                b'<a href="../">[To Parent Directory]</a>\n'
                b'<a href="test.pdf">test.pdf</a>    2026-01-01 12:00    1024\n'
                b'<a href="secret.bak">secret.bak</a>  2026-01-02 14:00    2048\n'
                b"</pre><hr></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self._write_counted(listing_html)
            return

        # Scenario 12: SCENARIO_SOURCE_MAP_EXPOSED
        if path == "/scenario/sourcemap/app.js.map":
            smap = json.dumps({
                "version": 3,
                "file": "app.js",
                "sources": ["src/index.ts", "src/auth.ts", "src/config.ts"],
                "mappings": "AAAA;...",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._write_counted(smap)
            return

        # Scenario 14: SCENARIO_STREAMING_STOPPING_RULE (Oversized 10 MB payload)
        if path == "/scenario/streaming/large-backup.zip":
            # Sends PK\x03\x04 followed by massive stream
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(10 * 1024 * 1024)) # 10 MB
            self.end_headers()
            self._write_counted(b"PK\x03\x04" + (b"A" * 1020))
            # Continue sending in chunks if client keeps reading
            chunk = b"B" * 8192
            for _ in range(1280): # Up to 10 MB
                try:
                    self._write_counted(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    break
            return

        if path == "/scenario/streaming/large-config.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(1024 * 1024)) # 1 MB
            self.end_headers()
            self._write_counted(b"APP_NAME=LargeApp\nDB_PASS=secret123\n")
            chunk = b"KEY_VAR=value_line_data_padding\n" * 256
            for _ in range(128):
                try:
                    self._write_counted(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    break
            return

        # Default 404 for any unmatched scenario path
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self._write_counted(b"Scenario path not found")

    def _write_counted(self, data: bytes) -> None:
        """Writes bytes to socket and increments count."""
        InfrastructureLabHandler.total_bytes_sent += len(data)
        self.wfile.write(data)

    def _send_spa_html(self) -> None:
        """Sends SPA index.html catch-all response."""
        spa_html = (
            b"<!DOCTYPE html><html><head><title>SPA Application</title></head>"
            b'<body><div id="root">Single Page Application Shell</div>'
            b'<script src="/app.js"></script></body></html>'
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self._write_counted(spa_html)

    def _send_dynamic_404(self) -> None:
        """Sends dynamic 200 error page with variable nonces and timestamps."""
        t_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        nonce_val = f"lab_nonce_{int(time.time() * 1000)}"
        html = (
            f"<!DOCTYPE html><html><head><title>Page Not Found</title></head>"
            f"<body><h1>Custom 404</h1>"
            f"<p>Timestamp: {t_str}</p>"
            f'<div nonce="{nonce_val}">Resource does not exist</div>'
            f"</body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self._write_counted(html)

    def _send_redirect(self, target_path: str) -> None:
        """Sends redirect catch-all response."""
        self.send_response(302)
        self.send_header("Location", target_path)
        self.end_headers()
        self._write_counted(b"Redirecting...")


class LocalInfrastructureLab:
    """
    Manages lifecycle of the isolated in-process test fixture server.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.server = HTTPServer((self.host, port), InfrastructureLabHandler)
        self.port = self.server.server_port
        self.thread: Optional[threading.Thread] = None

    def start(self) -> str:
        """Starts server in background thread and returns base URL."""
        InfrastructureLabHandler.total_bytes_sent = 0
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://{self.host}:{self.port}"

    def stop(self) -> None:
        """Stops and cleans up the HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

    def get_total_bytes_sent(self) -> int:
        """Returns total bytes transmitted by the test server."""
        return InfrastructureLabHandler.total_bytes_sent

    @classmethod
    def get_scope_engine(cls, port: Optional[int] = None) -> ScopeEngine:
        """Returns a ScopeEngine explicitly authorizing local lab fixture targets."""
        port_str = f":{port}" if port else ""
        return ScopeEngine({
            "program": {"name": "local-infra-lab"},
            "targets": {
                "domains": ["127.0.0.1", "localhost"],
                "urls": [
                    f"http://127.0.0.1{port_str}/",
                    f"http://localhost{port_str}/",
                    "http://127.0.0.1/",
                ],
                "cidrs": ["127.0.0.1/32"],
            },
        })
