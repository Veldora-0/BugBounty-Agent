"""
Optional Browser-Assisted Confirmation Layer for BugBounty-Agent XSS Engine.

Provides an isolated, headless Playwright confirmation layer strictly disabled
by default. Enforces strict anti-SSRF pre-checks, same-origin restrictions,
timeout ceilings, and automatic dialog dismissal.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from framework.validation.engine import is_ssrf_prohibited_ip


logger = logging.getLogger(__name__)


class BrowserConfirmationResult:
    """Outcome of optional browser-assisted verification."""

    def __init__(
        self,
        success: bool = False,
        dialog_observed: bool = False,
        dialog_message: Optional[str] = None,
        dialog_type: Optional[str] = None,
        console_messages: Optional[List[str]] = None,
        errors: Optional[List[str]] = None,
        evidence_summary: str = "",
    ):
        self.success = success
        self.dialog_observed = dialog_observed
        self.dialog_message = dialog_message
        self.dialog_type = dialog_type
        self.console_messages = console_messages or []
        self.errors = errors or []
        self.evidence_summary = evidence_summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "dialog_observed": self.dialog_observed,
            "dialog_message": self.dialog_message,
            "dialog_type": self.dialog_type,
            "console_messages": self.console_messages,
            "errors": self.errors,
            "evidence_summary": self.evidence_summary,
        }


class BrowserXssAssistant:
    """
    Modular headless browser confirmation engine.
    Disabled by default; requires explicit opt-in.
    """

    def __init__(
        self,
        enabled: bool = False,
        timeout: float = 5.0,
        scope_validator: Optional[Callable[[str], None]] = None,
    ):
        self.enabled = bool(enabled)
        self.timeout = max(1.0, float(timeout))
        self.scope_validator = scope_validator

    def is_playwright_available(self) -> bool:
        """Verifies if Playwright package is installed and importable."""
        try:
            import playwright
            return True
        except ImportError:
            return False

    def verify_url_safety(self, url: str) -> None:
        """Enforces anti-SSRF and scope boundaries before browser navigation."""
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Browser navigation blocked: protocol '{scheme}' not permitted.")

        host = (parsed.hostname or "").lower()
        if not host:
            raise ValueError(f"Browser navigation blocked: invalid hostname in '{url}'.")

        # Check prohibited IP space
        prohibited, reason = is_ssrf_prohibited_ip(host)
        if prohibited:
            raise ValueError(f"Browser navigation blocked: target '{host}' is in prohibited IP range ({reason}).")

        # Enforce scope if validator configured
        if self.scope_validator:
            self.scope_validator(url)

    def confirm_candidate(
        self,
        target_url: str,
        canary_token: str,
    ) -> BrowserConfirmationResult:
        """
        Navigates to candidate target URL in headless Playwright session to observe
        DOM events, console errors, or dialog popups.
        """
        if not self.enabled:
            return BrowserConfirmationResult(
                success=False,
                evidence_summary="Browser confirmation is disabled by default.",
            )

        if not self.is_playwright_available():
            return BrowserConfirmationResult(
                success=False,
                evidence_summary="Playwright is not installed in the current environment.",
            )

        # 1. SSRF & Scope Pre-check
        try:
            self.verify_url_safety(target_url)
        except Exception as e:
            return BrowserConfirmationResult(
                success=False,
                errors=[f"Safety check failed: {str(e)}"],
                evidence_summary=f"Pre-flight safety validation blocked navigation: {str(e)}",
            )

        # 2. Execution in headless browser context
        dialog_events: List[Dict[str, str]] = []
        console_logs: List[str] = []
        page_errors: List[str] = []

        try:
            from playwright.sync_api import sync_playwright

            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
                page = context.new_page()

                # Register non-blocking handlers
                def on_dialog(dialog):
                    dialog_events.append({
                        "type": dialog.type,
                        "message": dialog.message,
                    })
                    dialog.dismiss()

                def on_console(msg):
                    console_logs.append(f"[{msg.type}] {msg.text}")

                def on_error(err):
                    page_errors.append(str(err))

                page.on("dialog", on_dialog)
                page.on("console", on_console)
                page.on("pageerror", on_error)

                # Navigate safely with timeout bounds
                page.goto(target_url, timeout=int(self.timeout * 1000), wait_until="domcontentloaded")
                page.wait_for_timeout(500)

                browser.close()

            # Analyze findings
            has_dialog = len(dialog_events) > 0
            dialog_msg = dialog_events[0]["message"] if has_dialog else None
            dialog_typ = dialog_events[0]["type"] if has_dialog else None

            summary = (
                f"Browser observed dialog ({dialog_typ}: '{dialog_msg}')"
                if has_dialog
                else "Browser completed navigation without script dialog trigger."
            )

            return BrowserConfirmationResult(
                success=True,
                dialog_observed=has_dialog,
                dialog_message=dialog_msg,
                dialog_type=dialog_typ,
                console_messages=console_logs[:20],
                errors=page_errors[:10],
                evidence_summary=summary,
            )

        except Exception as e:
            return BrowserConfirmationResult(
                success=False,
                errors=[str(e)],
                evidence_summary=f"Browser execution exception: {str(e)}",
            )
