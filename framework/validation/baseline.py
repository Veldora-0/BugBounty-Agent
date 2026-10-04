"""
Baseline Observation and Comparison Engine for BugBounty-Agent Security Validation.

Establishes an empirical baseline for untouched endpoints before mutation,
and computes bounded differential signals (status, size, headers, marker reflection,
similarity ratio, error signatures) without treating single differences as automatic proof.
"""

from __future__ import annotations

from datetime import datetime, timezone
import difflib
import hashlib
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from framework.validation.request import ControlledResponse


# Standard error indicators (for informational comparison signals)
GENERIC_ERROR_PATTERNS = [
    re.compile(r"\b(?:syntax error|unexpected token|unclosed quotation|fatal error|internal server error|traceback \(most recent call last\))\b", re.IGNORECASE),
    re.compile(r"\b(?:sql syntax|mysql_fetch|pg_query|sqlite3::|ora-\d{5}|microsoft ole db provider)\b", re.IGNORECASE),
]


class BaselineObservation:
    """Snapshot of untouched endpoint behavior before security mutations."""

    def __init__(
        self,
        endpoint_key: str,
        status_code: int,
        content_type: str,
        response_size: int,
        headers_snapshot: Dict[str, str],
        body_hash: str,
        body_sample: str,
        title: Optional[str] = None,
        elapsed_seconds: float = 0.0,
        timestamp: Optional[str] = None,
    ):
        self.endpoint_key = endpoint_key
        self.status_code = int(status_code)
        self.content_type = content_type.lower()
        self.response_size = int(response_size)
        self.headers_snapshot = {k.lower(): str(v) for k, v in headers_snapshot.items()}
        self.body_hash = body_hash
        self.body_sample = body_sample[:1024]  # Bound to 1024 chars
        self.title = title
        self.elapsed_seconds = float(elapsed_seconds)
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()

    @classmethod
    def from_response(cls, endpoint_key: str, response: ControlledResponse) -> BaselineObservation:
        """Constructs a baseline observation from a ControlledResponse."""
        # Extract title if HTML
        title = None
        if "html" in response.content_type:
            title_match = re.search(r"<title[^>]*>(.*?)</title>", response.body, re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()[:128]

        body_hash = hashlib.sha256(response.body.encode("utf-8")).hexdigest()

        # Capture key security headers
        snap_headers = {}
        for h in ("content-type", "location", "server", "x-frame-options", "content-security-policy", "access-control-allow-origin"):
            if h in response.headers:
                snap_headers[h] = response.headers[h]

        return cls(
            endpoint_key=endpoint_key,
            status_code=response.status_code,
            content_type=response.content_type,
            response_size=response.size_bytes,
            headers_snapshot=snap_headers,
            body_hash=body_hash,
            body_sample=response.body[:1024],
            title=title,
            elapsed_seconds=response.elapsed_seconds,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes baseline to dictionary."""
        return {
            "endpoint_key": self.endpoint_key,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "response_size": self.response_size,
            "headers_snapshot": self.headers_snapshot,
            "body_hash": self.body_hash,
            "body_sample": self.body_sample,
            "title": self.title,
            "elapsed_seconds": self.elapsed_seconds,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BaselineObservation:
        """Deserializes baseline from dictionary."""
        return cls(
            endpoint_key=data.get("endpoint_key", ""),
            status_code=data.get("status_code", 200),
            content_type=data.get("content_type", ""),
            response_size=data.get("response_size", 0),
            headers_snapshot=data.get("headers_snapshot", {}),
            body_hash=data.get("body_hash", ""),
            body_sample=data.get("body_sample", ""),
            title=data.get("title"),
            elapsed_seconds=data.get("elapsed_seconds", 0.0),
            timestamp=data.get("timestamp"),
        )


class BaselineComparison:
    """
    Detailed comparison between baseline observation and post-mutation response.
    Never assumes a single discrepancy automatically proves vulnerability.
    """

    def __init__(
        self,
        status_changed: bool,
        size_delta: int,
        content_type_changed: bool,
        body_similarity: float,
        marker_reflected: bool,
        reflection_context: Optional[str] = None,
        location_header_changed: bool = False,
        redirect_destination: Optional[str] = None,
        error_pattern_detected: bool = False,
        matched_error: Optional[str] = None,
        signals: Optional[List[str]] = None,
        injected_token: Optional[str] = None,
    ):
        self.status_changed = status_changed
        self.size_delta = size_delta
        self.content_type_changed = content_type_changed
        self.body_similarity = float(body_similarity)
        self.marker_reflected = marker_reflected
        self.reflection_context = reflection_context
        self.location_header_changed = location_header_changed
        self.redirect_destination = redirect_destination
        self.error_pattern_detected = error_pattern_detected
        self.matched_error = matched_error
        self.signals = list(signals or [])
        self.injected_token = injected_token

    def to_dict(self) -> Dict[str, Any]:
        """Serializes comparison to dictionary."""
        return {
            "status_changed": self.status_changed,
            "size_delta": self.size_delta,
            "content_type_changed": self.content_type_changed,
            "body_similarity": round(self.body_similarity, 4),
            "marker_reflected": self.marker_reflected,
            "reflection_context": self.reflection_context,
            "location_header_changed": self.location_header_changed,
            "redirect_destination": self.redirect_destination,
            "error_pattern_detected": self.error_pattern_detected,
            "matched_error": self.matched_error,
            "signals": self.signals,
        }


def compare_with_baseline(
    baseline: BaselineObservation,
    response: ControlledResponse,
    test_marker: Optional[str] = None,
) -> BaselineComparison:
    """
    Compares post-mutation response against baseline observation.
    Extracts differential signals, marker reflection, and redirect changes.
    """
    signals: List[str] = []

    # 1. Status comparison
    status_changed = baseline.status_code != response.status_code
    if status_changed:
        signals.append(f"STATUS_CHANGE_{baseline.status_code}_TO_{response.status_code}")

    # 2. Size delta
    size_delta = response.size_bytes - baseline.response_size
    if abs(size_delta) > 50:
        signals.append(f"SIZE_DELTA_{size_delta:+d}")

    # 3. Content-Type comparison
    ct_changed = baseline.content_type != response.content_type
    if ct_changed:
        signals.append(f"CONTENT_TYPE_CHANGE_{baseline.content_type}_TO_{response.content_type}")

    # 4. Body similarity (using bounded samples to prevent heavy CPU load)
    base_sample = baseline.body_sample[:1000]
    resp_sample = response.body[:1000]
    similarity = difflib.SequenceMatcher(None, base_sample, resp_sample).ratio()

    # 5. Marker reflection analysis
    marker_reflected = False
    reflection_ctx = None
    if test_marker and test_marker in response.body:
        marker_reflected = True
        signals.append("MARKER_REFLECTED_IN_BODY")

        # Context detection
        body_str = response.body
        # Check if inside script tag
        script_pattern = re.compile(rf"<script[^>]*>[^<]*?{re.escape(test_marker)}[^<]*?</script>", re.IGNORECASE | re.DOTALL)
        attr_pattern = re.compile(rf"""<[^>]+?(?:href|src|value|name|placeholder|data-[a-z0-9_-]+)\s*=\s*['"][^'"]*?{re.escape(test_marker)}[^'"]*?['"][^>]*>""", re.IGNORECASE)

        if script_pattern.search(body_str):
            reflection_ctx = "SCRIPT_TAG"
            signals.append("REFLECTED_INSIDE_SCRIPT")
        elif attr_pattern.search(body_str):
            reflection_ctx = "HTML_ATTRIBUTE"
            signals.append("REFLECTED_INSIDE_ATTRIBUTE")
        elif "<html" in body_str.lower() or "<body" in body_str.lower():
            reflection_ctx = "HTML_BODY_TEXT"
            signals.append("REFLECTED_IN_HTML_BODY")
        elif "json" in response.content_type:
            reflection_ctx = "JSON_VALUE"
            signals.append("REFLECTED_IN_JSON")
        else:
            reflection_ctx = "RAW_TEXT"
            signals.append("REFLECTED_IN_RAW_TEXT")

    # 6. Redirect Location analysis
    loc_changed = False
    dest = None
    if response.status_code in (301, 302, 303, 307, 308) and response.location_header:
        base_loc = baseline.headers_snapshot.get("location")
        if response.location_header != base_loc:
            loc_changed = True
            dest = response.location_header
            signals.append(f"LOCATION_REDIRECT_{dest}")

    # 7. Error signature detection
    error_detected = False
    matched_err = None
    for pat in GENERIC_ERROR_PATTERNS:
        match = pat.search(response.body)
        if match:
            error_detected = True
            matched_err = match.group(0)[:64]
            signals.append(f"ERROR_PATTERN_{matched_err}")
            break

    return BaselineComparison(
        status_changed=status_changed,
        size_delta=size_delta,
        content_type_changed=ct_changed,
        body_similarity=similarity,
        marker_reflected=marker_reflected,
        reflection_context=reflection_ctx,
        location_header_changed=loc_changed,
        redirect_destination=dest,
        error_pattern_detected=error_detected,
        matched_error=matched_err,
        signals=signals,
        injected_token=test_marker,
    )
