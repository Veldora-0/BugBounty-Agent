"""
Controlled Request and Response Abstractions for BugBounty-Agent Security Validation.

Supports precise, deterministic mutation of a single selected parameter or component
(query, path, header, cookie, JSON body, form body) without altering other fields.
"""

from __future__ import annotations

import copy
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlparse, urlunparse

from framework.common.evidence import sanitize_sensitive_data


class ControlledRequest:
    """Represents a fully resolved HTTP request ready for safe execution."""

    def __init__(
        self,
        url: str,
        method: str = "GET",
        query_params: Optional[List[Tuple[str, str]]] = None,
        path_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        json_body: Optional[Any] = None,
        form_body: Optional[Dict[str, str]] = None,
        mutated_target: Optional[str] = None,
        mutated_value: Optional[str] = None,
    ):
        self.base_url = url.strip()
        self.method = method.strip().upper()
        self.query_params: List[Tuple[str, str]] = list(query_params or [])
        self.path_params: Dict[str, str] = dict(path_params or {})
        self.headers: Dict[str, str] = {k: str(v) for k, v in (headers or {}).items()}
        self.cookies: Dict[str, str] = {k: str(v) for k, v in (cookies or {}).items()}
        self.json_body = json_body
        self.form_body = dict(form_body or {}) if form_body is not None else None
        self.mutated_target = mutated_target
        self.mutated_value = mutated_value

    @property
    def url(self) -> str:
        """Returns the fully resolved effective URL."""
        return self.build_effective_url()

    def build_effective_url(self) -> str:
        """Constructs the final URL with path parameters substituted and query string encoded."""
        parsed = urlparse(self.base_url)
        path = parsed.path or "/"

        # 1. Substitute path parameters if any: {id}, :id, <id>
        for param, val in self.path_params.items():
            encoded_val = quote(str(val), safe="")
            path = path.replace(f"{{{param}}}", encoded_val)
            path = path.replace(f":{param}", encoded_val)
            path = path.replace(f"<{param}>", encoded_val)

        # 2. Build query string
        effective_query = ""
        if self.query_params:
            effective_query = urlencode(self.query_params)
        elif parsed.query:
            effective_query = parsed.query

        new_parsed = parsed._replace(path=path, query=effective_query)
        return urlunparse(new_parsed)

    def build_effective_headers(self) -> Dict[str, str]:
        """Builds headers including formatted Cookie header if cookies are present."""
        eff_headers = dict(self.headers)
        if self.cookies and "Cookie" not in eff_headers and "cookie" not in eff_headers:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            eff_headers["Cookie"] = cookie_str
        return eff_headers

    def build_body_bytes(self) -> Optional[bytes]:
        """Encodes request body according to content type."""
        if self.json_body is not None:
            return json.dumps(self.json_body).encode("utf-8")
        if self.form_body is not None:
            return urlencode(self.form_body).encode("utf-8")
        return None

    def get_sanitized_representation(self) -> str:
        """Returns sanitized HTTP text representation for evidence tracking."""
        eff_url = self.build_effective_url()
        lines = [f"{self.method} {eff_url} HTTP/1.1"]
        eff_headers = self.build_effective_headers()
        for k, v in sorted(eff_headers.items()):
            lines.append(f"{k}: {v}")
        lines.append("")

        body_bytes = self.build_body_bytes()
        if body_bytes:
            try:
                body_str = body_bytes.decode("utf-8", errors="replace")
                lines.append(body_str)
            except Exception:
                lines.append(f"[Binary Body: {len(body_bytes)} bytes]")

        raw_req = "\n".join(lines)
        return sanitize_sensitive_data(raw_req)

    def clone(self) -> ControlledRequest:
        """Creates a deep copy of this request."""
        return ControlledRequest(
            url=self.base_url,
            method=self.method,
            query_params=copy.deepcopy(self.query_params),
            path_params=copy.deepcopy(self.path_params),
            headers=copy.deepcopy(self.headers),
            cookies=copy.deepcopy(self.cookies),
            json_body=copy.deepcopy(self.json_body),
            form_body=copy.deepcopy(self.form_body),
            mutated_target=self.mutated_target,
            mutated_value=self.mutated_value,
        )


class ControlledResponse:
    """Represents a bounded HTTP response received during validation."""

    def __init__(
        self,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body: str | bytes = "",
        size_bytes: int = 0,
        elapsed_seconds: float = 0.0,
        final_url: str = "",
        redirect_history: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        self.status_code = int(status_code)
        self.headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
        self.body = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body or "")
        self.size_bytes = int(size_bytes) if size_bytes else len(self.body.encode("utf-8"))
        self.elapsed_seconds = float(elapsed_seconds)
        self.final_url = final_url
        self.redirect_history = list(redirect_history or [])
        if "body_text" in kwargs:
            self.body = str(kwargs.pop("body_text"))
        for k, v in kwargs.items():
            setattr(self, k, v)

    @property
    def body_text(self) -> str:
        return self.body

    @body_text.setter
    def body_text(self, val: str) -> None:
        self.body = str(val or "")

    @property
    def content_type(self) -> str:
        """Normalized content-type header."""
        raw = self.headers.get("content-type", "")
        return raw.split(";")[0].strip().lower()

    @property
    def location_header(self) -> Optional[str]:
        """Location header value if present."""
        return self.headers.get("location")

    def get_sanitized_representation(self) -> str:
        """Returns sanitized HTTP text representation for evidence tracking."""
        lines = [f"HTTP/1.1 {self.status_code}"]
        for k, v in sorted(self.headers.items()):
            lines.append(f"{k.title()}: {v}")
        lines.append("")
        lines.append(self.body)
        raw_res = "\n".join(lines)
        return sanitize_sensitive_data(raw_res)


class RequestBuilder:
    """
    Constructs baseline requests and performs single-component deterministic mutations.
    Guarantees that only ONE parameter is mutated at a time.
    """

    def __init__(self, base_url: str, method: str = "GET"):
        self.raw_url = base_url.strip()
        self.method = method.strip().upper()

        parsed = urlparse(self.raw_url)
        # Separate base path from query string
        clean_url = urlunparse(parsed._replace(query=""))
        self.base_url = clean_url
        self.query_params: List[Tuple[str, str]] = parse_qsl(parsed.query, keep_blank_values=True)
        self.path_params: Dict[str, str] = {}
        self.headers: Dict[str, str] = {
            "User-Agent": "BugBounty-Agent/1.1 (Security Validation Engine)",
            "Accept": "*/*",
        }
        self.cookies: Dict[str, str] = {}
        self.json_body: Optional[Any] = None
        self.form_body: Optional[Dict[str, str]] = None

    def set_header(self, name: str, value: str) -> RequestBuilder:
        self.headers[name] = str(value)
        return self

    def set_cookie(self, name: str, value: str) -> RequestBuilder:
        self.cookies[name] = str(value)
        return self

    def set_path_param(self, name: str, value: str) -> RequestBuilder:
        self.path_params[name] = str(value)
        return self

    def set_json_body(self, data: Any) -> RequestBuilder:
        self.json_body = data
        self.headers["Content-Type"] = "application/json"
        return self

    def set_form_body(self, data: Dict[str, str]) -> RequestBuilder:
        self.form_body = data
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        return self

    def add_query_param(self, name: str, value: str) -> RequestBuilder:
        self.query_params.append((name, str(value)))
        return self

    def build_baseline(self) -> ControlledRequest:
        """Produces the untouched baseline request."""
        return ControlledRequest(
            url=self.base_url,
            method=self.method,
            query_params=list(self.query_params),
            path_params=dict(self.path_params),
            headers=dict(self.headers),
            cookies=dict(self.cookies),
            json_body=copy.deepcopy(self.json_body),
            form_body=dict(self.form_body) if self.form_body is not None else None,
            mutated_target=None,
            mutated_value=None,
        )

    def mutate_query_param(self, param_name: str, test_value: str) -> ControlledRequest:
        """Mutates ONLY the specified query parameter, appending it if not present."""
        req = self.build_baseline()
        updated_params: List[Tuple[str, str]] = []
        found = False

        for k, v in req.query_params:
            if k.lower() == param_name.lower():
                updated_params.append((k, test_value))
                found = True
            else:
                updated_params.append((k, v))

        if not found:
            updated_params.append((param_name, test_value))

        req.query_params = updated_params
        req.mutated_target = f"query:{param_name}"
        req.mutated_value = test_value
        return req

    def mutate_path_param(self, param_name: str, test_value: str) -> ControlledRequest:
        """Mutates ONLY the specified path parameter placeholder."""
        req = self.build_baseline()
        req.path_params[param_name] = test_value
        req.mutated_target = f"path:{param_name}"
        req.mutated_value = test_value
        return req

    def mutate_header(self, header_name: str, test_value: str) -> ControlledRequest:
        """Mutates ONLY the specified HTTP header."""
        req = self.build_baseline()
        req.headers[header_name] = test_value
        req.mutated_target = f"header:{header_name}"
        req.mutated_value = test_value
        return req

    def mutate_cookie(self, cookie_name: str, test_value: str) -> ControlledRequest:
        """Mutates ONLY the specified cookie value."""
        req = self.build_baseline()
        req.cookies[cookie_name] = test_value
        req.mutated_target = f"cookie:{cookie_name}"
        req.mutated_value = test_value
        return req

    def mutate_json_param(self, key_path: str, test_value: Any) -> ControlledRequest:
        """
        Mutates ONLY a specific key in a JSON dictionary body.
        Supports single key names (e.g. 'username', 'redirect').
        """
        req = self.build_baseline()
        if not isinstance(req.json_body, dict):
            req.json_body = {}
        req.json_body[key_path] = test_value
        req.mutated_target = f"json:{key_path}"
        req.mutated_value = str(test_value)
        return req

    def mutate_form_param(self, param_name: str, test_value: str) -> ControlledRequest:
        """Mutates ONLY a specific key in a form body."""
        req = self.build_baseline()
        if req.form_body is None:
            req.form_body = {}
        req.form_body[param_name] = test_value
        req.mutated_target = f"form:{param_name}"
        req.mutated_value = test_value
        return req
