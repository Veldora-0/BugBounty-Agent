"""
Token & JWT Structural Intelligence Engine (Phase 14).

Performs safe, local structural analysis of JWTs, opaque bearer tokens, transport channels,
and refresh token lifecycles.
Does NOT tamper with live token signatures or launch brute-force verification attacks.
"""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from framework.authentication.models import TokenMetadata


class TokenAnalyzer:
    """Safely decodes and inspects authentication token structures and transport channels."""

    @staticmethod
    def _b64url_decode(segment: str) -> Optional[Dict[str, Any]]:
        """Safely decodes a base64url-encoded JSON string segment."""
        try:
            # Pad segment
            rem = len(segment) % 4
            if rem > 0:
                segment += "=" * (4 - rem)
            decoded = base64.urlsafe_b64decode(segment.encode("ascii")).decode("utf-8")
            return json.loads(decoded)
        except Exception:
            return None

    @classmethod
    def analyze_jwt_structure(cls, token: str) -> TokenMetadata:
        """
        Locally inspects a JWT without cryptographic verification.
        Extracts structural claims, header algorithm, expiration presence, and privilege roles.
        """
        meta = TokenMetadata(token_type="JWT", is_jwt=True)
        if not token or token.count(".") != 2:
            meta.token_type = "OPAQUE_BEARER"
            meta.is_jwt = False
            return meta

        parts = token.split(".")
        header = cls._b64url_decode(parts[0])
        payload = cls._b64url_decode(parts[1])

        if not header or not payload:
            meta.token_type = "OPAQUE_BEARER"
            meta.is_jwt = False
            return meta

        meta.jwt_algorithm = header.get("alg")
        meta.jwt_issuer = payload.get("iss")
        meta.jwt_subject_present = "sub" in payload
        meta.jwt_audience_present = "aud" in payload
        meta.jwt_expiry_present = "exp" in payload
        meta.jwt_not_before_present = "nbf" in payload
        meta.jwt_issued_at_present = "iat" in payload

        # Extract privilege claims
        privilege_keys = {"role", "roles", "admin", "is_admin", "scope", "scopes", "groups", "permissions", "privileges"}
        found_privs = []
        for k, v in payload.items():
            if k.lower() in privilege_keys:
                found_privs.append(f"{k}:{v}")
        meta.privilege_claims = found_privs

        # Generate informational observations
        if not meta.jwt_expiry_present:
            meta.observations.append("JWT_WITHOUT_EXPIRATION_CLAIM")
        if meta.jwt_algorithm and meta.jwt_algorithm.lower() == "none":
            meta.observations.append("JWT_ALGORITHM_NONE_HEADER")
        if meta.privilege_claims:
            meta.observations.append("PRIVILEGE_CLAIM_PRESENT")

        return meta

    @staticmethod
    def analyze_transport_exposure(url: str, headers: Optional[Dict[str, str]] = None) -> List[str]:
        """
        Detects whether authentication material appears in insecure transport locations
        (e.g., URL query parameters, referer headers).
        """
        exposures: List[str] = []
        if not url:
            return exposures

        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)

        sensitive_param_names = {"token", "access_token", "auth", "session", "jwt", "api_key", "bearer"}
        for param in query_params:
            if param.lower() in sensitive_param_names:
                exposures.append(f"TOKEN_IN_QUERY_PARAMETER:{param}")

        if parsed.fragment:
            frag_lower = parsed.fragment.lower()
            if any(s in frag_lower for s in ["access_token", "token=", "jwt="]):
                exposures.append("TOKEN_IN_URL_FRAGMENT")

        if headers:
            for k, v in headers.items():
                if k.lower() == "referer" and any(s in v.lower() for s in ["token=", "access_token="]):
                    exposures.append("TOKEN_LEAKED_IN_REFERER_HEADER")

        return exposures

    @classmethod
    def evaluate_refresh_token_reuse(
        cls,
        status_first_use: int,
        status_second_use: int,
        response_second_use: str,
    ) -> Tuple[bool, str]:
        """
        Evaluates whether a refresh token was accepted multiple times after rotation was expected.
        """
        # If second use is successful (200 OK) and issued new tokens
        if status_second_use in (200, 201) and "token" in response_second_use.lower():
            return (
                True,
                "Refresh token was successfully reused after initial consumption, indicating lack of one-time refresh token rotation/revocation.",
            )
        return (
            False,
            f"Refresh token reuse was correctly rejected (HTTP {status_second_use}).",
        )
