"""
Phase 21: Authentication & Authorization Correlation Data Models.

Provides safe dataclasses, type enums, fail-closed validation helpers, and secure
representations for correlating authentication and authorization states across multiple
principals, sessions, and tenants without credential leakage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import math
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

# Reused external domain models
from framework.authentication.models import IdentityProfile, SessionProfile as AuthSessionProfile
from framework.authz.model import PrincipalProfile, SessionProfile as AuthzSessionProfile


class SerializationSecurityError(Exception):
    """Raised when serialization encounters unapproved keys, disguised credentials, or schema violations."""
    pass


class StateSecurityValidationError(Exception):
    """Raised when state loading encounters invalid schemas, unapproved fields, or credential corruption."""
    pass


class EvidencePersistenceError(Exception):
    """Raised when saving an evidence artifact to the EvidenceStore fails."""
    pass


class AttestationSecurityError(Exception):
    """Raised when invalidation event attestation fails verification, signature validation, or trust boundaries."""
    pass


class CorrelationLifecycle(str, Enum):
    """Lifecycle stages for sessions and correlation hypotheses."""
    CREATED = "CREATED"
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"
    FAILED = "FAILED"


class ProbeStatus(str, Enum):
    """Normalized outcomes for authorization and preflight probes."""
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    NOT_FOUND = "NOT_FOUND"
    REDIRECT_LOGIN = "REDIRECT_LOGIN"
    ANOMALOUS = "ANOMALOUS"


# Strict schema and boundary regex patterns
SAFE_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")
SESSION_REF_PATTERN = re.compile(r"^sess_[a-f0-9]{32}$")
HMAC_FINGERPRINT_PATTERN = re.compile(r"^[a-f0-9]{32}$")
EVIDENCE_REF_PATTERN = re.compile(r"^EVID-[a-fA-F0-9]{12}$")
ATTESTATION_REF_PATTERN = re.compile(r"^ATT-[a-fA-F0-9]{64}$")
ATTESTATION_SIG_PATTERN = re.compile(r"^ATT-SIG-[a-fA-F0-9]{64}$")
ISO_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")
URL_PATH_PATTERN = re.compile(r"^/[a-zA-Z0-9_\-\./?=&%]*$")
HYPOTHESIS_ID_PATTERN = re.compile(r"^HYP-[a-zA-Z0-9_\-\.]{1,32}$")
FINDING_ID_PATTERN = re.compile(r"^FIND-[a-zA-Z0-9_\-\.]{1,32}$")
CVSS_VECTOR_PATTERN = re.compile(r"^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[HLN]/I:[HLN]/A:[HLN]$")

# Heuristic indicators serve as an additional safeguard, not the primary boundary
DISGUISED_CREDENTIAL_INDICATORS = (
    "bearer ", "eyjh", "phpsessid=", "token=", "jwt=", "password=", 
    "secret=", "api_key=", "apikey=", "session_id=", "auth="
)
MASKED_TOKEN_FRAGMENT_PATTERN = re.compile(r"tok_[a-zA-Z0-9_\.]{4,}")
HIGH_ENTROPY_TOKEN_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{32,}={0,2}|[A-Fa-f0-9]{32,})")

LIFECYCLE_PATTERN = re.compile(r"^(CREATED|UNVERIFIED|VERIFIED|EXPIRED|AUTHENTICATION_FAILED|AUTHORIZATION_DENIED|REVOKED|UNKNOWN|FAILED)$")
EXPECTED_RESULT_PATTERN = re.compile(r"^(ACCESS_ALLOWED|ACCESS_DENIED|AUTHENTICATION_REQUIRED|ISOLATED)$")
VALIDATION_STATUS_PATTERN = re.compile(r"^(PENDING|VALIDATED|FAILED|INCONCLUSIVE|SESSION_HEALTH_FAILED)$")
VERIFICATION_STATUS_PATTERN = re.compile(r"^(UNVERIFIED|VERIFIED|FAILED|EXPIRED)$")
HYPOTHESIS_CATEGORY_PATTERN = re.compile(r"^(TENANT_ISOLATION|REVOCATION_ENFORCEMENT|PRE_MFA_PRIVILEGE|STEP_UP_AUTH)$")
FINDING_CATEGORY_PATTERN = re.compile(r"^(TENANT_BOUNDARY_BYPASS|PRE_MFA_PRIVILEGE_LEAK|SESSION_NOT_INVALIDATED)$")
FINDING_SEVERITY_PATTERN = re.compile(r"^(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|NONE)$")
FREE_TEXT_TITLE_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.\s:,()\[\]]{1,128}$")


def _safe_repr(val: Any, pattern: re.Pattern, placeholder: str) -> str:
    """Safe repr helper: never displays raw strings that fail pattern constraints or are unvalidated."""
    if isinstance(val, str) and pattern.match(val):
        lower_v = val.lower()
        if not any(ind in lower_v for ind in DISGUISED_CREDENTIAL_INDICATORS) and not MASKED_TOKEN_FRAGMENT_PATTERN.search(val):
            return repr(val)
    return f"[{placeholder}]"


def _safe_lifecycle_repr(obj: Any) -> str:
    """
    Safely represents lifecycle state.
    Never calls str() or repr() on arbitrary or unexpected objects to prevent credential or payload leakage.
    """
    if isinstance(obj, CorrelationLifecycle):
        return repr(obj.value)
    if isinstance(obj, str) and LIFECYCLE_PATTERN.match(obj):
        return repr(obj)
    return "[UNVALIDATED_LIFECYCLE]"


def assert_safe_string(val: Any, field_name: str, pattern: Optional[re.Pattern] = None) -> str:
    """
    Enforces positive allowlisting on string fields.
    Never echoes rejected input values or keys into exception messages.
    """
    if not isinstance(val, str):
        raise SerializationSecurityError(f"Field '{field_name}' must be of type string")
    lower_val = val.lower()
    if any(ind in lower_val for ind in DISGUISED_CREDENTIAL_INDICATORS) or MASKED_TOKEN_FRAGMENT_PATTERN.search(val):
        raise SerializationSecurityError(f"Disguised credential detected in field '{field_name}'")
    if pattern and not pattern.match(val):
        raise SerializationSecurityError(f"Field '{field_name}' failed schema pattern validation: [REDACTED]")
    return val


def assert_strict_int(val: Any, field_name: str, min_val: Optional[int] = None, max_val: Optional[int] = None) -> int:
    """Strict integer validator: explicitly rejects booleans and out-of-bound values."""
    if isinstance(val, bool) or not isinstance(val, int):
        raise SerializationSecurityError(f"Field '{field_name}' must be an integer, not boolean or other type")
    if min_val is not None and val < min_val:
        raise SerializationSecurityError(f"Field '{field_name}' value below minimum permitted bound")
    if max_val is not None and val > max_val:
        raise SerializationSecurityError(f"Field '{field_name}' value exceeds maximum permitted bound")
    return val


def assert_strict_float(val: Any, field_name: str, min_val: Optional[float] = None, max_val: Optional[float] = None) -> float:
    """Strict float validator: explicitly rejects booleans, NaN, and Infinity."""
    if isinstance(val, bool) or not isinstance(val, (int, float)):
        raise SerializationSecurityError(f"Field '{field_name}' must be a float, not boolean or other type")
    f_val = float(val)
    if math.isnan(f_val) or math.isinf(f_val):
        raise SerializationSecurityError(f"Field '{field_name}' must be a finite number, NaN and Infinity are prohibited")
    if min_val is not None and f_val < min_val:
        raise SerializationSecurityError(f"Field '{field_name}' value below minimum permitted bound")
    if max_val is not None and f_val > max_val:
        raise SerializationSecurityError(f"Field '{field_name}' value exceeds maximum permitted bound")
    return f_val


ALLOWED_PRINCIPAL_KEYS: Set[str] = {
    "principal_id", "tenant_id", "role", "privilege_level", 
    "verification_status", "evidence_refs", "confidence"
}


@dataclass
class CorrelatedPrincipalContext:
    """Represents a security principal within the correlation graph."""
    principal_id: str
    identity_profile: Optional[IdentityProfile] = None
    principal_profile: Optional[PrincipalProfile] = None
    tenant_id: Optional[str] = None
    role: str = "UNKNOWN"
    privilege_level: Optional[int] = None
    verification_status: str = "UNVERIFIED"
    evidence_refs: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def __repr__(self) -> str:
        # Safe repr even when object is unvalidated: masks all dynamic attributes
        pid = _safe_repr(self.principal_id, SAFE_IDENTIFIER_PATTERN, "UNVALIDATED_PRINCIPAL_ID")
        role = _safe_repr(self.role, SAFE_IDENTIFIER_PATTERN, "UNVALIDATED_ROLE")
        vs = _safe_repr(self.verification_status, VERIFICATION_STATUS_PATTERN, "UNVALIDATED_STATUS")
        return f"CorrelatedPrincipalContext(principal_id={pid}, role={role}, verification_status={vs})"

    def __str__(self) -> str:
        return self.__repr__()

    def validate(self) -> Dict[str, Any]:
        """Fail-closed validation covering every persisted principal field."""
        pid = assert_safe_string(self.principal_id, "principal_id", SAFE_IDENTIFIER_PATTERN)
        
        tid = None
        if self.tenant_id is not None:
            tid = assert_safe_string(self.tenant_id, "tenant_id", SAFE_IDENTIFIER_PATTERN)
            
        role = assert_safe_string(self.role, "role", SAFE_IDENTIFIER_PATTERN)
        
        pl = None
        if self.privilege_level is not None:
            pl = assert_strict_int(self.privilege_level, "privilege_level", 0, 100)
                
        vs = assert_safe_string(self.verification_status, "verification_status", VERIFICATION_STATUS_PATTERN)
            
        if not isinstance(self.evidence_refs, list):
            raise SerializationSecurityError("Field 'evidence_refs' must be a list of strings")
        validated_refs = [
            assert_safe_string(r, "evidence_ref", EVIDENCE_REF_PATTERN)
            for r in self.evidence_refs
        ]
        
        conf = assert_strict_float(self.confidence, "confidence", 0.0, 1.0)

        return {
            "principal_id": pid,
            "tenant_id": tid,
            "role": role,
            "privilege_level": pl,
            "verification_status": vs,
            "evidence_refs": validated_refs,
            "confidence": round(conf, 3),
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.validate()


ALLOWED_SESSION_KEYS: Set[str] = {
    "session_ref", "principal_id", "hmac_fingerprint", "lifecycle", 
    "expires_at", "verified_at", "metadata"
}

ALLOWED_METADATA_KEYS: Set[str] = {
    "token_type", "preflight_endpoint", "is_test_account", 
    "tenant_id", "observed_role", "claim_keys", "mfa_level"
}


@dataclass
class CorrelatedSessionContext:
    """Represents an active, ephemeral session associated with a principal."""
    session_ref: str  # Ephemeral reference: e.g. "sess_f47ac10b58cc4372a5670e02b2c3d479"
    principal_id: str
    authz_session: Optional[AuthzSessionProfile] = None
    auth_session: Optional[AuthSessionProfile] = None
    volatile_headers: Dict[str, str] = field(default_factory=dict, repr=False)  # In-memory only!
    pre_revocation_baseline: Optional[Any] = field(default=None, repr=False)  # In-memory only!
    invalidation_evidence_ref: Optional[str] = field(default=None, repr=False)  # In-memory only!
    hmac_fingerprint: Optional[str] = None  # Domain-separated HMAC-SHA256[:32]
    lifecycle: CorrelationLifecycle = CorrelationLifecycle.CREATED
    expires_at: Optional[str] = None
    verified_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def mfa_level(self) -> str:
        """Returns session MFA level: NONE, PRE_MFA, FULL_MFA, or STEP_UP."""
        return str(self.metadata.get("mfa_level", "NONE"))

    @property
    def is_pre_mfa(self) -> bool:
        """Indicates whether session is in an intermediate pre-MFA state."""
        return self.metadata.get("mfa_level") == "PRE_MFA"

    def __repr__(self) -> str:
        # Safe repr even when object is unvalidated; volatile_headers is repr=False
        sref = _safe_repr(self.session_ref, SESSION_REF_PATTERN, "UNVALIDATED_SESSION_REF")
        pid = _safe_repr(self.principal_id, SAFE_IDENTIFIER_PATTERN, "UNVALIDATED_PRINCIPAL_ID")
        lc = _safe_lifecycle_repr(self.lifecycle)
        return f"CorrelatedSessionContext(session_ref={sref}, principal_id={pid}, lifecycle={lc})"

    def __str__(self) -> str:
        return self.__repr__()

    def validate(self) -> Dict[str, Any]:
        """Fail-closed validation covering every persisted session field."""
        sref = assert_safe_string(self.session_ref, "session_ref", SESSION_REF_PATTERN)
        pid = assert_safe_string(self.principal_id, "principal_id", SAFE_IDENTIFIER_PATTERN)
        
        fp = None
        if self.hmac_fingerprint is not None:
            fp = assert_safe_string(self.hmac_fingerprint, "hmac_fingerprint", HMAC_FINGERPRINT_PATTERN)
            
        if isinstance(self.lifecycle, CorrelationLifecycle):
            lc = self.lifecycle.value
        elif isinstance(self.lifecycle, str) and LIFECYCLE_PATTERN.match(self.lifecycle):
            lc = self.lifecycle
        else:
            raise SerializationSecurityError("Field 'lifecycle' must be a valid CorrelationLifecycle enum or recognized lifecycle string")
            
        exp = None
        if self.expires_at is not None:
            exp = assert_safe_string(self.expires_at, "expires_at", ISO_TIMESTAMP_PATTERN)
            
        ver = None
        if self.verified_at is not None:
            ver = assert_safe_string(self.verified_at, "verified_at", ISO_TIMESTAMP_PATTERN)
            
        if not isinstance(self.metadata, dict):
            raise SerializationSecurityError("Field 'metadata' must be a dictionary")
            
        # Reject unknown metadata fields (fail-closed, zero input reflection in exception)
        unknown_meta = set(self.metadata.keys()) - ALLOWED_METADATA_KEYS
        if unknown_meta:
            raise SerializationSecurityError("Rejected unapproved metadata keys detected in session")
            
        validated_meta: Dict[str, Any] = {}
        for k, v in self.metadata.items():
            if k == "token_type":
                assert_safe_string(v, "metadata.token_type")
                if v not in ("BEARER", "COOKIE", "HEADER", "OAUTH2"):
                    raise SerializationSecurityError("Invalid token_type value")
                validated_meta[k] = v
            elif k == "preflight_endpoint":
                assert_safe_string(v, "metadata.preflight_endpoint", URL_PATH_PATTERN)
                validated_meta[k] = v
            elif k == "is_test_account":
                if not isinstance(v, bool):
                    raise SerializationSecurityError("Field 'metadata.is_test_account' must be boolean")
                validated_meta[k] = v
            elif k in ("tenant_id", "observed_role"):
                validated_meta[k] = assert_safe_string(v, f"metadata.{k}", SAFE_IDENTIFIER_PATTERN)
            elif k == "claim_keys":
                if not isinstance(v, list) or not all(isinstance(x, str) and SAFE_IDENTIFIER_PATTERN.match(x) for x in v):
                    raise SerializationSecurityError("Field 'metadata.claim_keys' must be a list of safe identifier strings")
                validated_meta[k] = list(v)
            elif k == "mfa_level":
                assert_safe_string(v, "metadata.mfa_level")
                if v not in ("NONE", "PRE_MFA", "FULL_MFA", "STEP_UP"):
                    raise SerializationSecurityError("Invalid mfa_level value in session metadata")
                validated_meta[k] = v

        return {
            "session_ref": sref,
            "principal_id": pid,
            "hmac_fingerprint": fp,
            "lifecycle": lc,
            "expires_at": exp,
            "verified_at": ver,
            "metadata": validated_meta,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.validate()


ALLOWED_HYPOTHESIS_KEYS: Set[str] = {
    "hypothesis_id", "category", "target_endpoint", "principal_a_id", "principal_b_id",
    "preflight_status", "expected_result", "validation_status"
}

ALLOWED_FINDING_KEYS: Set[str] = {
    "finding_id", "title", "category", "severity", "cvss_score", "cvss_vector",
    "confidence", "endpoint", "description", "evidence_chain"
}


@dataclass
class CorrelationHypothesis:
    """Hypothesis describing an expected boundary or isolation property."""
    hypothesis_id: str
    category: str
    target_endpoint: str
    principal_a_id: str
    principal_b_id: str
    preflight_status: CorrelationLifecycle = CorrelationLifecycle.CREATED
    expected_result: str = "ISOLATED"
    validation_status: str = "PENDING"

    def __repr__(self) -> str:
        hid = _safe_repr(self.hypothesis_id, HYPOTHESIS_ID_PATTERN, "UNVALIDATED_HYPOTHESIS_ID")
        cat = _safe_repr(self.category, HYPOTHESIS_CATEGORY_PATTERN, "UNVALIDATED_CATEGORY")
        exp = _safe_repr(self.expected_result, EXPECTED_RESULT_PATTERN, "UNVALIDATED_EXPECTED_RESULT")
        ps = _safe_lifecycle_repr(self.preflight_status)
        return f"CorrelationHypothesis(hypothesis_id={hid}, category={cat}, expected_result={exp}, preflight_status={ps})"

    def __str__(self) -> str:
        return self.__repr__()

    def validate(self) -> Dict[str, Any]:
        hid = assert_safe_string(self.hypothesis_id, "hypothesis_id", HYPOTHESIS_ID_PATTERN)
        cat = assert_safe_string(self.category, "category", HYPOTHESIS_CATEGORY_PATTERN)
        endpoint = assert_safe_string(self.target_endpoint, "target_endpoint", URL_PATH_PATTERN)
        pa = assert_safe_string(self.principal_a_id, "principal_a_id", SAFE_IDENTIFIER_PATTERN)
        pb = assert_safe_string(self.principal_b_id, "principal_b_id", SAFE_IDENTIFIER_PATTERN)
        
        if isinstance(self.preflight_status, CorrelationLifecycle):
            ps = self.preflight_status.value
        elif isinstance(self.preflight_status, str) and LIFECYCLE_PATTERN.match(self.preflight_status):
            ps = self.preflight_status
        else:
            raise SerializationSecurityError("Field 'preflight_status' must be a valid CorrelationLifecycle enum or recognized lifecycle string")
            
        if not isinstance(self.expected_result, str) or not EXPECTED_RESULT_PATTERN.match(self.expected_result):
            raise SerializationSecurityError("Invalid expected_result value: failed allowlist pattern validation")
        if not isinstance(self.validation_status, str) or not VALIDATION_STATUS_PATTERN.match(self.validation_status):
            raise SerializationSecurityError("Invalid validation_status value: failed allowlist pattern validation")
        return {
            "hypothesis_id": hid,
            "category": cat,
            "target_endpoint": endpoint,
            "principal_a_id": pa,
            "principal_b_id": pb,
            "preflight_status": ps,
            "expected_result": self.expected_result,
            "validation_status": self.validation_status,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.validate()


@dataclass
class CorrelationFinding:
    """Discovered and verified correlation security finding."""
    finding_id: str
    title: str
    category: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str]
    confidence: float
    endpoint: str
    description: str
    evidence_chain: List[str] = field(default_factory=list)

    def __repr__(self) -> str:
        # Safe repr strictly omits title, description, and evidence_chain
        fid = _safe_repr(self.finding_id, FINDING_ID_PATTERN, "UNVALIDATED_FINDING_ID")
        cat = _safe_repr(self.category, FINDING_CATEGORY_PATTERN, "UNVALIDATED_CATEGORY")
        sev = _safe_repr(self.severity, FINDING_SEVERITY_PATTERN, "UNVALIDATED_SEVERITY")
        score = self.cvss_score if isinstance(self.cvss_score, (int, float)) and not (isinstance(self.cvss_score, bool) or math.isnan(self.cvss_score) or math.isinf(self.cvss_score)) else 0.0
        return f"CorrelationFinding(finding_id={fid}, category={cat}, severity={sev}, cvss_score={score})"

    def __str__(self) -> str:
        return self.__repr__()

    def validate(self) -> Dict[str, Any]:
        fid = assert_safe_string(self.finding_id, "finding_id", FINDING_ID_PATTERN)
        
        # Free-text validation: title must be printable ASCII, no newlines/tags, no token blocks
        title = assert_safe_string(self.title, "title", FREE_TEXT_TITLE_PATTERN)
        if HIGH_ENTROPY_TOKEN_PATTERN.search(title):
            raise SerializationSecurityError("Finding title contains prohibited high-entropy token pattern")
            
        cat = assert_safe_string(self.category, "category", FINDING_CATEGORY_PATTERN)
        sev = assert_safe_string(self.severity, "severity", FINDING_SEVERITY_PATTERN)
        score = assert_strict_float(self.cvss_score, "cvss_score", 0.0, 10.0)
        
        vec = None
        if self.cvss_vector is not None:
            vec = assert_safe_string(self.cvss_vector, "cvss_vector", CVSS_VECTOR_PATTERN)
            
        conf = assert_strict_float(self.confidence, "confidence", 0.0, 1.0)
        endpoint = assert_safe_string(self.endpoint, "endpoint", URL_PATH_PATTERN)
        
        # Free-text validation: description max 1024 chars, printable ASCII/whitespace, no token blocks
        desc = assert_safe_string(self.description, "description")
        if len(desc) > 1024 or not all(c.isascii() and (c.isprintable() or c in "\n\r\t") for c in desc):
            raise SerializationSecurityError("Finding description failed character set constraints")
        if HIGH_ENTROPY_TOKEN_PATTERN.search(desc):
            raise SerializationSecurityError("Finding description contains prohibited high-entropy token pattern")
            
        if not isinstance(self.evidence_chain, list):
            raise SerializationSecurityError("Field 'evidence_chain' must be a list of strings")
        v_chain = [assert_safe_string(e, "evidence_chain item", EVIDENCE_REF_PATTERN) for e in self.evidence_chain]
        
        return {
            "finding_id": fid,
            "title": title,
            "category": cat,
            "severity": sev,
            "cvss_score": round(score, 1),
            "cvss_vector": vec,
            "confidence": round(conf, 3),
            "endpoint": endpoint,
            "description": desc,
            "evidence_chain": v_chain,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.validate()

    def to_native_finding(self) -> Any:
        """Converts into standard framework.findings.schema.Finding."""
        from framework.findings.schema import Finding
        v = self.validate()
        conf_label = "HIGH" if v["confidence"] >= 0.8 else ("MEDIUM" if v["confidence"] >= 0.5 else "LOW")
        return Finding(
            title=v["title"],
            summary=v["title"],
            affected_asset="correlation-target",
            affected_endpoint=v["endpoint"],
            vulnerability_type=v["category"],
            severity=v["severity"],
            description=v["description"],
            root_cause=f"Authentication & Authorization Correlation finding: {v['category']}",
            prerequisites="Multi-session or multi-tenant authorization environment",
            reproduction_steps=["Analyze correlated session responses", f"Verify endpoint {v['endpoint']}"],
            expected_result="Enforced access boundary and isolation",
            observed_result="Boundary violation or access control inconsistency",
            security_impact="Potential authorization or authentication boundary failure",
            remediation="Implement strict server-side tenant and session validation checks",
            scope_reference="in-scope",
            confidence=conf_label,
            finding_id=v["finding_id"],
            evidence=[{"evidence_type": "correlation_evidence", "content": ref} for ref in v["evidence_chain"]],
        )
