"""
Phase 21: AuthCorrelationStateManager.

Manages persistent state in state/auth_correlation.json with symmetrical,
fail-closed allowlist schema enforcement across load and save, length-prefixed
HMAC session fingerprinting, external key management, and atomic persistence.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from framework.auth_correlation.model import (
    ALLOWED_PRINCIPAL_KEYS,
    ALLOWED_SESSION_KEYS,
    ALLOWED_HYPOTHESIS_KEYS,
    ALLOWED_FINDING_KEYS,
    CorrelatedPrincipalContext,
    CorrelatedSessionContext,
    CorrelationHypothesis,
    CorrelationFinding,
    CorrelationLifecycle,
    SerializationSecurityError,
    StateSecurityValidationError,
    SAFE_IDENTIFIER_PATTERN,
    SESSION_REF_PATTERN,
    ISO_TIMESTAMP_PATTERN,
    LIFECYCLE_PATTERN,
    EXPECTED_RESULT_PATTERN,
    VALIDATION_STATUS_PATTERN,
    assert_safe_string,
)


SUPPORTED_SCHEMA_ID = "https://bugbounty.local/schemas/auth-correlation-v1.json"
SUPPORTED_VERSION_PATTERN = re.compile(r"^1\.\d+\.\d+$")

ALLOWED_ROOT_KEYS: Set[str] = {
    "$schema", "version", "program", "created_at", "last_updated",
    "key_id", "principals", "sessions", "hypotheses", "findings"
}


class KeySecurityError(Exception):
    """Raised when external HMAC key cannot be accessed, secured, or verified."""
    pass


def validate_state_schema(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Symmetrical validator executed before writing state and after loading state.
    Enforces exact allowed keys and types for all 5 records: root, principals,
    sessions, hypotheses, and findings.
    Requires $schema to equal the exact supported schema identifier.
    Rejects missing, unexpected, or unsupported schema identifiers.
    Enforces cross-record referential integrity and duplicate identifier rejection.
    Zero rejected input values or unapproved keys are reflected in exception messages.
    """
    if not isinstance(data, dict):
        raise StateSecurityValidationError("Root state must be a JSON dictionary")
        
    if set(data.keys()) != ALLOWED_ROOT_KEYS:
        raise StateSecurityValidationError("Root state keys do not match approved schema")

    # 1. Enforce exact supported $schema identifier
    schema_val = data.get("$schema")
    if not isinstance(schema_val, str):
        raise StateSecurityValidationError("Field 'root.$schema' must be a string")
    if schema_val != SUPPORTED_SCHEMA_ID:
        raise StateSecurityValidationError("Unsupported, missing, or unapproved root.$schema identifier")

    # Validate remaining root scalars
    assert_safe_string(data.get("version", ""), "root.version", SUPPORTED_VERSION_PATTERN)
    assert_safe_string(data.get("program", ""), "root.program", SAFE_IDENTIFIER_PATTERN)
    assert_safe_string(data.get("created_at", ""), "root.created_at", ISO_TIMESTAMP_PATTERN)
    assert_safe_string(data.get("last_updated", ""), "root.last_updated", ISO_TIMESTAMP_PATTERN)
    assert_safe_string(data.get("key_id", ""), "root.key_id", re.compile(r"^[a-f0-9]{8}$"))

    # 1. Validate principals
    principals = data.get("principals")
    if not isinstance(principals, dict):
        raise StateSecurityValidationError("Field 'principals' must be a dictionary")
    validated_principals = {}
    for pid_key, pdata in principals.items():
        assert_safe_string(pid_key, "principal dictionary key", SAFE_IDENTIFIER_PATTERN)
        if not isinstance(pdata, dict):
            raise StateSecurityValidationError("Principal record must be a dictionary")
        if set(pdata.keys()) != ALLOWED_PRINCIPAL_KEYS:
            raise StateSecurityValidationError("Principal record keys do not match approved schema")
        # Enforce consistency between dictionary key and embedded identifier
        if pdata.get("principal_id") != pid_key:
            raise StateSecurityValidationError("Dictionary key does not match embedded principal_id")
        ctx = CorrelatedPrincipalContext(
            principal_id=pdata.get("principal_id", ""),
            tenant_id=pdata.get("tenant_id"),
            role=pdata.get("role", "UNKNOWN"),
            privilege_level=pdata.get("privilege_level"),
            verification_status=pdata.get("verification_status", "UNVERIFIED"),
            evidence_refs=pdata.get("evidence_refs", []),
            confidence=pdata.get("confidence", 0.0),
        )
        validated_principals[pid_key] = ctx.validate()

    # 2. Validate sessions & enforce referential integrity
    sessions = data.get("sessions")
    if not isinstance(sessions, dict):
        raise StateSecurityValidationError("Field 'sessions' must be a dictionary")
    validated_sessions = {}
    for sref_key, sdata in sessions.items():
        assert_safe_string(sref_key, "session dictionary key", SESSION_REF_PATTERN)
        if not isinstance(sdata, dict):
            raise StateSecurityValidationError("Session record must be a dictionary")
        if set(sdata.keys()) != ALLOWED_SESSION_KEYS:
            raise StateSecurityValidationError("Session record keys do not match approved schema")
        # Enforce consistency between dictionary key and embedded identifier
        if sdata.get("session_ref") != sref_key:
            raise StateSecurityValidationError("Dictionary key does not match embedded session_ref")
            
        # Referential integrity: session must reference an existing validated principal
        ref_pid = sdata.get("principal_id", "")
        if ref_pid not in validated_principals:
            raise StateSecurityValidationError("Session record references nonexistent principal_id")
            
        raw_lc = sdata.get("lifecycle")
        if not isinstance(raw_lc, str) or not LIFECYCLE_PATTERN.match(raw_lc):
            raise StateSecurityValidationError("Invalid lifecycle state value in session record")

        s_ctx = CorrelatedSessionContext(
            session_ref=sdata.get("session_ref", ""),
            principal_id=ref_pid,
            hmac_fingerprint=sdata.get("hmac_fingerprint"),
            lifecycle=CorrelationLifecycle(raw_lc),
            expires_at=sdata.get("expires_at"),
            verified_at=sdata.get("verified_at"),
            metadata=sdata.get("metadata", {}),
        )
        validated_sessions[sref_key] = s_ctx.validate()

    # 3. Validate hypotheses & enforce referential integrity
    hypotheses = data.get("hypotheses")
    if not isinstance(hypotheses, list):
        raise StateSecurityValidationError("Field 'hypotheses' must be a list")
    validated_hypotheses = []
    seen_hyp_ids = set()
    for h in hypotheses:
        if not isinstance(h, dict):
            raise StateSecurityValidationError("Hypothesis record must be a dictionary")
        if set(h.keys()) != ALLOWED_HYPOTHESIS_KEYS:
            raise StateSecurityValidationError("Hypothesis record keys do not match approved schema")
            
        hid = h.get("hypothesis_id", "")
        if hid in seen_hyp_ids:
            raise StateSecurityValidationError("Duplicate hypothesis_id detected in state")
        seen_hyp_ids.add(hid)
        
        # Referential integrity: hypothesis must reference existing validated principals
        pa_id = h.get("principal_a_id", "")
        pb_id = h.get("principal_b_id", "")
        if pa_id not in validated_principals or pb_id not in validated_principals:
            raise StateSecurityValidationError("Hypothesis record references nonexistent principal_id")

        raw_ps = h.get("preflight_status")
        if not isinstance(raw_ps, str) or not LIFECYCLE_PATTERN.match(raw_ps):
            raise StateSecurityValidationError("Invalid preflight_status value in hypothesis record")

        raw_exp = h.get("expected_result")
        if not isinstance(raw_exp, str) or not EXPECTED_RESULT_PATTERN.match(raw_exp):
            raise StateSecurityValidationError("Invalid expected_result value in hypothesis record")

        raw_vs = h.get("validation_status")
        if not isinstance(raw_vs, str) or not VALIDATION_STATUS_PATTERN.match(raw_vs):
            raise StateSecurityValidationError("Invalid validation_status value in hypothesis record")

        h_obj = CorrelationHypothesis(
            hypothesis_id=hid,
            category=h.get("category", ""),
            target_endpoint=h.get("target_endpoint", ""),
            principal_a_id=pa_id,
            principal_b_id=pb_id,
            preflight_status=CorrelationLifecycle(raw_ps),
            expected_result=raw_exp,
            validation_status=raw_vs,
        )
        validated_hypotheses.append(h_obj.validate())

    # 4. Validate findings & duplicate rejection
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise StateSecurityValidationError("Field 'findings' must be a list")
    validated_findings = []
    seen_finding_ids = set()
    for f in findings:
        if not isinstance(f, dict):
            raise StateSecurityValidationError("Finding record must be a dictionary")
        if set(f.keys()) != ALLOWED_FINDING_KEYS:
            raise StateSecurityValidationError("Finding record keys do not match approved schema")
            
        fid = f.get("finding_id", "")
        if fid in seen_finding_ids:
            raise StateSecurityValidationError("Duplicate finding_id detected in state")
        seen_finding_ids.add(fid)

        f_obj = CorrelationFinding(
            finding_id=fid,
            title=f.get("title", ""),
            category=f.get("category", ""),
            severity=f.get("severity", ""),
            cvss_score=f.get("cvss_score", 0.0),
            cvss_vector=f.get("cvss_vector"),
            confidence=f.get("confidence", 0.0),
            endpoint=f.get("endpoint", ""),
            description=f.get("description", ""),
            evidence_chain=f.get("evidence_chain", []),
        )
        validated_findings.append(f_obj.validate())

    return {
        "$schema": data["$schema"],
        "version": data["version"],
        "program": data["program"],
        "created_at": data["created_at"],
        "last_updated": data["last_updated"],
        "key_id": data["key_id"],
        "principals": validated_principals,
        "sessions": validated_sessions,
        "hypotheses": validated_hypotheses,
        "findings": validated_findings,
    }


def _verify_and_prepare_state_dir(state_dir: str, workspace_root: Optional[str] = None) -> str:
    """
    Verifies that the state directory and every directory component below the trusted
    workspace root are strictly confined, contain no symlinks or reparse points, and
    are owned by the current user with restrictive permissions.
    """
    abs_dir = os.path.abspath(state_dir)
    
    if workspace_root:
        abs_root = os.path.realpath(os.path.abspath(workspace_root))
        try:
            common = os.path.commonpath([abs_root, abs_dir])
            if common != abs_root:
                raise SerializationSecurityError("State directory escapes workspace boundary")
        except ValueError:
            raise SerializationSecurityError("State directory is on a different drive or volume")
            
        rel_path = os.path.relpath(abs_dir, abs_root)
        current_ancestor = abs_root
        if rel_path != ".":
            for part in rel_path.split(os.sep):
                current_ancestor = os.path.join(current_ancestor, part)
                if not os.path.exists(current_ancestor):
                    if os.name != "nt":
                        os.makedirs(current_ancestor, mode=0o700, exist_ok=True)
                    else:
                        os.makedirs(current_ancestor, exist_ok=True)
                        _enforce_windows_directory_dacl(current_ancestor)

                anc_stat = os.lstat(current_ancestor)
                if stat.S_ISLNK(anc_stat.st_mode):
                    raise SerializationSecurityError(f"Security violation: directory component '{part}' is a symbolic link")
                if os.name == "nt" and hasattr(anc_stat, "st_file_attributes") and (anc_stat.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                    raise SerializationSecurityError(f"Security violation: directory component '{part}' is an NTFS reparse point or junction")
                
                if os.name != "nt":
                    if anc_stat.st_uid != os.getuid():
                        raise SerializationSecurityError(f"Security violation: directory component '{part}' ownership mismatch: not owned by current user")
                    if anc_stat.st_mode & 0o022 != 0:
                        raise SerializationSecurityError(f"Security violation: directory component '{part}' has unsafe permissions: must not be group- or world-writable")
                else:
                    _enforce_windows_directory_dacl(current_ancestor)
                    _verify_windows_directory_security(current_ancestor)
    else:
        if not os.path.exists(abs_dir):
            if os.name != "nt":
                os.makedirs(abs_dir, mode=0o700, exist_ok=True)
            else:
                os.makedirs(abs_dir, exist_ok=True)
                _enforce_windows_directory_dacl(abs_dir)

        dir_lstat = os.lstat(abs_dir)
        if stat.S_ISLNK(dir_lstat.st_mode):
            raise SerializationSecurityError("State directory cannot be a symbolic link")
        if os.name == "nt" and hasattr(dir_lstat, "st_file_attributes") and (dir_lstat.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise SerializationSecurityError("State directory cannot be an NTFS reparse point or directory junction")
            
        if os.name != "nt":
            if dir_lstat.st_uid != os.getuid():
                raise SerializationSecurityError("State directory ownership mismatch: not owned by current user")
            if dir_lstat.st_mode & 0o022 != 0:
                raise SerializationSecurityError("State directory has unsafe permissions: must not be group- or world-writable")
        else:
            _enforce_windows_directory_dacl(abs_dir)
            _verify_windows_directory_security(abs_dir)
        
    return abs_dir


if os.name == "nt":
    import ctypes
    from ctypes import wintypes, c_void_p, POINTER, byref, c_ulong, Structure

    advapi32 = ctypes.windll.advapi32
    kernel32 = ctypes.windll.kernel32

    kernel32.GetCurrentProcess.restype = c_void_p
    advapi32.OpenProcessToken.argtypes = [c_void_p, wintypes.DWORD, POINTER(c_void_p)]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [c_void_p, POINTER(c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [c_void_p]

    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        POINTER(c_void_p), POINTER(c_void_p), POINTER(c_void_p),
        POINTER(c_void_p), POINTER(c_void_p)
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD

    advapi32.GetSecurityDescriptorControl.argtypes = [
        c_void_p, POINTER(wintypes.WORD), POINTER(wintypes.DWORD)
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL

    class ACL_SIZE_INFORMATION(Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    advapi32.GetAclInformation.argtypes = [c_void_p, c_void_p, wintypes.DWORD, wintypes.DWORD]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [c_void_p, wintypes.DWORD, POINTER(c_void_p)]
    advapi32.GetAce.restype = wintypes.BOOL

    class ACE_HEADER(Structure):
        _fields_ = [
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
        ]

    class ACCESS_ALLOWED_ACE(Structure):
        _fields_ = [
            ("Header", ACE_HEADER),
            ("Mask", wintypes.DWORD),
            ("SidStart", wintypes.DWORD),
        ]

    def _get_current_user_sid_windows() -> Optional[str]:
        TOKEN_QUERY = 0x0008
        h_proc = kernel32.GetCurrentProcess()
        h_token = c_void_p()
        if not advapi32.OpenProcessToken(h_proc, TOKEN_QUERY, byref(h_token)):
            return None
        try:
            ret_len = c_ulong()
            advapi32.GetTokenInformation(h_token, 1, None, 0, byref(ret_len))
            buf = ctypes.create_string_buffer(ret_len.value)
            if not advapi32.GetTokenInformation(h_token, 1, buf, ret_len.value, byref(ret_len)):
                return None
            sid_ptr = ctypes.cast(buf, POINTER(c_void_p))[0]
            str_sid_ptr = c_void_p()
            if advapi32.ConvertSidToStringSidW(sid_ptr, byref(str_sid_ptr)):
                sid_str = ctypes.wstring_at(str_sid_ptr)
                kernel32.LocalFree(str_sid_ptr)
                return sid_str
        finally:
            kernel32.CloseHandle(h_token)
        return None

    def _enforce_windows_directory_dacl(dir_path: str) -> None:
        user_sid = _get_current_user_sid_windows()
        if not user_sid:
            raise SerializationSecurityError("Security violation: cannot determine current Windows user SID")
        import subprocess
        cmd = [
            "icacls", dir_path, "/inheritance:r",
            f"/grant:r", f"*{user_sid}:(OI)(CI)F",
            "/grant:r", "*S-1-5-18:(OI)(CI)F",
            "/grant:r", "*S-1-5-32-544:(OI)(CI)F",
            "/c", "/q"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise SerializationSecurityError(f"Security violation: failed to enforce Windows DACL on directory '{dir_path}' (exit code {res.returncode})")

    def _enforce_windows_file_dacl(file_path: str) -> None:
        user_sid = _get_current_user_sid_windows()
        if not user_sid:
            raise SerializationSecurityError("Security violation: cannot determine current Windows user SID")
        import subprocess
        cmd = [
            "icacls", file_path, "/inheritance:r",
            f"/grant:r", f"*{user_sid}:F",
            "/grant:r", "*S-1-5-18:F",
            "/grant:r", "*S-1-5-32-544:F",
            "/c", "/q"
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise SerializationSecurityError(f"Security violation: failed to enforce Windows DACL on file '{file_path}' (exit code {res.returncode})")

    def _verify_windows_path_security(target_path: str, is_dir: bool = True) -> None:
        lst = os.lstat(target_path)
        if hasattr(lst, "st_file_attributes") and (lst.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            path_type = "directory" if is_dir else "file"
            raise SerializationSecurityError(f"Security violation: {path_type} '{target_path}' is an NTFS reparse point or junction")

        SE_FILE_OBJECT = 1
        OWNER_SECURITY_INFORMATION = 0x00000001
        DACL_SECURITY_INFORMATION = 0x00000004

        p_owner = c_void_p()
        p_dacl = c_void_p()
        p_sd = c_void_p()

        res = advapi32.GetNamedSecurityInfoW(
            target_path, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            byref(p_owner), None, byref(p_dacl), None, byref(p_sd)
        )
        if res != 0:
            raise SerializationSecurityError(f"Security violation: failed to inspect Windows security descriptor for '{target_path}' (code {res})")

        try:
            # 1. Protected DACL verification (inheritance disabled)
            ctrl = wintypes.WORD()
            rev = wintypes.DWORD()
            if not advapi32.GetSecurityDescriptorControl(p_sd, byref(ctrl), byref(rev)):
                raise SerializationSecurityError(f"Security violation: failed to read security descriptor control for '{target_path}'")
            SE_DACL_PROTECTED = 0x1000
            if not (ctrl.value & SE_DACL_PROTECTED):
                raise SerializationSecurityError(f"Security violation: path '{target_path}' DACL is not protected (inheritance enabled)")

            # 2. Owner verification
            current_sid = _get_current_user_sid_windows()
            str_sid = c_void_p()
            owner_str = ""
            if advapi32.ConvertSidToStringSidW(p_owner, byref(str_sid)):
                owner_str = ctypes.wstring_at(str_sid)
                kernel32.LocalFree(str_sid)

            ALLOWED_OWNERS = {current_sid, "S-1-5-18", "S-1-5-32-544"}
            if current_sid and owner_str not in ALLOWED_OWNERS:
                raise SerializationSecurityError(f"Security violation: path '{target_path}' ownership mismatch: not owned by current user or Administrators")

            # 3. DACL verification
            if not p_dacl:
                raise SerializationSecurityError(f"Security violation: path '{target_path}' has a NULL DACL")

            acl_info = ACL_SIZE_INFORMATION()
            if not advapi32.GetAclInformation(p_dacl, byref(acl_info), ctypes.sizeof(acl_info), 2):
                raise SerializationSecurityError(f"Security violation: failed to read DACL information for '{target_path}'")

            # Approved principals: current user, Local SYSTEM (S-1-5-18), Builtin Administrators (S-1-5-32-544),
            # and NT AUTHORITY\OWNER RIGHTS (S-1-3-4) which represents the object owner.
            ALLOWED_SIDS = {current_sid, "S-1-5-18", "S-1-5-32-544", "S-1-3-4"}
            UNSAFE_SIDS = {"S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-7", "S-1-5-32-546"}
            WRITE_MASK = 0x0002 | 0x0004 | 0x0010 | 0x0100 | 0x40000000 | 0x10000000 | 0x1f01ff

            has_user_access = False
            for i in range(acl_info.AceCount):
                p_ace = c_void_p()
                if advapi32.GetAce(p_dacl, i, byref(p_ace)):
                    ace = ACCESS_ALLOWED_ACE.from_address(p_ace.value)
                    sid_ptr = p_ace.value + ACCESS_ALLOWED_ACE.SidStart.offset
                    str_sid_buf = c_void_p()
                    ace_sid = ""
                    if advapi32.ConvertSidToStringSidW(sid_ptr, byref(str_sid_buf)):
                        ace_sid = ctypes.wstring_at(str_sid_buf)
                        kernel32.LocalFree(str_sid_buf)

                    if ace.Header.AceType == 0:  # ACCESS_ALLOWED_ACE_TYPE
                        if ace_sid in UNSAFE_SIDS:
                            raise SerializationSecurityError(f"Security violation: path '{target_path}' DACL grants unsafe write access to unprivileged or public principals ({ace_sid})")
                        if ace_sid not in ALLOWED_SIDS:
                            raise SerializationSecurityError(f"Security violation: path '{target_path}' DACL grants unexpected access to unapproved principal ({ace_sid})")
                        if current_sid and (ace_sid == current_sid or ace_sid == "S-1-3-4"):
                            has_user_access = True
            if current_sid and not has_user_access:
                raise SerializationSecurityError(f"Security violation: path '{target_path}' DACL does not grant required access to current user ({current_sid})")
        finally:
            kernel32.LocalFree(p_sd)

    def _verify_windows_directory_security(dir_path: str) -> None:
        _verify_windows_path_security(dir_path, is_dir=True)

    def _verify_windows_file_security(file_path: str) -> None:
        _verify_windows_path_security(file_path, is_dir=False)
else:
    def _enforce_windows_directory_dacl(dir_path: str) -> None:
        pass

    def _enforce_windows_file_dacl(file_path: str) -> None:
        pass

    def _verify_windows_directory_security(dir_path: str) -> None:
        pass

    def _verify_windows_file_security(file_path: str) -> None:
        pass


class AuthCorrelationStateManager:
    """Manages persistent state and keyed HMAC session fingerprinting."""

    def __init__(
        self,
        program_id: str,
        workspace_root: Optional[str] = None,
        state_dir: Optional[str] = None,
        key_dir: Optional[str] = None,
    ):
        self.program_id = program_id
        self.workspace_root = workspace_root or os.getcwd()
        self.state_dir = state_dir or os.path.join(self.workspace_root, "state")
        self.key_dir = key_dir
        self.created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.principals: Dict[str, CorrelatedPrincipalContext] = {}
        self._key: Optional[bytes] = None
        self._key_id: Optional[str] = None

    @property
    def key_id(self) -> str:
        if self._key_id is None:
            _, kid = self.get_or_create_hmac_key()
            self._key_id = kid
        return self._key_id

    def get_or_create_hmac_key(self) -> Tuple[bytes, str]:
        """
        Retrieves or creates the 32-byte secret HMAC key stored strictly outside the Git repository.
        POSIX: $XDG_CONFIG_HOME/opencode/auth_correlation.key (fallback ~/.config/opencode/auth_correlation.key).
        Windows: %LOCALAPPDATA%\\opencode\\auth_correlation.key.
        """
        if self._key and self._key_id:
            return self._key, self._key_id

        if self.key_dir:
            key_file = os.path.join(self.key_dir, "auth_correlation.key")
            key_folder = self.key_dir
        elif os.name == "nt":
            base_dir = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
            key_folder = os.path.join(base_dir, "opencode")
            key_file = os.path.join(key_folder, "auth_correlation.key")
        else:
            base_dir = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
            key_folder = os.path.join(base_dir, "opencode")
            key_file = os.path.join(key_folder, "auth_correlation.key")

        try:
            if not os.path.exists(key_folder):
                if os.name != "nt":
                    os.makedirs(key_folder, mode=0o700, exist_ok=True)
                else:
                    os.makedirs(key_folder, exist_ok=True)
                    _enforce_windows_directory_dacl(key_folder)

            # Verify key folder security
            if os.name == "nt":
                _verify_windows_directory_security(key_folder)
            else:
                kdir_stat = os.lstat(key_folder)
                if stat.S_ISLNK(kdir_stat.st_mode):
                    raise KeySecurityError("Key directory is a symbolic link")
                if kdir_stat.st_uid != os.getuid():
                    raise KeySecurityError("Key directory ownership mismatch")
                if kdir_stat.st_mode & 0o077 != 0:
                    try:
                        os.chmod(key_folder, 0o700)
                        kdir_stat = os.lstat(key_folder)
                    except OSError:
                        pass
                if kdir_stat.st_mode & 0o077 != 0:
                    raise KeySecurityError("Key directory permissions are not private")

            if os.path.exists(key_file):
                # Verify key file security
                k_stat = os.lstat(key_file)
                if stat.S_ISLNK(k_stat.st_mode):
                    raise KeySecurityError("Key file is a symbolic link")
                if os.name == "nt":
                    try:
                        _enforce_windows_file_dacl(key_file)
                        _verify_windows_file_security(key_file)
                    except SerializationSecurityError as err:
                        raise KeySecurityError(str(err))
                else:
                    if k_stat.st_uid != os.getuid():
                        raise KeySecurityError("Key file ownership mismatch")
                    if k_stat.st_mode & 0o077 != 0:
                        raise KeySecurityError("Key file permissions are not private")
                    if k_stat.st_nlink != 1:
                        raise KeySecurityError("Key file has unexpected hardlinks")

                with open(key_file, "rb") as f:
                    key = f.read(32)
                if len(key) != 32:
                    raise KeySecurityError("Invalid key file length")
            else:
                key = secrets.token_bytes(32)
                flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL
                if hasattr(os, "O_BINARY"):
                    flags |= os.O_BINARY
                fd = os.open(key_file, flags, 0o600)
                try:
                    with os.fdopen(fd, "wb", closefd=True) as f:
                        f.write(key)
                except Exception as e:
                    raise KeySecurityError(f"Failed to write key file: {e}")

                if os.name == "nt":
                    try:
                        _enforce_windows_file_dacl(key_file)
                        _verify_windows_file_security(key_file)
                    except SerializationSecurityError as err:
                        raise KeySecurityError(str(err))

            key_id = hashlib.sha256(key).hexdigest()[:8]
            self._key = key
            self._key_id = key_id
            return key, key_id
        except Exception as e:
            if isinstance(e, KeySecurityError):
                raise
            raise KeySecurityError(f"Cannot secure external HMAC key: {e}")

    def compute_session_fingerprint(self, raw_token: str, program_id: str, credential_type: str) -> str:
        """
        Computes unambiguous length-prefixed keyed HMAC-SHA256[:32] fingerprint.
        Avoids delimiter collisions and prevents raw token persistence.
        """
        key, _ = self.get_or_create_hmac_key()
        p = program_id.encode("utf-8")
        t = credential_type.encode("utf-8")
        c = raw_token.encode("utf-8")

        # Binary canonical context: b"bb-v1\x00" + len4(p) + p + len4(t) + t + len4(c) + c
        context = (
            b"bb-v1\x00" +
            struct.pack(">I", len(p)) + p +
            struct.pack(">I", len(t)) + t +
            struct.pack(">I", len(c)) + c
        )
        return hmac.new(key, context, hashlib.sha256).hexdigest()[:32]

    def save_state(
        self,
        contexts: List[CorrelatedSessionContext],
        hypotheses: List[CorrelationHypothesis],
        findings: List[CorrelationFinding],
    ) -> None:
        """
        Atomically persists correlation state to state/auth_correlation.json.
        Applies full directory validation, descriptor verification via os.fstat(),
        and atomic replacement via os.replace().
        """
        raw_state = {
            "$schema": SUPPORTED_SCHEMA_ID,
            "version": "1.0.0",
            "program": self.program_id,
            "created_at": self.created_at,
            "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "key_id": self.key_id,
            "principals": {p.principal_id: p.to_dict() for p in self.principals.values()},
            "sessions": {s.session_ref: s.to_dict() for s in contexts},
            "hypotheses": [h.to_dict() for h in hypotheses],
            "findings": [f.to_dict() for f in findings],
        }

        validated = validate_state_schema(raw_state)
        state_dir = _verify_and_prepare_state_dir(self.state_dir, self.workspace_root)
        final_path = os.path.join(state_dir, "auth_correlation.json")
        temp_path = os.path.join(state_dir, f"auth_correlation.tmp.{uuid.uuid4().hex}.json")

        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        fd = -1
        try:
            fd = os.open(temp_path, flags, 0o600)
            fd_stat = os.fstat(fd)
            if not stat.S_ISREG(fd_stat.st_mode):
                raise SerializationSecurityError("Security violation: opened file descriptor is not a regular file")
            if fd_stat.st_nlink != 1:
                raise SerializationSecurityError("Security violation: temporary file has unexpected hardlinks")
            if os.name != "nt":
                if fd_stat.st_uid != os.getuid():
                    raise SerializationSecurityError("Security violation: temporary file ownership mismatch")
                if fd_stat.st_mode & 0o077 != 0:
                    raise SerializationSecurityError("Security violation: temporary file permissions too permissive")

            lst_stat = os.lstat(temp_path)
            if stat.S_ISLNK(lst_stat.st_mode):
                raise SerializationSecurityError("Security violation: temporary file is a symbolic link")
            if os.name == "nt" and hasattr(lst_stat, "st_file_attributes") and (lst_stat.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                raise SerializationSecurityError("Security violation: temporary file is a reparse point")
            if os.name != "nt":
                if (fd_stat.st_ino != lst_stat.st_ino) or (fd_stat.st_dev != lst_stat.st_dev):
                    raise SerializationSecurityError("Security violation: file descriptor inode does not match path inode")

            with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as f:
                json.dump(validated, f, indent=2)
                f.flush()
                os.fsync(fd)

            os.close(fd)
            fd = -1

            if os.path.lexists(final_path):
                dest_lst = os.lstat(final_path)
                if stat.S_ISLNK(dest_lst.st_mode):
                    raise SerializationSecurityError("Security violation: destination state file is a symbolic link")
                if os.name == "nt" and hasattr(dest_lst, "st_file_attributes") and (dest_lst.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                    raise SerializationSecurityError("Security violation: destination state file is an NTFS reparse point")

            os.replace(temp_path, final_path)
        finally:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except OSError:
                    pass

    def load_state(self) -> Dict[str, Any]:
        """
        Loads persistent state from state/auth_correlation.json using a descriptor-based
        procedure that eliminates TOCTOU races between path validation and reading.
        Applies identical symmetrical schema enforcement via validate_state_schema().
        Guarantees that state deserialized from disk adheres to the exact same security contract.
        """
        state_dir = _verify_and_prepare_state_dir(self.state_dir, self.workspace_root)
        state_file = os.path.join(state_dir, "auth_correlation.json")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        fd = -1
        try:
            try:
                fd = os.open(state_file, flags)
            except FileNotFoundError:
                raise StateSecurityValidationError("State file does not exist") from None
            except OSError:
                raise StateSecurityValidationError("Security violation: state file cannot be opened (possible symlink or loop)") from None

            fd_stat = os.fstat(fd)
            if not stat.S_ISREG(fd_stat.st_mode):
                raise StateSecurityValidationError("Security violation: state file descriptor is not a regular file")
            if fd_stat.st_nlink != 1:
                raise StateSecurityValidationError("Security violation: state file has unexpected hardlinks")

            if os.name != "nt":
                if fd_stat.st_uid != os.getuid():
                    raise StateSecurityValidationError("Security violation: state file ownership mismatch")
                if fd_stat.st_mode & 0o077 != 0:
                    raise StateSecurityValidationError("Security violation: state file permissions are not private")
            else:
                dest_lst = os.lstat(state_file)
                if hasattr(dest_lst, "st_file_attributes") and (dest_lst.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT):
                    raise StateSecurityValidationError("Security violation: state file is an NTFS reparse point")

            with os.fdopen(fd, "r", encoding="utf-8", closefd=True) as f:
                fd = -1
                raw_data = json.load(f)

        except json.JSONDecodeError:
            raise StateSecurityValidationError("State file is malformed JSON") from None
        finally:
            if fd != -1:
                try:
                    os.close(fd)
                except OSError:
                    pass

        return validate_state_schema(raw_data)

    def quarantine_corrupted_state(self) -> None:
        """Renames a malformed or corrupted state file to preserve forensics while unblocking execution."""
        state_file = os.path.join(self.state_dir, "auth_correlation.json")
        if os.path.exists(state_file):
            quarantine_name = os.path.join(self.state_dir, f"auth_correlation.corrupted.{int(time.time())}.json")
            try:
                os.replace(state_file, quarantine_name)
            except OSError:
                pass
