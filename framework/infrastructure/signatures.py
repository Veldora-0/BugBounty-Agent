"""
Deterministic Content and Signature Matchers for BugBounty-Agent Infrastructure Intelligence.

Provides strict, non-destructive signature evaluation across all 8 exposure classes.
Guarantees:
- Rejects HTML soft-404 responses for non-HTML categories (.git, .env, backups).
- Accurately differentiates login forms (OBSERVATION) from open diagnostic consoles.
- Distinguishes sensitive credential keys from benign configuration parameters.
- Truncates inspection streams early via evidence-sufficiency rules.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple


# Regex to detect HTML documents
HTML_DOCTYPE_REGEX = re.compile(r"<!DOCTYPE\s+html|<html[\s>]|<body[\s>]|<head[\s>]", re.IGNORECASE)

# Version control signatures
GIT_HEAD_REF_REGEX = re.compile(r"^ref:\s*refs/heads/[a-zA-Z0-9_\-./]+", re.MULTILINE)
GIT_HEAD_SHA_REGEX = re.compile(r"^[0-9a-fA-F]{40}\s*$", re.MULTILINE)
GIT_CONFIG_CORE_REGEX = re.compile(r"\[core\][\s\S]*?repositoryformatversion\s*=", re.IGNORECASE)

# Environment and configuration file signatures
ENV_KEY_VAL_REGEX = re.compile(r"^[A-Z0-9_]{3,}\s*=\s*[^\r\n]*", re.MULTILINE)
SENSITIVE_KEY_REGEX = re.compile(
    r"\b(?:PASSWORD|PASSWD|PWD|SECRET|SECRET_KEY|API_KEY|APIKEY|ACCESS_KEY|AUTH_TOKEN|"
    r"DATABASE_URL|DB_PASS|PRIVATE_KEY|TOKEN|JWT_SECRET|CREDENTIALS?|AWS_SECRET)\b",
    re.IGNORECASE,
)

# Open Directory Listing signatures
DIR_LISTING_SIGNATURES = [
    re.compile(r"<title>\s*Index of\s+/[^<]*</title>", re.IGNORECASE),
    re.compile(r"<h1>\s*Index of\s+/[^<]*</h1>", re.IGNORECASE),
    re.compile(r"Directory\s+Listing\s+For\s+/", re.IGNORECASE),
    re.compile(r"\[To Parent Directory\]", re.IGNORECASE),
]

# Login form indicators
LOGIN_FORM_INDICATORS = [
    re.compile(r"<input[^>]*type=[\"']password[\"']", re.IGNORECASE),
    re.compile(r"<form[^>]*action=[^>]*login", re.IGNORECASE),
    re.compile(r"<button[^>]*>[^<]*(?:log\s*in|sign\s*in|submit)[^<]*</button>", re.IGNORECASE),
]

# Debug error stack trace signatures
DEBUG_STACK_SIGNATURES = [
    ("Django Debug", re.compile(r"You're seeing this error because you have <code>DEBUG\s*=\s*True</code>", re.IGNORECASE)),
    ("Laravel Ignition", re.compile(r"<title>.*Ignition.*</title>|window\.ignition", re.IGNORECASE)),
    ("Python Traceback", re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE)),
    ("Rails Routing Error", re.compile(r"ActionController::RoutingError|Rails\.root:", re.IGNORECASE)),
    ("Spring Whitelabel Error", re.compile(r"Whitelabel Error Page|This application has no explicit mapping for /error", re.IGNORECASE)),
]


class InfrastructureSignatures:
    """Deterministic signature evaluation methods."""

    @staticmethod
    def is_html(content: str | bytes) -> bool:
        """Determines if the payload represents an HTML document."""
        if isinstance(content, bytes):
            sample = content[:4096].decode("utf-8", errors="replace")
        else:
            sample = content[:4096]
        return bool(HTML_DOCTYPE_REGEX.search(sample))

    @staticmethod
    def match_version_control(content: str | bytes) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates version control metadata (e.g. .git/HEAD, .git/config, .svn/wc.db).
        Returns (is_match, reason, metadata).
        """
        if InfrastructureSignatures.is_html(content):
            return False, "Response is HTML (SPA catch-all or error page)", {}

        if isinstance(content, bytes):
            text = content[:2048].decode("utf-8", errors="replace")
            raw_bytes = content[:512]
        else:
            text = content[:2048]
            raw_bytes = content[:512].encode("utf-8", errors="replace")

        # Check .git/HEAD
        clean_text = text.strip()
        ref_match = GIT_HEAD_REF_REGEX.search(clean_text)
        if ref_match:
            ref_str = ref_match.group(0).strip()
            return True, "Valid .git/HEAD branch reference", {"type": "git_head", "ref": ref_str}

        sha_match = GIT_HEAD_SHA_REGEX.search(clean_text)
        if sha_match:
            sha_str = sha_match.group(0).strip()
            return True, "Valid .git/HEAD commit SHA", {"type": "git_head_sha", "sha": sha_str}

        # Check .git/config
        if GIT_CONFIG_CORE_REGEX.search(text):
            return True, "Valid .git/config repository configuration", {"type": "git_config"}

        # Check .svn
        if raw_bytes.startswith(b"SQLite format 3") and b"wc.db" in raw_bytes:
            return True, "Valid .svn/wc.db Subversion database", {"type": "svn_db"}

        return False, "No recognized version control markers found", {}

    @staticmethod
    def match_config_file(content: str | bytes) -> Tuple[bool, str, Dict[str, Any], bool]:
        """
        Validates environment / configuration files (e.g. .env, web.config).
        Returns (is_match, reason, metadata, has_sensitive_keys).
        Stopping rule: requires at least 2 valid key-value pairs; halts evaluation.
        """
        if InfrastructureSignatures.is_html(content):
            return False, "Response is HTML (SPA catch-all or error page)", {}, False

        if isinstance(content, bytes):
            text = content[:8192].decode("utf-8", errors="replace")
        else:
            text = content[:8192]

        lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
        valid_keys: List[str] = []
        has_sensitive = False

        SENSITIVE_KEY_PATTERNS = [
            "PASS", "PWD", "SECRET", "TOKEN", "KEY", "CREDENTIAL",
            "DATABASE_URL", "AUTH", "PRIVATE", "APIKEY", "ACCESS",
        ]

        for line in lines:
            if "=" in line:
                key = line.split("=", 1)[0].strip()
                if re.match(r"^[A-Z0-9_]{3,}$", key, re.IGNORECASE):
                    valid_keys.append(key)
                    key_upper = key.upper()
                    if any(p in key_upper for p in SENSITIVE_KEY_PATTERNS):
                        has_sensitive = True

        # Require at least 2 valid key-value pairs to prevent single false-positive match
        if len(valid_keys) >= 2:
            return True, f"Found {len(valid_keys)} configuration keys", {
                "key_count": len(valid_keys),
                "keys_preview": valid_keys[:5],
                "has_sensitive_keys": has_sensitive,
            }, has_sensitive

        # Check web.config (XML)
        if "<configuration>" in text.lower() and ("<system.web" in text.lower() or "<connectionstrings" in text.lower()):
            has_sensitive = "connectionstring" in text.lower() or "password" in text.lower()
            return True, "Valid ASP.NET web.config configuration", {
                "type": "web.config",
                "has_sensitive_keys": has_sensitive,
            }, has_sensitive

        return False, "Insufficient configuration markers found", {}, False

    @staticmethod
    def match_backup_archive(raw_bytes: bytes, content_type: str = "") -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates backup/archive files using binary magic bytes.
        Stopping rule: inspects only first 512–1024 bytes; aborts further reading.
        Returns (is_match, reason, metadata).
        """
        if "text/html" in content_type.lower():
            return False, "Content-Type is text/html", {}

        header = raw_bytes[:1024]
        if len(header) < 4:
            return False, "Payload too short to verify magic bytes", {}

        # Zip magic bytes: PK\x03\x04
        if header.startswith(b"PK\x03\x04"):
            return True, "Verified ZIP archive magic bytes (PK\\x03\\x04)", {"format": "zip", "magic": "PK\\x03\\x04"}

        # Gzip magic bytes: \x1f\x8b
        if header.startswith(b"\x1f\x8b"):
            return True, "Verified GZIP archive magic bytes (\\x1f\\x8b)", {"format": "gzip", "magic": "\\x1f\\x8b"}

        # Tar magic bytes: 'ustar' at offset 257
        if len(header) >= 262 and header[257:262] == b"ustar":
            return True, "Verified POSIX TAR archive header (ustar)", {"format": "tar", "magic": "ustar"}

        # SQL Dump check: initial SQL comment headers
        try:
            head_text = header[:512].decode("utf-8", errors="ignore")
            if head_text.startswith(("-- MySQL dump", "-- PostgreSQL database dump", "/*M!999999\\- enable max")):
                return True, "Verified SQL database dump header", {"format": "sql_dump"}
            if "CREATE TABLE " in head_text.upper() or "INSERT INTO " in head_text.upper():
                return True, "Verified SQL DDL/DML statements", {"format": "sql_statements"}
        except Exception:
            pass

        return False, "No valid backup/archive magic bytes detected", {}

    @staticmethod
    def match_admin_interface(content: str, status_code: int = 200) -> Tuple[bool, str, Dict[str, Any], bool]:
        """
        Evaluates administrative surfaces.
        Differentiates protected login pages (OBSERVATION) from open diagnostic dashboards (VALIDATED).
        Returns (is_match, reason, metadata, is_login_page).
        """
        if status_code != 200:
            return False, f"Unexpected status code {status_code}", {}, False

        # 1. Check for standard login forms
        has_password = bool(LOGIN_FORM_INDICATORS[0].search(content))
        has_login_form = bool(LOGIN_FORM_INDICATORS[1].search(content))
        if has_password and (has_login_form or "login" in content.lower()):
            return True, "Protected administrative login interface detected", {
                "surface": "login_page",
            }, True

        # 2. Check for open diagnostic dashboards
        # Prometheus metrics
        if "# HELP " in content and "# TYPE " in content:
            return True, "Open Prometheus metrics exposition", {
                "surface": "prometheus_metrics",
            }, False

        # Spring Boot Actuator health/info
        if "application/json" in content or content.strip().startswith("{"):
            try:
                data = json.loads(content[:4096])
                if isinstance(data, dict):
                    if "status" in data and ("UP" in str(data["status"]) or "DOWN" in str(data["status"])):
                        return True, "Open Spring Boot Actuator health endpoint", {
                            "surface": "actuator_health",
                            "health_status": data.get("status"),
                        }, False
                    if "_links" in data and isinstance(data["_links"], dict):
                        return True, "Open Spring Boot Actuator discovery index", {
                            "surface": "actuator_index",
                        }, False
            except Exception:
                pass

        # Grafana / Solr open dashboards
        if "<title>Grafana</title>" in content or "window.grafanaBootData" in content:
            return True, "Exposed Grafana dashboard interface", {"surface": "grafana"}, False

        if "Solr Admin" in content or "solr-spec-version" in content:
            return True, "Exposed Apache Solr administration console", {"surface": "solr"}, False

        return False, "No recognized administrative interface signatures found", {}, False

    @staticmethod
    def match_deployment_manifest(content: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates build and package manifests (composer.json, package.json, Dockerfile).
        Returns (is_match, reason, metadata).
        """
        if InfrastructureSignatures.is_html(content):
            return False, "Response is HTML", {}

        clean = content.strip()

        # JSON manifests
        if clean.startswith("{"):
            try:
                data = json.loads(clean[:8192])
                if isinstance(data, dict):
                    # composer.json
                    if "require" in data or "require-dev" in data:
                        return True, "Valid composer.json PHP dependency manifest", {
                            "manifest_type": "composer.json",
                            "name": data.get("name", "unnamed"),
                        }
                    # package.json
                    if "name" in data and ("dependencies" in data or "devDependencies" in data or "scripts" in data):
                        return True, "Valid package.json Node.js dependency manifest", {
                            "manifest_type": "package.json",
                            "name": data.get("name", "unnamed"),
                        }
            except Exception:
                pass

        # Dockerfile
        lines = [line.strip() for line in clean.splitlines() if line.strip() and not line.strip().startswith("#")]
        if lines and lines[0].upper().startswith("FROM "):
            return True, "Valid Dockerfile container recipe", {"manifest_type": "Dockerfile"}

        return False, "No recognized deployment manifest markers", {}

    @staticmethod
    def match_source_map(content: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates frontend JavaScript source maps (.js.map).
        Stopping rule: reads root JSON keys; stops at 8 KB without dumping full source tree.
        Returns (is_match, reason, metadata).
        """
        if InfrastructureSignatures.is_html(content):
            return False, "Response is HTML", {}

        clean = content.strip()
        if not clean.startswith("{"):
            return False, "Source map must be a JSON object", {}

        try:
            data = json.loads(clean[:8192])
            if isinstance(data, dict) and "version" in data and "sources" in data and "mappings" in data:
                sources = data.get("sources", [])
                source_count = len(sources) if isinstance(sources, list) else 0
                sample_sources = sources[:5] if isinstance(sources, list) else []
                return True, f"Valid JavaScript source map containing {source_count} source files", {
                    "version": data.get("version"),
                    "source_count": source_count,
                    "sample_sources": sample_sources,
                }
        except Exception:
            pass

        return False, "JSON does not match JavaScript source map schema", {}

    @staticmethod
    def match_directory_listing(content: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates open web server directory listings (e.g. Apache/Nginx Index of /).
        Returns (is_match, reason, metadata).
        """
        matched_sig = False
        for sig in DIR_LISTING_SIGNATURES:
            if sig.search(content):
                matched_sig = True
                break

        if not matched_sig:
            return False, "No directory listing title or header signature", {}

        # Verify presence of file links or parent directory navigation
        has_links = bool(re.search(r"<a\s+href=[\"'][^\"']+[\"']>", content, re.IGNORECASE))
        has_parent = bool(re.search(r"Parent\s+Directory|\[To\s+Parent\s+Directory\]|\.\./", content, re.IGNORECASE))

        if has_links and has_parent:
            return True, "Open web server directory listing with file index", {
                "type": "directory_index",
            }

        return False, "Header matched but missing structural file list links", {}

    @staticmethod
    def match_debug_interface(content: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates exposed debug stack traces or error handlers.
        Returns (is_match, reason, metadata).
        """
        for framework, sig in DEBUG_STACK_SIGNATURES:
            if sig.search(content):
                return True, f"Verbose framework debug stack trace ({framework})", {
                    "framework": framework,
                }

        return False, "No recognized debug stack trace signatures found", {}
