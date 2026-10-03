"""
Tests for Runtime Isolation, Directory Separation, and Sensitive Data Protection.
"""

import os
import tempfile
import pytest

from framework.common.config import (
    PROGRAM_SUBDIRECTORIES,
    get_program_dir,
    init_program_workspace,
    list_local_programs,
)
from framework.common.evidence import sanitize_sensitive_data


def test_program_workspace_isolation():
    with tempfile.TemporaryDirectory() as tmp_root:
        # Initialize two separate programs
        prog_a = init_program_workspace("program-alpha", workspace_root=tmp_root)
        prog_b = init_program_workspace("program-beta", workspace_root=tmp_root)

        # Check directories exist
        assert os.path.isdir(prog_a["program_root"])
        assert os.path.isdir(prog_b["program_root"])
        assert prog_a["program_root"] != prog_b["program_root"]

        # Check required subdirectories
        for subdir in PROGRAM_SUBDIRECTORIES:
            assert os.path.isdir(prog_a[subdir])
            assert os.path.isdir(prog_b[subdir])

        # Verify listing
        progs = list_local_programs(workspace_root=tmp_root)
        assert "program-alpha" in progs
        assert "program-beta" in progs


def test_sensitive_data_sanitization():
    raw_http = (
        "POST /api/v1/login HTTP/1.1\r\n"
        "Host: api.example.com\r\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.signature\r\n"
        "Cookie: sessionid=secret_session_token_12345; user=alice\r\n"
        "api-key: my_super_secret_api_key_xyz987\r\n"
        "\r\n"
        "{\"status\":\"active\"}"
    )

    sanitized = sanitize_sensitive_data(raw_http)

    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in sanitized
    assert "secret_session_token_12345" not in sanitized
    assert "my_super_secret_api_key_xyz987" not in sanitized
    assert "[REDACTED_BY_BB_AGENT]" in sanitized


def test_gitignore_covers_sensitive_runtime_data():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    gitignore_path = os.path.join(repo_root, ".gitignore")

    # If .gitignore exists, check rules
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        required_patterns = [
            "runtime/",
            ".env",
            "*.key",
            "*.token",
            "evidence/",
            "scans/",
            "*.burp",
        ]
        for pattern in required_patterns:
            assert pattern in content, f"Expected {pattern} in .gitignore"
