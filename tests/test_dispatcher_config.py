"""Security tests for the Linux dispatcher's externally managed trust config."""

import os
import pytest

from framework.auth_correlation.ipc.config import (
    DispatcherConfigurationError,
    load_operator_approval_key,
    load_scope_engine,
)


pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="The systemd dispatcher trust-file contract is Linux-only",
)


def test_load_operator_approval_key_accepts_private_32_byte_file(tmp_path):
    key_path = tmp_path / "operator.key"
    key_path.write_bytes(b"k" * 32)
    os.chmod(key_path, 0o640)

    assert load_operator_approval_key(str(key_path)) == b"k" * 32


@pytest.mark.parametrize("contents", [b"", b"k" * 31, b"k" * 33])
def test_load_operator_approval_key_rejects_wrong_length(tmp_path, contents):
    key_path = tmp_path / "operator.key"
    key_path.write_bytes(contents)
    os.chmod(key_path, 0o600)

    with pytest.raises(DispatcherConfigurationError, match="exactly 32 bytes"):
        load_operator_approval_key(str(key_path))


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are required for this permission check")
def test_load_operator_approval_key_rejects_group_writable_file(tmp_path):
    key_path = tmp_path / "operator.key"
    key_path.write_bytes(b"k" * 32)
    os.chmod(key_path, 0o660)

    with pytest.raises(DispatcherConfigurationError, match="group- or world-writable"):
        load_operator_approval_key(str(key_path))


@pytest.mark.skipif(os.name == "nt", reason="POSIX hard-link semantics are required")
def test_load_operator_approval_key_rejects_hard_link(tmp_path):
    key_path = tmp_path / "operator.key"
    linked_path = tmp_path / "operator-copy.key"
    key_path.write_bytes(b"k" * 32)
    os.chmod(key_path, 0o600)
    os.link(key_path, linked_path)

    with pytest.raises(DispatcherConfigurationError, match="hard links"):
        load_operator_approval_key(str(key_path))


def test_load_scope_engine_applies_inclusions_and_exclusions(tmp_path):
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(
        "program:\n  name: Example Program\ntargets:\n  domains:\n    - example.test\n"
        "  recursive_subdomains:\n    enabled: true\n    max_depth: 0\n"
        "out_of_scope:\n  domains:\n    - private.example.test\n",
        encoding="utf-8",
    )
    os.chmod(scope_path, 0o640)

    scope = load_scope_engine(str(scope_path))

    assert scope.is_in_scope("https://api.example.test/") is True
    assert scope.is_in_scope("https://private.example.test/") is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink-open semantics are required")
def test_load_scope_engine_rejects_symlink(tmp_path):
    real_path = tmp_path / "real-scope.yaml"
    link_path = tmp_path / "scope.yaml"
    real_path.write_text("targets:\n  domains: [example.test]\n", encoding="utf-8")
    os.chmod(real_path, 0o640)
    link_path.symlink_to(real_path)

    with pytest.raises(DispatcherConfigurationError, match="Cannot open"):
        load_scope_engine(str(link_path))


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are required for this permission check")
def test_load_scope_engine_rejects_group_writable_file(tmp_path):
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text("targets:\n  domains: [example.test]\n", encoding="utf-8")
    os.chmod(scope_path, 0o660)

    with pytest.raises(DispatcherConfigurationError, match="group- or world-writable"):
        load_scope_engine(str(scope_path))


def test_load_scope_engine_rejects_invalid_schema(tmp_path):
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text("targets: invalid\n", encoding="utf-8")
    os.chmod(scope_path, 0o600)

    with pytest.raises(DispatcherConfigurationError, match="Invalid dispatcher scope"):
        load_scope_engine(str(scope_path))
