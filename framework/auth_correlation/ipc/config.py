"""Fail-closed readers for dispatcher trust configuration."""

from __future__ import annotations

import os
import stat
from typing import Any


class DispatcherConfigurationError(ValueError):
    """Raised when dispatcher trust configuration is missing or unsafe."""


def _read_trusted_file(path: str, *, maximum_bytes: int) -> bytes:
    if not path or not isinstance(path, str):
        raise DispatcherConfigurationError("Configuration path must be a non-empty string")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(os.path.abspath(path), flags)
    except OSError as exc:
        raise DispatcherConfigurationError(f"Cannot open dispatcher configuration file: {exc}") from exc

    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise DispatcherConfigurationError("Dispatcher configuration must be a regular file")
        if metadata.st_nlink != 1:
            raise DispatcherConfigurationError("Dispatcher configuration file must not have hard links")
        if metadata.st_mode & 0o022:
            raise DispatcherConfigurationError("Dispatcher configuration must not be group- or world-writable")
        if metadata.st_size > maximum_bytes:
            raise DispatcherConfigurationError("Dispatcher configuration exceeds its size limit")

        with os.fdopen(fd, "rb", closefd=False) as stream:
            contents = stream.read(maximum_bytes + 1)
        if len(contents) > maximum_bytes:
            raise DispatcherConfigurationError("Dispatcher configuration exceeds its size limit")
        return contents
    finally:
        os.close(fd)


def load_operator_approval_key(path: str) -> bytes:
    """Load a 32-byte HMAC key without following links or accepting writable files."""
    key = _read_trusted_file(path, maximum_bytes=33)
    if len(key) != 32:
        raise DispatcherConfigurationError("Operator approval key must contain exactly 32 bytes")
    return key


def load_scope_engine(path: str) -> Any:
    """Load a validated program scope from a bounded, non-writable file."""
    import yaml

    from framework.scope.engine import ScopeEngine

    raw = _read_trusted_file(path, maximum_bytes=1024 * 1024)
    try:
        config = yaml.safe_load(raw.decode("utf-8"))
        return ScopeEngine(config or {})
    except Exception as exc:
        raise DispatcherConfigurationError(f"Invalid dispatcher scope configuration: {exc}") from exc
