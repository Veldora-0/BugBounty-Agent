"""Keep the package, runtime and latest changelog release in sync."""

from __future__ import annotations

import re
from pathlib import Path

import framework


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_package_runtime_and_latest_release_versions_match():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    package_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
    release_match = re.search(r'^## \[([^\]]+)\] - \d{4}-\d{2}-\d{2}', changelog, re.MULTILINE)

    assert package_match is not None
    assert release_match is not None
    assert package_match.group(1) == framework.__version__ == release_match.group(1)
