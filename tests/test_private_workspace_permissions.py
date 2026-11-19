"""Sensitive workspace and report files must use private permissions."""

from __future__ import annotations

import os

import pytest

from framework.common.config import (
    ensure_private_directory,
    init_program_workspace,
    write_private_text_file,
)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are verified on Linux; Windows DACLs use platform tests")
def test_program_workspace_directories_are_private(tmp_path):
    paths = init_program_workspace("private-test", str(tmp_path))
    for directory in paths.values():
        assert os.stat(directory).st_mode & 0o777 == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are verified on Linux; Windows DACLs use platform tests")
def test_existing_sensitive_directory_is_tightened(tmp_path):
    target = tmp_path / "reports"
    target.mkdir(mode=0o755)
    os.chmod(target, 0o755)

    ensure_private_directory(str(target))

    assert os.stat(target).st_mode & 0o777 == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are verified on Linux; Windows DACLs use platform tests")
def test_private_report_write_is_atomic_and_mode_0600(tmp_path):
    report_dir = tmp_path / "reports"
    path = report_dir / "finding.md"

    write_private_text_file(str(path), "private report\n")

    assert path.read_text(encoding="utf-8") == "private report\n"
    assert os.stat(path).st_mode & 0o777 == 0o600
    assert os.stat(report_dir).st_mode & 0o777 == 0o700
    assert not list(report_dir.glob(".private-write-*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink semantics are verified on Linux")
def test_private_writer_rejects_symlink_target(tmp_path):
    real_file = tmp_path / "real.md"
    real_file.write_text("keep", encoding="utf-8")
    link = tmp_path / "report.md"
    try:
        link.symlink_to(real_file)
    except OSError as exc:
        pytest.skip(f"Symlink creation unavailable: {exc}")

    with pytest.raises(PermissionError, match="symbolic link"):
        write_private_text_file(str(link), "replace")
    assert real_file.read_text(encoding="utf-8") == "keep"
