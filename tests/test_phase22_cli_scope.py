"""Fail-closed scope resolution tests for the Phase 22 CLI."""

from __future__ import annotations

import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.scope.engine import ScopeStatus


CLI_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bb-chain"


@pytest.fixture
def cli_namespace():
    return runpy.run_path(str(CLI_PATH), run_name="bb_chain_scope_test")


def test_scope_resolution_uses_canonical_program_scope_path(cli_namespace, tmp_path):
    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    (scope_dir / "scope.yaml").write_text(
        "program:\n  name: test-program\ntargets:\n  domains:\n    - authorized.example\nout_of_scope:\n  domains: []\n",
        encoding="utf-8",
    )

    scope = cli_namespace["resolve_scope_engine"](str(tmp_path))

    assert scope is not None
    assert scope.check("authorized.example").status == ScopeStatus.IN_SCOPE
    assert scope.check("example.com").status == ScopeStatus.OUT_OF_SCOPE


def test_default_chain_program_directory_is_under_current_directory(cli_namespace, monkeypatch, tmp_path):
    monkeypatch.delenv("BUGBOUNTY_WORKSPACE", raising=False)
    monkeypatch.chdir(tmp_path)

    program_dir = cli_namespace["resolve_program_directory"]("Example Program", None)

    assert Path(program_dir) == tmp_path / "programs" / "exampleprogram"
    assert (Path(program_dir) / "state").is_dir()


def test_missing_or_invalid_scope_fails_closed(cli_namespace, tmp_path):
    assert cli_namespace["resolve_scope_engine"](str(tmp_path)) is None

    scope_dir = tmp_path / "scope"
    scope_dir.mkdir()
    (scope_dir / "scope.yaml").write_text("targets: [\n", encoding="utf-8")
    assert cli_namespace["resolve_scope_engine"](str(tmp_path)) is None


def test_validate_command_refuses_to_dispatch_without_scope(cli_namespace, tmp_path, capsys):
    state_mgr = SimpleNamespace(
        program_dir=str(tmp_path),
        load_plans=lambda: {"PLAN-safe1": SimpleNamespace(plan_id="PLAN-safe1")},
    )

    result = cli_namespace["cmd_validate"](SimpleNamespace(plan_id="PLAN-safe1"), state_mgr)

    assert result == 1
    assert "valid program scope file is required" in capsys.readouterr().err
