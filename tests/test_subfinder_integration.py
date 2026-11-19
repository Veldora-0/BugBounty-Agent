"""No-network tests for bounded passive Subfinder asset discovery."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import yaml

from framework.assets.subfinder import build_subfinder_command, run_subfinder
from framework.scope.engine import ScopeEngine
from framework.state.manager import StateManager


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bb-assets"
LOADER = importlib.machinery.SourceFileLoader("bb_assets_test_module", str(SCRIPT_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
bb_assets = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(bb_assets)


def _scope():
    return ScopeEngine({
        "program": {"name": "test-program"},
        "targets": {"domains": ["example.com"], "recursive_subdomains": {"enabled": True}},
        "out_of_scope": {"domains": ["private.example.com"]},
    })


def test_command_is_fixed_passive_and_resource_bounded(tmp_path):
    command = build_subfinder_command("/usr/bin/subfinder", "example.com", str(tmp_path / "out.jsonl"), str(tmp_path / "config.yaml"))
    assert command[command.index("-domain") + 1] == "example.com"
    assert command[command.index("-rate-limit") + 1] == "2"
    assert command[command.index("-timeout") + 1] == "8"
    assert command[command.index("-max-time") + 1] == "1"
    assert command[command.index("-t") + 1] == "1"
    assert "-json" in command and "-collect-sources" in command
    assert "-active" not in command and "-recursive" not in command


def test_run_subfinder_scope_filters_and_attributes_passive_results(tmp_path, monkeypatch):
    monkeypatch.setattr("framework.assets.subfinder.shutil.which", lambda _name: "/usr/bin/subfinder")

    def fake_run(command, **_kwargs):
        output = command[command.index("-output") + 1]
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(json.dumps({"host": "api.example.com", "sources": ["crtsh", "dnsdumpster"]}) + "\n")
            stream.write(json.dumps({"host": "admin.api.example.com", "source": "crtsh"}) + "\n")
            stream.write(json.dumps({"host": "private.example.com", "source": "crtsh"}) + "\n")
            stream.write(json.dumps({"host": "attacker.example.net", "source": "crtsh"}) + "\n")
            stream.write("not-json\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("framework.assets.subfinder.subprocess.run", fake_run)
    result = run_subfinder("EXAMPLE.COM.", _scope())
    assert result == [
        {"hostname": "api.example.com", "sources": ["crtsh", "dnsdumpster"]},
        {"hostname": "admin.api.example.com", "sources": ["crtsh"]},
    ]


def test_run_subfinder_requires_in_scope_root_and_installed_binary(monkeypatch):
    monkeypatch.setattr("framework.assets.subfinder.shutil.which", lambda _name: None)
    try:
        run_subfinder("attacker.example.net", _scope())
    except ValueError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("out-of-scope root was accepted")

    try:
        run_subfinder("example.com", _scope())
    except FileNotFoundError as exc:
        assert "not installed" in str(exc)
    else:
        raise AssertionError("missing Subfinder binary was accepted")


def test_bb_assets_wires_passive_results_to_scoped_state(tmp_path, monkeypatch):
    program_dir = tmp_path / "program"
    scope_dir = program_dir / "scope"
    scope_dir.mkdir(parents=True)
    scope_path = scope_dir / "scope.yaml"
    scope_path.write_text(yaml.safe_dump({
        "program": {"name": "test-program"},
        "targets": {"domains": ["example.com"], "recursive_subdomains": {"enabled": True}},
        "out_of_scope": {"domains": ["private.example.com"]},
    }), encoding="utf-8")

    monkeypatch.setattr(bb_assets, "get_program_dir", lambda _name: str(program_dir))
    monkeypatch.setattr(bb_assets, "resolve_program_scope_file", lambda _program_dir, _scope: str(scope_path))
    monkeypatch.setattr(bb_assets, "run_subfinder", lambda _root, _engine: [
        {"hostname": "api.example.com", "sources": ["crtsh"]},
        {"hostname": "admin.api.example.com", "sources": ["crtsh", "dnsdumpster"]},
    ])
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "--program", "test-program", "--subfinder", "--passive-only"])

    bb_assets.main()
    graph = StateManager(str(program_dir)).get_asset_graph()
    api = graph.get_asset("api.example.com")
    admin = graph.get_asset("admin.api.example.com")
    assert api is not None and api.scope_status == "IN_SCOPE"
    assert admin is not None and admin.scope_status == "IN_SCOPE"
    assert api.provenance[-1].source == "subfinder"
    assert api.attributes["passive_discovery_sources"] == ["crtsh"]
    assert admin.attributes["passive_discovery_sources"] == ["crtsh", "dnsdumpster"]
    assert graph.get_asset("private.example.com") is None
