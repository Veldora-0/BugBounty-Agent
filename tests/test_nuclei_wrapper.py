"""No-network regressions for the bounded Nuclei wrapper."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

import yaml


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bb-nuclei"
LOADER = importlib.machinery.SourceFileLoader("bb_nuclei_test_module", str(SCRIPT_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
bb_nuclei = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(bb_nuclei)


def _workspace(tmp_path, monkeypatch):
    program_dir = tmp_path / "programs" / "test-program"
    scope_dir = program_dir / "scope"
    scope_dir.mkdir(parents=True)
    (scope_dir / "scope.yaml").write_text(
        yaml.safe_dump({
            "program": {"name": "test-program"},
            "targets": {"domains": ["example.com"]},
            "out_of_scope": {"domains": []},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(bb_nuclei, "get_program_dir", lambda _name: str(program_dir))
    monkeypatch.setattr(bb_nuclei, "resolve_public_destination_ips", lambda _host, _port: ["93.184.216.34"])
    monkeypatch.setattr(bb_nuclei.shutil, "which", lambda _name: "/usr/bin/nuclei")
    return program_dir


def _argv(monkeypatch, *extra):
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT_PATH), "https://example.com/path", "--program", "test-program", *extra],
    )


def _hit(matched_at="https://93.184.216.34/path"):
    return {
        "template-id": "test/exposure-001",
        "matched-at": matched_at,
        "matcher-name": "header-match",
        "info": {
            "name": "Exposed Header",
            "severity": "low",
            "description": "Example template result",
            "remediation": "Review the configuration",
        },
        "request": "Authorization: Bearer topsecret",
        "response": "Cookie: session=topsecret",
    }


def test_scan_requires_explicit_program_approval(monkeypatch):
    _argv(monkeypatch)
    subprocess_calls = []
    monkeypatch.setattr(bb_nuclei.subprocess, "run", lambda *args, **kwargs: subprocess_calls.append(args))

    assert bb_nuclei.main() == 2
    assert subprocess_calls == []


def test_command_pins_target_and_keeps_hard_scan_bounds(tmp_path):
    command = bb_nuclei.build_nuclei_command(
        "https://93.184.216.34/path",
        "example.com",
        443,
        str(tmp_path / "out.jsonl"),
        str(tmp_path / "safe-config.yaml"),
        ["exposure"],
        ["low"],
        "https",
    )

    assert command[command.index("-target") + 1] == "https://93.184.216.34/path"
    assert command[command.index("-config") + 1] == str(tmp_path / "safe-config.yaml")
    assert command[command.index("-rate-limit") + 1] == "1"
    assert command[command.index("-concurrency") + 1] == "1"
    assert command[command.index("-timeout") + 1] == "5"
    assert command[command.index("-retries") + 1] == "0"
    assert command[command.index("-type") + 1] == "http"
    assert "-disable-redirects" in command
    assert "-no-interactsh" in command
    assert "-restrict-local-network-access" in command
    assert command[command.index("-header") + 1] == "Host: example.com"
    assert command[command.index("-sni") + 1] == "example.com"
    assert "-dast" not in command and "-headless" not in command


def test_main_scans_pinned_ip_and_ingests_only_curated_candidate(tmp_path, monkeypatch):
    program_dir = _workspace(tmp_path, monkeypatch)
    _argv(monkeypatch, "--approve-active-scan")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        output = command[command.index("-json-export") + 1]
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(_hit()) + "\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bb_nuclei.subprocess, "run", fake_run)
    assert bb_nuclei.main() == 0

    command = captured["command"]
    assert command[command.index("-target") + 1] == "https://93.184.216.34/path"
    assert captured["kwargs"]["timeout"] == bb_nuclei.MAX_RUNTIME_SECONDS
    assert captured["kwargs"]["stdout"] == bb_nuclei.subprocess.DEVNULL
    output_path = command[command.index("-json-export") + 1]
    assert os.stat(output_path).st_mode & 0o777 == 0o600
    assert os.stat(os.path.dirname(output_path)).st_mode & 0o777 == 0o700

    from framework.state.manager import StateManager

    findings = StateManager(str(program_dir)).get_findings()
    assert len(findings) == 1
    assert findings[0].lifecycle_state.value == "CANDIDATE"
    serialized = json.dumps(findings[0].to_dict())
    assert "Bearer topsecret" not in serialized
    assert "Cookie: session=topsecret" not in serialized
    assert findings[0].provenance.get("raw_hit") is None


def test_failed_process_output_is_never_ingested(tmp_path, monkeypatch):
    program_dir = _workspace(tmp_path, monkeypatch)
    _argv(monkeypatch, "--approve-active-scan")

    def fake_run(command, **kwargs):
        output = command[command.index("-json-export") + 1]
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(_hit()) + "\n")
        return SimpleNamespace(returncode=3)

    monkeypatch.setattr(bb_nuclei.subprocess, "run", fake_run)
    assert bb_nuclei.main() == 1
    assert not list((program_dir / "scans").glob("nuclei_*.jsonl"))
    assert not (program_dir / "state" / "findings.json").exists()


def test_result_for_another_host_is_discarded(tmp_path, monkeypatch):
    program_dir = _workspace(tmp_path, monkeypatch)
    _argv(monkeypatch, "--approve-active-scan")

    def fake_run(command, **kwargs):
        output = command[command.index("-json-export") + 1]
        with open(output, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(_hit("https://other.example/path")) + "\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(bb_nuclei.subprocess, "run", fake_run)
    assert bb_nuclei.main() == 0

    from framework.state.manager import StateManager

    assert StateManager(str(program_dir)).get_findings() == []
