"""Safety-bound tests for the scope-checked content-discovery CLI."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from framework.scope.engine import ScopeStatus


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "bb-content"


def load_cli():
    loader = importlib.machinery.SourceFileLoader("bb_content_test_module", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--rate", "0"],
        ["--rate", "11"],
        ["--max-requests", "0"],
        ["--max-requests", "1001"],
        ["--max-runtime", "0"],
        ["--max-runtime", "301"],
    ],
)
def test_content_cli_rejects_unbounded_limits_before_workspace_access(monkeypatch, extra_args):
    module = load_cli()
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), "https://api.example.org/FUZZ", "--program", "demo", "--wordlist", "unused.txt", *extra_args])
    monkeypatch.setattr(module, "get_program_dir", lambda _name: pytest.fail("workspace must not be read"))

    with pytest.raises(SystemExit) as exc:
        module.main()

    assert exc.value.code == 2


@pytest.mark.parametrize(
    "url",
    [
        "ftp://api.example.org/FUZZ",
        "https://user:pass@api.example.org/FUZZ",
        "https://FUZZ.example.org/path",
        "https://api.example.org/FUZZ/FUZZ",
    ],
)
def test_content_cli_rejects_unsafe_url_templates_before_workspace_access(monkeypatch, url):
    module = load_cli()
    monkeypatch.setattr(sys, "argv", [str(SCRIPT_PATH), url, "--program", "demo", "--wordlist", "unused.txt"])
    monkeypatch.setattr(module, "get_program_dir", lambda _name: pytest.fail("workspace must not be read"))

    with pytest.raises(SystemExit) as exc:
        module.main()

    assert exc.value.code == 2


def test_content_cli_uses_pinned_safe_transport_and_bounded_entries(monkeypatch, tmp_path):
    module = load_cli()
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("one\ntwo\nthree\nfour\n", encoding="utf-8")
    seen = {"urls": [], "calls": []}

    class FakeScope:
        @classmethod
        def from_file(cls, _path):
            return cls()

        def check(self, url):
            seen.setdefault("checked", []).append(url)
            return SimpleNamespace(status=ScopeStatus.IN_SCOPE, reason="fixture")

    def fake_fetch(url, **kwargs):
        seen["urls"].append(url)
        seen["calls"].append(kwargs)
        return {
            "status_code": 200,
            "headers": {"Content-Type": "text/plain"},
            "raw_bytes": b"fixture-body",
            "final_url": url,
        }

    monkeypatch.setattr(module, "get_program_dir", lambda _name: str(tmp_path))
    monkeypatch.setattr(module, "resolve_program_scope_file", lambda *_args: str(tmp_path / "scope.yaml"))
    monkeypatch.setattr(module, "ScopeEngine", FakeScope)
    monkeypatch.setattr(module, "safe_fetch_url", fake_fetch)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(module.time, "monotonic", iter([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]).__next__)
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT_PATH), "https://api.example.org/FUZZ", "--program", "demo", "--wordlist", str(wordlist), "--max-requests", "2"],
    )

    assert module.main() == 0

    assert seen["urls"] == ["https://api.example.org/one", "https://api.example.org/two"]
    assert all(call["scope_engine"].__class__ is FakeScope for call in seen["calls"])
    assert all(call["max_bytes"] == module.MAX_RESPONSE_BYTES for call in seen["calls"])
    assert all(call["max_redirects"] == 3 for call in seen["calls"])
    output_file = tmp_path / "scans" / "content_api.example.org.json"
    saved = json.loads(output_file.read_text(encoding="utf-8"))
    assert saved["attempted"] == 2
    assert saved["results"] == [
        {"path": "/one", "status_code": 200, "content_length_sampled": 12, "content_type": "text/plain"},
        {"path": "/two", "status_code": 200, "content_length_sampled": 12, "content_type": "text/plain"},
    ]
    assert "fixture-body" not in output_file.read_text(encoding="utf-8")


def test_content_cli_skips_each_out_of_scope_entry_without_dispatch(monkeypatch, tmp_path):
    module = load_cli()
    wordlist = tmp_path / "paths.txt"
    wordlist.write_text("inside\noutside\n", encoding="utf-8")
    dispatched = []

    class FakeScope:
        @classmethod
        def from_file(cls, _path):
            return cls()

        def check(self, url):
            status = ScopeStatus.OUT_OF_SCOPE if url.endswith("outside") else ScopeStatus.IN_SCOPE
            return SimpleNamespace(status=status, reason="fixture")

    monkeypatch.setattr(module, "get_program_dir", lambda _name: str(tmp_path))
    monkeypatch.setattr(module, "resolve_program_scope_file", lambda *_args: str(tmp_path / "scope.yaml"))
    monkeypatch.setattr(module, "ScopeEngine", FakeScope)
    monkeypatch.setattr(module, "safe_fetch_url", lambda url, **_kwargs: dispatched.append(url) or None)
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)
    monotonic_values = iter([0.0] * 20)
    monkeypatch.setattr(module.time, "monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT_PATH), "https://api.example.org/FUZZ", "--program", "demo", "--wordlist", str(wordlist)],
    )

    assert module.main() == 0
    assert dispatched == ["https://api.example.org/inside"]
    saved = json.loads((tmp_path / "scans" / "content_api.example.org.json").read_text(encoding="utf-8"))
    assert saved["skipped_out_of_scope"] == 1


def test_content_cli_sanitizes_host_and_port_in_output_filename():
    module = load_cli()
    assert module._safe_output_name("2001:db8::1", 8443) == "content_2001_db8__1_8443.json"
