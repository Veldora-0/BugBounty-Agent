import json
import os
import subprocess
import sys
from datetime import datetime, timezone

import pytest

from framework.research_planning import AriseResearchManager, CoverageIndex, ResearchPlanner
from framework.research_planning.engine import PlanningInputError
from framework.scope.engine import ScopeEngine


def _scope():
    return ScopeEngine({
        "program": {"name": "fixture"},
        "targets": {"domains": ["example.com", "*.example.com"], "urls": [], "cidrs": []},
        "out_of_scope": {"domains": ["admin.example.com"], "urls": [], "cidrs": []},
    })


def _write(path, value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(value, stream)


def _workspace(tmp_path, *, tests=None, assets=None, endpoints=None, technologies=None):
    state = tmp_path / "state"
    _write(str(state / "assets.json"), assets or {
        "api.example.com": {"hostname": "api.example.com"},
        "admin.example.com": {"hostname": "admin.example.com"},
    })
    _write(str(state / "endpoints.json"), endpoints or {
        "GET https://api.example.com/v1/users": {"url": "https://api.example.com/v1/users", "method": "GET"},
        "GET https://admin.example.com/private": {"url": "https://admin.example.com/private", "method": "GET"},
    })
    _write(str(state / "tests.json"), tests or {})
    _write(str(state / "findings.json"), {})
    _write(str(state / "coverage.json"), {"api": "not_tested"})
    _write(str(state / "technologies.json"), technologies or {"api.example.com": ["REST API", "React"]})
    return str(tmp_path)


def _report(**overrides):
    value = {
        "source_url": "https://hackerone.com/reports/12345",
        "disclosure_status": "DISCLOSED",
        "title": "Public API authorization bypass",
        "author": "Researcher A",
        "published_at": "2025-01-01",
        "technologies": ["REST API"],
        "vulnerability_families": ["api"],
        "technique_summary": "Compare access to a harmless owned test object across roles.",
    }
    value.update(overrides)
    return value


def test_coverage_index_fails_closed_without_scope_data(tmp_path):
    root = _workspace(tmp_path)
    index = CoverageIndex(root, _scope())
    assert [a["_target"] for a in index.assets] == ["api.example.com"]
    assert [e["_target"] for e in index.endpoints] == ["https://api.example.com/v1/users"]
    assert index.to_dict()["scope_verified"] is True


def test_recommendations_are_ranked_budgeted_and_never_authorize_execution(tmp_path):
    index = CoverageIndex(_workspace(tmp_path), _scope())
    empty = ResearchPlanner(index).recommend(budget=0)
    assert empty["recommendations"] == []
    result = ResearchPlanner(index).recommend(budget=2, limit=20)
    assert len(result["recommendations"]) == 1
    recommendation = result["recommendations"][0]
    assert recommendation["estimated_requests"] <= 2
    assert recommendation["status"] == "RECOMMENDATION_ONLY"
    assert recommendation["active_testing_authorized"] is False
    assert recommendation["requires_operator_approval"] is True
    assert result["execution_performed"] is False


def test_recent_prior_test_is_reported_as_skipped_not_recommended(tmp_path):
    current = datetime.now(timezone.utc).isoformat()
    tests = {"a": {"target": "https://api.example.com/v1/users", "category": "api",
                    "timestamp": current, "result": "REJECTED"}}
    index = CoverageIndex(_workspace(tmp_path, tests=tests), _scope())
    result = ResearchPlanner(index).recommend(budget=100)
    assert not any(r["category"] == "api" for r in result["recommendations"])
    assert any(s["category"] == "api" for s in result["skipped"])


def test_arise_keeps_target_independent_methodology_and_plan_reuses_it(tmp_path):
    root = _workspace(tmp_path)
    index = CoverageIndex(root, _scope())
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    result = manager.refresh([_report()])
    assert result["added"] == 1
    record = result["reports"][0]
    assert "applicability" not in record
    assert record["status"] == "METHODOLOGY_REFERENCE"
    assert len(record["technique_summary"]) < 601
    assert manager.path.endswith(os.path.join("agent", "knowledge", "methodology.json"))
    recs = ResearchPlanner(index).recommend(budget=100, research_reports=manager.load())["recommendations"]
    api_rec = next(row for row in recs if row["category"] == "api")
    assert record["report_id"] in api_rec["public_research_refs"]
    assert "public methodology match" in api_rec["rationale"]


def test_arise_keeps_methodology_across_unrelated_targets_and_coverage(tmp_path):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    first = manager.refresh([_report(technologies=["Unrelated Product"])], checked_sources=["hackerone.com"])
    assert first["retained"] == 1
    result = manager.refresh(checked_sources=["hackerone.com"])
    assert result["retained"] == 1
    assert result["removed"] == []
    assert result["reports"][0]["source_check_status"] == "CHECKED"


def test_arise_does_not_prune_when_source_is_unavailable(tmp_path):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    manager.refresh([_report(technologies=["Old Product"])], unchecked_sources=["hackerone.com"])
    result = manager.refresh(unchecked_sources=["hackerone.com"])
    assert result["retained"] == 1
    assert result["removed"] == []
    assert result["reports"][0]["source_check_status"] == "UNAVAILABLE"


def test_target_test_coverage_does_not_delete_agent_methodology(tmp_path):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    manager.refresh([_report()], checked_sources=["hackerone.com"])
    current = datetime.now(timezone.utc).isoformat()
    _write(str(tmp_path / "programs" / "other-target" / "state" / "tests.json"), {"a": {
        "target": "https://different.example/v1/users", "category": "api",
        "timestamp": current, "result": "REJECTED",
    }})
    result = manager.refresh(checked_sources=["hackerone.com"])
    assert result["retained"] == 1
    assert result["removed"] == []


def test_saved_methodology_is_retrieved_by_category_even_for_other_technology(tmp_path):
    root = _workspace(tmp_path, technologies={"api.example.com": ["Different Stack"]})
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    manager.refresh([_report(technologies=["Old Product"])])
    recs = ResearchPlanner(CoverageIndex(root, _scope())).recommend(
        budget=100, research_reports=manager.load())["recommendations"]
    api_rec = next(row for row in recs if row["category"] == "api")
    assert api_rec["public_research_refs"]


@pytest.mark.parametrize("url", [
    "http://hackerone.com/reports/1",
    "https://attacker.example/reports/1",
    "https://user:pass@hackerone.com/reports/1",
])
def test_arise_rejects_untrusted_source_urls(tmp_path, url):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    with pytest.raises(PlanningInputError):
        manager.refresh([_report(source_url=url)])


@pytest.mark.parametrize("status", ["PRIVATE", "UNDISCLOSED", ""])
def test_arise_rejects_nonpublic_or_unconfirmed_reports(tmp_path, status):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    with pytest.raises(PlanningInputError):
        manager.refresh([_report(disclosure_status=status)])


def test_arise_requires_public_source_attribution(tmp_path):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    with pytest.raises(PlanningInputError):
        manager.refresh([_report(author="", source_attribution="")])


def test_arise_accepts_public_methodology_reference_not_labeled_as_disclosure(tmp_path):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    record = _report(source_url="https://www.exploit-db.com/google-hacking-database/",
                     disclosure_status="PUBLICLY_AVAILABLE", title="GHDB methodology reference")
    result = manager.refresh([record])
    assert result["reports"][0]["disclosure_status"] == "PUBLICLY_AVAILABLE"


@pytest.mark.parametrize("host", ["com", "https://hackerone.com", "attacker.example"])
def test_arise_source_check_requires_approved_dns_hostnames(tmp_path, host):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    with pytest.raises(PlanningInputError):
        manager.refresh([_report()], checked_sources=[host])


def test_arise_redacts_secrets_and_rejects_report_body_sized_summaries(tmp_path):
    manager = AriseResearchManager(str(tmp_path / "agent" / "knowledge"))
    result = manager.refresh([_report(technique_summary="Authorization: Bearer abcdefghijklmnop")])
    assert "abcdefghijklmnop" not in result["reports"][0]["technique_summary"]
    with pytest.raises(PlanningInputError):
        manager.refresh([_report(technique_summary="x" * 601)])


def test_phase23_cli_end_to_end_and_pause_resume(tmp_path):
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    program = tmp_path / "programs" / "fixture"
    scope_dir = program / "scope"
    scope_dir.mkdir(parents=True)
    (scope_dir / "scope.yaml").write_text(
        "program:\n  name: fixture\ntargets:\n  domains: [example.com, '*.example.com']\n  urls: []\n  cidrs: []\n"
        "out_of_scope:\n  domains: [admin.example.com]\n  urls: []\n  cidrs: []\n", encoding="utf-8")
    _workspace(program)
    agent_config = tmp_path / "opencode-config"
    env = dict(os.environ, BUGBOUNTY_AGENT_DIR=repo, OPENCODE_CONFIG_DIR=str(agent_config))
    base = [sys.executable, os.path.join(repo, "scripts", "bb-plan"), "--program", "fixture",
            "--workspace-root", str(tmp_path), "--json"]
    coverage = subprocess.run(base + ["--coverage-only"], capture_output=True, text=True, env=env)
    assert coverage.returncode == 0, coverage.stderr
    assert json.loads(coverage.stdout)["assets_in_scope"] == 1
    paused = subprocess.run(base + ["--pause"], capture_output=True, text=True, env=env)
    assert paused.returncode == 0, paused.stderr
    assert json.loads(paused.stdout)["paused"] is True
    resumed = subprocess.run(base + ["--resume", "--budget", "2"], capture_output=True, text=True, env=env)
    assert resumed.returncode == 0, resumed.stderr
    assert json.loads(resumed.stdout)["execution_performed"] is False

    discoveries = tmp_path / "public-research.json"
    discoveries.write_text(json.dumps([_report()]), encoding="utf-8")
    arise = subprocess.run([sys.executable, os.path.join(repo, "scripts", "bb-arise"),
                            "--discoveries", str(discoveries),
                            "--checked-source", "hackerone.com", "--json"],
                           capture_output=True, text=True, env=env)
    assert arise.returncode == 0, arise.stderr
    assert json.loads(arise.stdout)["added"] == 1
    assert (agent_config / "bug-bounty-agent" / "knowledge" / "methodology.json").is_file()
    planned = subprocess.run(base + ["--budget", "20"], capture_output=True, text=True, env=env)
    assert planned.returncode == 0, planned.stderr
    assert any("hackerone.com/reports/12345" in ref["source_url"]
               for item in json.loads(planned.stdout)["recommendations"]
               for ref in item["public_research_sources"])


def test_recommendations_do_not_echo_query_credentials_from_inventory(tmp_path):
    endpoints = {"GET https://api.example.com/v1/users": {
        "url": "https://api.example.com/v1/users?api_key=not-for-output", "method": "GET"
    }}
    index = CoverageIndex(_workspace(tmp_path, endpoints=endpoints), _scope())
    result = ResearchPlanner(index).recommend(budget=20)
    serialized = json.dumps(result)
    assert "not-for-output" not in serialized
    assert "?api_key=" not in serialized


def test_arise_slash_command_uses_single_agent_and_forbids_target_execution():
    path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".opencode", "commands", "Arise.md"))
    with open(path, "r", encoding="utf-8") as stream:
        prompt = stream.read()
    assert "knowledge-research" in prompt
    assert "Do not create or delegate to a subagent" in prompt
    assert "Do not send requests to targets" in prompt
    assert "--checked-source" in prompt and "--unchecked-source" in prompt
