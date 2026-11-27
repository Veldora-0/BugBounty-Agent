from __future__ import annotations

import copy
import os

import yaml

from framework.coverage.registry import CoverageRegistry


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def test_repository_coverage_registry_has_valid_paths_and_tool_statuses():
    registry = CoverageRegistry(repo_root=REPO_ROOT)

    assert registry.validate() == []
    assert registry.classes
    assert len({item["id"] for item in registry.classes}) == len(registry.classes)


def test_coverage_summary_is_static_and_filters_by_area_and_status():
    registry = CoverageRegistry(repo_root=REPO_ROOT)

    result = registry.summary(area="api", status="manual-assisted")

    assert result["target_requests_sent"] is False
    assert result["class_count"] == len(result["classes"])
    assert all(item["area"] == "api" for item in result["classes"])
    assert all(item["status"] == "manual-assisted" for item in result["classes"])


def test_registry_validation_rejects_duplicate_ids(tmp_path):
    registry = CoverageRegistry(repo_root=REPO_ROOT)
    duplicate_data = copy.deepcopy(registry.data)
    duplicate_data["classes"].append(copy.deepcopy(duplicate_data["classes"][0]))
    path = tmp_path / "coverage.yaml"
    path.write_text(yaml.safe_dump(duplicate_data), encoding="utf-8")

    errors = CoverageRegistry(repo_root=REPO_ROOT, registry_path=str(path)).validate()

    assert any("Duplicate coverage id" in error for error in errors)


def test_registry_validation_rejects_missing_engine_path(tmp_path):
    registry = CoverageRegistry(repo_root=REPO_ROOT)
    invalid_data = copy.deepcopy(registry.data)
    invalid_data["classes"][0]["engine"] = "framework/missing/engine.py"
    path = tmp_path / "coverage.yaml"
    path.write_text(yaml.safe_dump(invalid_data), encoding="utf-8")

    errors = CoverageRegistry(repo_root=REPO_ROOT, registry_path=str(path)).validate()

    assert any("engine path does not exist" in error for error in errors)
