"""Disclosure readiness must bind finding text to an intact EvidenceStore capture."""

from __future__ import annotations

import json

from framework.common.evidence import EvidenceStore
from framework.findings.lifecycle import FindingLifecycle, InvalidLifecycleTransition
from framework.findings.schema import Finding


def _finding():
    return Finding(
        title="Authorization bypass on /api/v1/profile",
        summary="A user can read another account's profile.",
        affected_asset="api.example.com",
        affected_endpoint="/api/v1/profile",
        vulnerability_type="BOLA",
        severity="HIGH",
        description="The endpoint returns a different user's profile.",
        root_cause="The requested object owner is not checked.",
        prerequisites="A valid low-privilege account.",
        reproduction_steps=["Request the other user's profile with the test account."],
        expected_result="The response denies access to the other user's profile.",
        observed_result="The response returns the other user's profile.",
        security_impact="Private account data can be read across tenants.",
        remediation="Check object ownership before returning profile data.",
        scope_reference="api.example.com is included in the active program scope.",
        lifecycle_state=FindingLifecycle.CANDIDATE,
    )


def _attach_capture(finding, store):
    response = "HTTP/1.1 200 OK\n\n{\"user_id\": 42, \"email\": \"victim@example.com\"}"
    record = store.save_http_capture(
        request_text="GET /api/v1/profile?user_id=42 HTTP/1.1\nHost: api.example.com",
        response_text=response,
    )
    finding.add_evidence(
        "HTTP_TRANSACTION",
        response,
        metadata={"evidence_id": record["evidence_id"], "sha256": record["sha256"]},
    )
    return record


def test_report_gate_verifies_capture_bytes_and_response_binding(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    finding = _finding()
    record = _attach_capture(finding, store)
    finding.transition_to(
        FindingLifecycle.VALIDATED,
        notes="The control request and cross-user response establish an authorization failure.",
        evidence_store=store,
    )

    assert finding.is_report_ready(evidence_store=store)[0] is True
    assert finding.to_markdown_report(evidence_store=store)

    finding.evidence[0]["metadata"]["sha256"] = "a" * 64
    ready, reason = finding.is_report_ready(evidence_store=store)
    assert ready is False
    assert "EvidenceStore capture" in reason
    assert record["sha256"] != "a" * 64


def test_report_gate_rejects_tampered_capture_file(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    finding = _finding()
    _attach_capture(finding, store)
    finding.transition_to(
        FindingLifecycle.VALIDATED,
        notes="The response proves cross-account access.",
        evidence_store=store,
    )
    capture = store.get_evidence(finding.evidence[0]["metadata"]["evidence_id"])["capture_path"]
    with open(capture, "a", encoding="utf-8") as stream:
        stream.write("tampered\n")

    ready, reason = finding.is_report_ready(evidence_store=store)
    assert ready is False
    assert "missing, altered" in reason


def test_transition_and_report_gate_require_store_verification(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    finding = _finding()
    _attach_capture(finding, store)

    try:
        finding.transition_to(
            FindingLifecycle.VALIDATED,
            notes="A differential check proved cross-account access.",
        )
    except InvalidLifecycleTransition as exc:
        assert "EvidenceStore verification is required" in str(exc)
    else:
        raise AssertionError("Validation transition succeeded without EvidenceStore verification")


def test_deserialized_validated_finding_with_forged_digest_is_not_reportable(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    finding = _finding()
    _attach_capture(finding, store)
    finding.transition_to(
        FindingLifecycle.VALIDATED,
        notes="Evidence verified before serialization.",
        evidence_store=store,
    )
    serialized = finding.to_dict()
    serialized["evidence"][0]["metadata"]["sha256"] = "f" * 64
    restored = Finding.from_dict(serialized, evidence_store=store)

    ready, reason = restored.is_report_ready(evidence_store=store)
    assert ready is False
    assert restored.lifecycle_state == FindingLifecycle.NEEDS_MANUAL_REVIEW
    assert "only VALIDATED findings can be reported" in reason
    assert json.loads(restored.to_json())["lifecycle_state"] == "NEEDS_MANUAL_REVIEW"


def test_provenance_credentials_are_redacted_before_serialization():
    finding = _finding()
    finding.provenance = {
        "tool": "nuclei",
        "raw_hit": {
            "request": "GET /private?token=secret_value HTTP/1.1\nAuthorization: Bearer header_secret",
            "headers": {"Cookie": "session=secret_cookie"},
        },
    }

    serialized = json.dumps(finding.to_dict())
    for secret in ("secret_value", "header_secret", "secret_cookie"):
        assert secret not in serialized


def test_evidence_metadata_redacts_url_and_sensitive_key_values(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    record = store.save_http_capture(
        request_text="GET / HTTP/1.1",
        response_text="HTTP/1.1 200 OK",
        metadata={
            "target": "https://example.test/path?access_token=url_secret",
            "credentials": {"password": "nested_secret"},
            "labels": ["session=label_secret", "ordinary label"],
        },
    )

    with open(record["meta_path"], encoding="utf-8") as stream:
        serialized_metadata = json.load(stream)["metadata"]
    serialized = json.dumps(serialized_metadata)

    for secret in ("url_secret", "nested_secret", "label_secret"):
        assert secret not in serialized
    assert "ordinary label" in serialized


def test_report_gate_requires_a_bound_content_digest(tmp_path):
    store = EvidenceStore(str(tmp_path / "evidence"))
    finding = _finding()
    _attach_capture(finding, store)
    finding.evidence[0]["metadata"].pop("content_sha256")
    try:
        finding.transition_to(
            FindingLifecycle.VALIDATED,
            notes="Stored response was compared to the baseline.",
            evidence_store=store,
        )
    except InvalidLifecycleTransition as exc:
        assert "content SHA-256" in str(exc)
    else:
        raise AssertionError("Validation transition succeeded without a content digest")
