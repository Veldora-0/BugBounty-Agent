"""
Finding Schema and Serialization for BugBounty-Agent.

Enforces structured fields, validation, and professional Markdown report rendering.
Never exaggerates severity or impact.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid

from framework.findings.lifecycle import (
    FindingLifecycle,
    validate_transition,
    InvalidLifecycleTransition,
)


class FindingValidationError(ValueError):
    """Raised when finding data violates schema or required fields."""
    pass


VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
VALID_CONFIDENCES = {"CONFIRMED", "HIGH", "MEDIUM", "LOW"}


class Finding:
    """Represents a security finding throughout its entire lifecycle."""

    def __init__(
        self,
        title: str,
        summary: str,
        affected_asset: str,
        affected_endpoint: str,
        vulnerability_type: str,
        severity: str,
        description: str,
        root_cause: str,
        prerequisites: str,
        reproduction_steps: List[str],
        expected_result: str,
        observed_result: str,
        security_impact: str,
        remediation: str,
        scope_reference: str,
        confidence: str = "HIGH",
        finding_id: Optional[str] = None,
        lifecycle_state: FindingLifecycle = FindingLifecycle.CANDIDATE,
        evidence: Optional[List[Dict[str, Any]]] = None,
        provenance: Optional[Dict[str, Any]] = None,
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        validation_notes: Optional[str] = None,
        duplicate_of: Optional[str] = None,
        parameter: Optional[str] = None,
        test_case_id: Optional[str] = None,
        detection_method: Optional[str] = None,
        references: Optional[List[str]] = None,
    ):
        self.finding_id = finding_id or f"BB-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        self.title = title
        self.summary = summary
        self.affected_asset = affected_asset
        self.affected_endpoint = affected_endpoint
        self.parameter = parameter
        self.test_case_id = test_case_id
        self.detection_method = detection_method
        self.references = references or []
        self.vulnerability_type = vulnerability_type
        self.severity = severity.upper()
        self.description = description
        self.root_cause = root_cause
        self.prerequisites = prerequisites
        self.reproduction_steps = list(reproduction_steps)
        self.expected_result = expected_result
        self.observed_result = observed_result
        self.security_impact = security_impact
        self.remediation = remediation
        self.scope_reference = scope_reference
        self.confidence = confidence.upper()

        if isinstance(lifecycle_state, str):
            self.lifecycle_state = FindingLifecycle(lifecycle_state)
        else:
            self.lifecycle_state = lifecycle_state

        self.evidence = evidence or []
        self.provenance = provenance or {}
        now_str = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now_str
        self.updated_at = updated_at or now_str
        self.validation_notes = validation_notes
        self.duplicate_of = duplicate_of

        self.validate()

    def validate(self) -> None:
        """Validates all required fields and invariants."""
        if not self.title or not self.title.strip():
            raise FindingValidationError("Finding title is required.")
        if not self.affected_asset or not self.affected_asset.strip():
            raise FindingValidationError("Affected asset is required.")
        if not self.affected_endpoint or not self.affected_endpoint.strip():
            raise FindingValidationError("Affected endpoint is required.")
        if not self.vulnerability_type or not self.vulnerability_type.strip():
            raise FindingValidationError("Vulnerability type is required.")
        if self.severity not in VALID_SEVERITIES:
            raise FindingValidationError(f"Invalid severity '{self.severity}'. Must be one of {VALID_SEVERITIES}")
        if self.confidence not in VALID_CONFIDENCES:
            raise FindingValidationError(f"Invalid confidence '{self.confidence}'. Must be one of {VALID_CONFIDENCES}")
        if not isinstance(self.reproduction_steps, list) or len(self.reproduction_steps) == 0:
            raise FindingValidationError("Reproduction steps must be a non-empty list.")
        if not self.security_impact or not self.security_impact.strip():
            raise FindingValidationError("Security impact is required.")
        if not self.scope_reference or not self.scope_reference.strip():
            raise FindingValidationError("Scope reference is required.")

    def transition_to(self, new_state: FindingLifecycle, notes: Optional[str] = None) -> None:
        """Transitions finding lifecycle state."""
        validate_transition(self.lifecycle_state, new_state)
        self.lifecycle_state = new_state
        if notes:
            self.validation_notes = notes
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_evidence(self, evidence_type: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Appends verified evidence item."""
        item = {
            "type": evidence_type,
            "content": content,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.evidence.append(item)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes finding to dictionary."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "summary": self.summary,
            "affected_asset": self.affected_asset,
            "affected_endpoint": self.affected_endpoint,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "lifecycle_state": self.lifecycle_state.value,
            "description": self.description,
            "root_cause": self.root_cause,
            "prerequisites": self.prerequisites,
            "reproduction_steps": self.reproduction_steps,
            "expected_result": self.expected_result,
            "observed_result": self.observed_result,
            "security_impact": self.security_impact,
            "remediation": self.remediation,
            "scope_reference": self.scope_reference,
            "evidence": self.evidence,
            "provenance": self.provenance,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "validation_notes": self.validation_notes,
            "duplicate_of": self.duplicate_of,
            "parameter": self.parameter,
            "test_case_id": self.test_case_id,
            "detection_method": self.detection_method,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        """Deserializes finding from dictionary."""
        return cls(
            finding_id=data.get("finding_id"),
            title=data.get("title", ""),
            summary=data.get("summary", ""),
            affected_asset=data.get("affected_asset", ""),
            affected_endpoint=data.get("affected_endpoint", ""),
            vulnerability_type=data.get("vulnerability_type", ""),
            severity=data.get("severity", "INFORMATIONAL"),
            description=data.get("description", ""),
            root_cause=data.get("root_cause", ""),
            prerequisites=data.get("prerequisites", ""),
            reproduction_steps=data.get("reproduction_steps", []),
            expected_result=data.get("expected_result", ""),
            observed_result=data.get("observed_result", ""),
            security_impact=data.get("security_impact", ""),
            remediation=data.get("remediation", ""),
            scope_reference=data.get("scope_reference", ""),
            confidence=data.get("confidence", "HIGH"),
            lifecycle_state=FindingLifecycle(data.get("lifecycle_state", "CANDIDATE")),
            evidence=data.get("evidence", []),
            provenance=data.get("provenance", {}),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            validation_notes=data.get("validation_notes"),
            duplicate_of=data.get("duplicate_of"),
            parameter=data.get("parameter"),
            test_case_id=data.get("test_case_id"),
            detection_method=data.get("detection_method"),
            references=data.get("references", []),
        )

    def to_json(self, indent: int = 2) -> str:
        """Returns JSON representation."""
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown_report(self) -> str:
        """
        Renders the finding into a professional markdown report conforming
        to the 17 standard bug bounty disclosure sections.
        """
        repro_steps_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(self.reproduction_steps))

        evidence_blocks = []
        if self.evidence:
            for idx, item in enumerate(self.evidence, 1):
                ev_type = item.get("type", "General")
                ev_content = item.get("content", "")
                evidence_blocks.append(f"#### Evidence Item {idx} ({ev_type})\n\n```text\n{ev_content}\n```")
            evidence_md = "\n\n".join(evidence_blocks)
        else:
            evidence_md = "_No raw HTTP captures or attachments attached._"

        return f"""# {self.title}

## Summary
{self.summary}

## Asset Details
* **Affected Asset**: `{self.affected_asset}`
* **Affected Endpoint**: `{self.affected_endpoint}`
* **Vulnerability Type**: {self.vulnerability_type}
* **Severity**: {self.severity}
* **Confidence**: {self.confidence}
* **Lifecycle State**: {self.lifecycle_state.value}
* **Scope Reference**: `{self.scope_reference}`

## Description
{self.description}

## Root Cause
{self.root_cause}

## Prerequisites
{self.prerequisites}

## Reproduction Steps
{repro_steps_md}

## Expected Result
{self.expected_result}

## Observed Result
{self.observed_result}

## Security Impact
{self.security_impact}

## Evidence
{evidence_md}

## Remediation
{self.remediation}

---
*Report generated by BugBounty-Agent Framework (ID: {self.finding_id})*
"""
