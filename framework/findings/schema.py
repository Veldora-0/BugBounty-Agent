"""
Finding Schema and Serialization for BugBounty-Agent.

Enforces structured fields, validation, and professional Markdown report rendering.
Never exaggerates severity or impact.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from typing import Any, Dict, List, Optional, Tuple
import uuid

from framework.common.evidence import sanitize_sensitive_data
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

    def is_report_ready(self) -> Tuple[bool, str]:
        """
        Evaluates whether finding satisfies all requirements for formal disclosure reporting.
        Returns (is_ready, diagnostic_reason).
        """
        if self.lifecycle_state != FindingLifecycle.VALIDATED:
            return False, f"Lifecycle state is '{self.lifecycle_state.value}', but only VALIDATED findings can be reported."

        if self.lifecycle_state == FindingLifecycle.SIMULATED or (
            isinstance(self.provenance, dict) and (self.provenance.get("is_simulation") or self.provenance.get("simulated"))
        ):
            return False, "Simulated or mock observations cannot be used for disclosure reporting."

        if not self.evidence or len(self.evidence) == 0:
            return False, "Finding has no attached evidence items; cryptographic evidence is required for disclosure."

        for idx, item in enumerate(self.evidence, 1):
            if not isinstance(item, dict):
                return False, f"Evidence item {idx} is not a valid structured dictionary."
            content = item.get("content", "")
            if not content or not str(content).strip():
                return False, f"Evidence item {idx} contains empty content."
            meta = item.get("metadata", {})
            if isinstance(meta, dict) and "sha256" in meta and meta["sha256"]:
                digest = str(meta["sha256"]).strip()
                if not re.match(r"^[0-9a-fA-F]{64}$", digest):
                    return False, f"Evidence item {idx} contains invalid SHA-256 integrity hash: '{digest}'."

        if not self.reproduction_steps or len(self.reproduction_steps) == 0:
            return False, "Reproduction steps must be a non-empty list."
        for idx, step in enumerate(self.reproduction_steps, 1):
            if not step or not str(step).strip() or len(str(step).strip()) < 5:
                return False, f"Reproduction step {idx} is too short or empty."

        if not self.observed_result or not self.observed_result.strip():
            return False, "Observed result is required to document demonstrated behavior."
        if not self.expected_result or not self.expected_result.strip():
            return False, "Expected result is required to define the secure baseline."
        if self.observed_result.strip().lower() == self.expected_result.strip().lower():
            return False, "Observed result cannot be identical to expected result; differential security invariant must be demonstrated."

        has_notes = bool(self.validation_notes and self.validation_notes.strip())
        has_prov_notes = bool(isinstance(self.provenance, dict) and self.provenance.get("validation_notes"))
        if not (has_notes or has_prov_notes):
            return False, "Validation notes explaining the differential invariant violation rationale are required."

        if not self.title or not self.title.strip():
            return False, "Finding title is required."
        if not self.affected_asset or not self.affected_asset.strip():
            return False, "Affected asset is required."
        if not self.affected_endpoint or not self.affected_endpoint.strip():
            return False, "Affected endpoint is required."
        if not self.vulnerability_type or not self.vulnerability_type.strip():
            return False, "Vulnerability type is required."
        if not self.security_impact or not self.security_impact.strip():
            return False, "Security impact is required."
        if not self.scope_reference or not self.scope_reference.strip():
            return False, "Scope reference is required."

        return True, "Finding is report-ready."

    def transition_to(self, new_state: FindingLifecycle, notes: Optional[str] = None) -> None:
        """Transitions finding lifecycle state."""
        validate_transition(self.lifecycle_state, new_state)
        if new_state == FindingLifecycle.VALIDATED:
            if self.lifecycle_state == FindingLifecycle.SIMULATED or (
                isinstance(self.provenance, dict) and (self.provenance.get("is_simulation") or self.provenance.get("simulated"))
            ):
                raise InvalidLifecycleTransition(
                    f"Cannot transition finding '{self.finding_id}' to VALIDATED: simulated or mock observations are forbidden from entering VALIDATED state."
                )
            effective_notes = notes or self.validation_notes or (self.provenance.get("validation_notes") if isinstance(self.provenance, dict) else None)
            if not effective_notes or not str(effective_notes).strip():
                raise InvalidLifecycleTransition(
                    f"Cannot transition finding '{self.finding_id}' to VALIDATED: validation notes explaining the differential security invariant are required."
                )
            if not self.evidence or len(self.evidence) == 0:
                raise InvalidLifecycleTransition(
                    f"Cannot transition finding '{self.finding_id}' to VALIDATED: at least one verified evidence item is required."
                )
            for idx, item in enumerate(self.evidence, 1):
                if not isinstance(item, dict) or not item.get("content") or not str(item.get("content")).strip():
                    raise InvalidLifecycleTransition(
                        f"Cannot transition finding '{self.finding_id}' to VALIDATED: evidence item {idx} has empty content."
                    )
                meta = item.get("metadata", {})
                if isinstance(meta, dict) and "sha256" in meta and meta["sha256"]:
                    digest = str(meta["sha256"]).strip()
                    if not re.match(r"^[0-9a-fA-F]{64}$", digest):
                        raise InvalidLifecycleTransition(
                            f"Cannot transition finding '{self.finding_id}' to VALIDATED: evidence item {idx} has invalid SHA-256 integrity hash: '{digest}'."
                        )
            if not self.reproduction_steps or len(self.reproduction_steps) == 0:
                raise InvalidLifecycleTransition(
                    f"Cannot transition finding '{self.finding_id}' to VALIDATED: reproduction steps must be a non-empty list."
                )
            for idx, step in enumerate(self.reproduction_steps, 1):
                if not step or not str(step).strip() or len(str(step).strip()) < 5:
                    raise InvalidLifecycleTransition(
                        f"Cannot transition finding '{self.finding_id}' to VALIDATED: reproduction step {idx} is too short or empty."
                    )
            if not self.observed_result or not self.observed_result.strip():
                raise InvalidLifecycleTransition(
                    f"Cannot transition finding '{self.finding_id}' to VALIDATED: observed result is required."
                )
            if not self.expected_result or not self.expected_result.strip():
                raise InvalidLifecycleTransition(
                    f"Cannot transition finding '{self.finding_id}' to VALIDATED: expected result is required."
                )
            if self.observed_result.strip().lower() == self.expected_result.strip().lower():
                raise InvalidLifecycleTransition(
                    f"Cannot transition finding '{self.finding_id}' to VALIDATED: observed result cannot match expected result."
                )

        self.lifecycle_state = new_state
        if notes:
            self.validation_notes = notes
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_evidence(self, evidence_type: str, content: str, metadata: Optional[Dict[str, Any]] = None) -> None:
        """Appends verified evidence item with sensitive data sanitized."""
        sanitized_content = sanitize_sensitive_data(str(content))
        item = {
            "type": evidence_type,
            "content": sanitized_content,
            "metadata": metadata or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.evidence.append(item)
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes finding to dictionary with sanitized evidence."""
        sanitized_evidence: List[Dict[str, Any]] = []
        for ev in self.evidence:
            if isinstance(ev, dict):
                ev_copy = dict(ev)
                if "content" in ev_copy and isinstance(ev_copy["content"], str):
                    ev_copy["content"] = sanitize_sensitive_data(ev_copy["content"])
                sanitized_evidence.append(ev_copy)
            else:
                sanitized_evidence.append(ev)

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
            "evidence": sanitized_evidence,
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
        raw_state = data.get("lifecycle_state", "CANDIDATE")
        ev_list = data.get("evidence", [])
        val_notes = data.get("validation_notes")
        # Safe migration: if older serialized finding was marked VALIDATED but has no evidence or validation notes,
        # downgrade to NEEDS_MANUAL_REVIEW to preserve state without invalid promotion
        if raw_state == "VALIDATED" and not ev_list:
            state = FindingLifecycle.NEEDS_MANUAL_REVIEW
            if not val_notes:
                val_notes = "Migrated finding lacks attached evidence; flagged for manual review."
        elif raw_state == "VALIDATED" and not val_notes and not (data.get("provenance", {}).get("validation_notes")):
            val_notes = "Legacy validated finding imported with attached evidence."
            state = FindingLifecycle.VALIDATED
        else:
            state = FindingLifecycle(raw_state)

        conf_val = data.get("confidence", "HIGH")
        if str(conf_val).upper() == "VALIDATED":
            conf_val = "CONFIRMED"
        elif str(conf_val).upper() not in VALID_CONFIDENCES:
            conf_val = "HIGH"

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
            confidence=conf_val,
            lifecycle_state=state,
            evidence=ev_list,
            provenance=data.get("provenance", {}),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            validation_notes=val_notes,
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
        Fails closed with FindingValidationError if finding is not report-ready.
        """
        ready, reason = self.is_report_ready()
        if not ready:
            raise FindingValidationError(f"Finding '{self.finding_id}' is not report-ready: {reason}")

        repro_steps_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(self.reproduction_steps))

        evidence_blocks = []
        if self.evidence:
            for idx, item in enumerate(self.evidence, 1):
                ev_type = item.get("type", "General")
                raw_content = item.get("content", "")
                clean_content = sanitize_sensitive_data(str(raw_content))
                evidence_blocks.append(f"#### Evidence Item {idx} ({ev_type})\n\n```text\n{clean_content}\n```")
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
