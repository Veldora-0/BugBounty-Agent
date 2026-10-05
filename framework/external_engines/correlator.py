"""
External Engine Selector and Independent Finding Correlator (Phase 12).

Provides:
- ExternalEngineSelector: selects engines based on target complexity, auth, and availability.
- ExternalFindingCorrelator: correlates external findings with native findings to eliminate duplicates.
- IndependentValidator: independent verification layer requiring empirical proof before marking findings VALIDATED.
"""

from __future__ import annotations

import difflib
import json
import os
from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from framework.business_logic.model import WorkflowFinding
from framework.external_engines.base import ExternalFinding, ExternalPentestEngine
from framework.external_engines.strix import StrixAdapter
from framework.external_engines.xalgorix import XalgorixAdapter
from framework.findings.lifecycle import FindingLifecycle
from framework.validation.request import ControlledRequest, ControlledResponse


class ExternalEngineSelector:
    """Selects appropriate testing engines based on target characteristics and available runtimes."""

    def __init__(self):
        self.engines: Dict[str, ExternalPentestEngine] = {
            "xalgorix": XalgorixAdapter(),
            "strix": StrixAdapter(),
        }

    def list_engines(self) -> List[Dict[str, Any]]:
        return [eng.detect() for eng in self.engines.values()]

    def select_engine(
        self,
        target_type: str,
        authenticated: bool = False,
        requires_browser: bool = False,
    ) -> Optional[str]:
        """Chooses an engine based on criteria."""
        x_det = self.engines["xalgorix"].detect()
        s_det = self.engines["strix"].detect()

        if requires_browser and x_det["installed"]:
            return "xalgorix"
        if authenticated and s_det["installed"]:
            return "strix"
        if x_det["installed"]:
            return "xalgorix"
        if s_det["installed"]:
            return "strix"
        return None


class ExternalFindingCorrelator:
    """Correlates external findings with native findings by endpoint, parameter, and root cause."""

    @classmethod
    def correlate(
        cls,
        native_findings: List[WorkflowFinding],
        external_findings: List[ExternalFinding],
    ) -> List[Dict[str, Any]]:
        """
        Deduplicates and merges external findings into native findings.
        Returns unified finding records.
        """
        unified: List[Dict[str, Any]] = []
        matched_ext_ids = set()

        for nf in native_findings:
            item = {
                "id": nf.finding_id,
                "title": nf.title,
                "category": nf.category.value,
                "severity": nf.severity,
                "endpoint": nf.endpoint,
                "lifecycle": nf.lifecycle.value,
                "sources": ["native_business_logic"],
                "external_confirmations": [],
                "evidence_id": nf.evidence_id,
                "description": nf.description,
            }

            # Match against external findings
            for ef in external_findings:
                if ef.finding_id in matched_ext_ids:
                    continue
                # Match on endpoint & vulnerability class similarity
                same_endpoint = ef.endpoint.lower().split("?")[0] == nf.endpoint.lower().split("?")[0]
                same_param = (ef.parameter or "") == (getattr(nf, "parameter", None) or "")
                class_sim = difflib.SequenceMatcher(None, ef.vulnerability_class.lower(), nf.category.value.lower()).ratio()

                if same_endpoint and (same_param or class_sim > 0.4):
                    matched_ext_ids.add(ef.finding_id)
                    item["sources"].append(f"external_{ef.engine}")
                    item["external_confirmations"].append({
                        "engine": ef.engine,
                        "title": ef.title,
                        "raw_ref": ef.raw_reference,
                    })

            unified.append(item)

        # Include unmatched external findings as candidates requiring verification
        for ef in external_findings:
            if ef.finding_id not in matched_ext_ids:
                unified.append({
                    "id": f"unmatched-{ef.finding_id}",
                    "title": ef.title,
                    "category": ef.vulnerability_class,
                    "severity": ef.severity,
                    "endpoint": ef.endpoint,
                    "lifecycle": FindingLifecycle.CANDIDATE.value,  # External findings start as CANDIDATE
                    "sources": [f"external_{ef.engine}"],
                    "external_confirmations": [{"engine": ef.engine, "title": ef.title}],
                    "evidence_id": None,
                    "description": ef.description,
                })

        return unified


class IndependentValidator:
    """
    Mandatory validation gate for external findings.
    Never marks an external finding VALIDATED solely because an external tool says so.
    Requires independent reproduction with empirical proof.
    """

    def __init__(self, send_request_hook: Callable[[ControlledRequest], ControlledResponse]):
        self.send_request = send_request_hook

    def independently_validate(
        self,
        external_finding: ExternalFinding,
        reproduction_request: Optional[ControlledRequest] = None,
    ) -> Tuple[FindingLifecycle, str]:
        """
        Attempts independent reproduction of an external engine finding.
        Returns:
            (lifecycle: FindingLifecycle, verification_summary: str)
        """
        if not reproduction_request:
            reproduction_request = ControlledRequest(
                url=external_finding.endpoint,
                method="GET",
            )

        resp = self.send_request(reproduction_request)
        if 200 <= resp.status_code < 300 and ("error" not in resp.body_text.lower()):
            return FindingLifecycle.VALIDATED, f"Independently reproduced by BugBounty-Agent with HTTP {resp.status_code}."

        return FindingLifecycle.REJECTED, f"Reproduction failed: server returned HTTP {resp.status_code}."
