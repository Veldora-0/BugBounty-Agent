"""
State Manager for BugBounty-Agent.

Maintains persistent local research state per program:
assets, endpoints, technologies, hypotheses, tests, findings, and coverage.
Never leaks target data to the Git repository.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from framework.common.evidence import sanitize_sensitive_data
from framework.findings.lifecycle import FindingLifecycle
from framework.findings.schema import Finding
from framework.state.dedup import (
    FindingDeduplicator,
    generate_test_fingerprint,
)


DEFAULT_COVERAGE = {
    "authentication": "not_tested",
    "authorization": "not_tested",
    "api": "not_tested",
    "javascript": "not_tested",
    "uploads": "not_tested",
    "business_logic": "not_tested",
    "cloud": "not_tested",
}


class StateManager:
    """
    Manages isolated persistent state files for a specific bug bounty program.
    """

    def __init__(self, program_dir: str):
        self.program_dir = os.path.abspath(program_dir)
        self.state_dir = os.path.join(self.program_dir, "state")
        os.makedirs(self.state_dir, exist_ok=True)

        self.assets_file = os.path.join(self.state_dir, "assets.json")
        self.endpoints_file = os.path.join(self.state_dir, "endpoints.json")
        self.technologies_file = os.path.join(self.state_dir, "technologies.json")
        self.hypotheses_file = os.path.join(self.state_dir, "hypotheses.json")
        self.tests_file = os.path.join(self.state_dir, "tests.json")
        self.findings_file = os.path.join(self.state_dir, "findings.json")
        self.coverage_file = os.path.join(self.state_dir, "coverage.json")
        self.recon_file = os.path.join(self.state_dir, "recon.json")
        self.webapps_file = os.path.join(self.state_dir, "webapps.json")
        self.javascript_file = os.path.join(self.state_dir, "javascript.json")
        self.api_file = os.path.join(self.state_dir, "api.json")
        self.security_file = os.path.join(self.state_dir, "security.json")

        self._init_files()

    def _init_files(self) -> None:
        """Ensures all state JSON files exist with default structures."""
        for filepath, default_content in [
            (self.assets_file, {}),
            (self.endpoints_file, {}),
            (self.technologies_file, {}),
            (self.hypotheses_file, []),
            (self.tests_file, {}),
            (self.findings_file, {}),
            (self.coverage_file, DEFAULT_COVERAGE),
            (self.recon_file, {}),
            (self.webapps_file, {}),
            (self.javascript_file, {}),
            (self.api_file, {}),
            (self.security_file, {}),
        ]:
            if not os.path.exists(filepath):
                self._atomic_write_json(filepath, default_content)

    def _read_json(self, filepath: str) -> Any:
        """Reads JSON file safely."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}

    def _atomic_write_json(self, filepath: str, data: Any) -> None:
        """Writes JSON data atomically via a temporary file."""
        dir_name = os.path.dirname(filepath)
        with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
            json.dump(data, tf, indent=2)
            temp_path = tf.name
        # Atomic replace
        os.replace(temp_path, filepath)

    # ---------------- Asset Management ----------------

    def add_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """
        Adds or updates an asset in local state.
        Preserves first_seen and updates last_seen.
        Supports both legacy dictionary format and graph format.
        """
        hostname = asset.get("hostname") or asset.get("normalized") or asset.get("value")
        if not hostname:
            raise ValueError("Asset must include a 'hostname'.")

        data = self._read_json(self.assets_file)
        now_str = datetime.now(timezone.utc).isoformat()

        if isinstance(data, dict) and "assets" in data and isinstance(data["assets"], dict):
            # Graph format
            assets = data["assets"]
            asset_id = asset.get("id") or f"asset:hostname:{hostname}"
            if asset_id in assets:
                existing = assets[asset_id]
                existing.update(asset)
                existing["last_seen"] = now_str
                assets[asset_id] = existing
            else:
                asset_record = dict(asset)
                asset_record["first_seen"] = now_str
                asset_record["last_seen"] = now_str
                assets[asset_id] = asset_record
            data["total_assets"] = len(assets)
            self._atomic_write_json(self.assets_file, data)
            return assets[asset_id]
        else:
            # Legacy dictionary format
            assets = data if isinstance(data, dict) else {}
            if hostname in assets:
                existing = assets[hostname]
                existing.update(asset)
                existing["last_seen"] = now_str
                assets[hostname] = existing
            else:
                asset_record = dict(asset)
                asset_record["first_seen"] = now_str
                asset_record["last_seen"] = now_str
                assets[hostname] = asset_record

            self._atomic_write_json(self.assets_file, assets)
            return assets[hostname]

    def get_assets(self) -> List[Dict[str, Any]]:
        """Returns all discovered assets, whether stored in graph format or legacy format."""
        data = self._read_json(self.assets_file)
        if isinstance(data, dict) and "assets" in data and isinstance(data["assets"], dict):
            return list(data["assets"].values())
        return list(data.values()) if isinstance(data, dict) else []

    def get_asset(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Retrieves single asset by hostname."""
        data = self._read_json(self.assets_file)
        if isinstance(data, dict) and "assets" in data and isinstance(data["assets"], dict):
            target = hostname.strip().lower()
            for a in data["assets"].values():
                if (
                    a.get("hostname") == target
                    or a.get("normalized") == target
                    or a.get("id") == target
                    or a.get("value") == target
                ):
                    return a
            return None
        return data.get(hostname) if isinstance(data, dict) else None

    def get_asset_graph(self) -> Any:
        """Loads and returns an AssetGraph instance from local state."""
        from framework.assets.graph import AssetGraph
        return AssetGraph.load_from_file(self.assets_file)

    def save_asset_graph(self, graph: Any) -> None:
        """Saves an AssetGraph instance into local state atomically."""
        graph.save_to_file(self.assets_file)

    # ---------------- Endpoint Management ----------------

    def add_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Adds or updates an endpoint."""
        url = endpoint.get("url")
        method = endpoint.get("method", "GET").upper()
        if not url:
            raise ValueError("Endpoint must include 'url'.")

        key = f"{method} {url}"
        endpoints = self._read_json(self.endpoints_file)
        now_str = datetime.now(timezone.utc).isoformat()

        if key in endpoints:
            existing = endpoints[key]
            existing.update(endpoint)
            existing["last_seen"] = now_str
            endpoints[key] = existing
        else:
            ep_record = dict(endpoint)
            ep_record["first_seen"] = now_str
            ep_record["last_seen"] = now_str
            endpoints[key] = ep_record

        self._atomic_write_json(self.endpoints_file, endpoints)
        return endpoints[key]

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Returns all discovered endpoints."""
        endpoints = self._read_json(self.endpoints_file)
        return list(endpoints.values())

    # ---------------- Technology Management ----------------

    def set_technologies(self, hostname: str, techs: List[str]) -> None:
        """Sets detected technologies for a host."""
        tech_data = self._read_json(self.technologies_file)
        existing = set(tech_data.get(hostname, []))
        existing.update(techs)
        tech_data[hostname] = sorted(list(existing))
        self._atomic_write_json(self.technologies_file, tech_data)

    def get_technologies(self, hostname: str) -> List[str]:
        """Gets detected technologies for a host."""
        tech_data = self._read_json(self.technologies_file)
        return tech_data.get(hostname, [])

    # ---------------- Test Deduplication & Execution ----------------

    def has_test_run(
        self,
        target: str,
        endpoint: str,
        method: str,
        parameter: Optional[str] = None,
        test_category: str = "general",
    ) -> bool:
        """Checks if a test with the same fingerprint has already been executed."""
        fp = generate_test_fingerprint(target, endpoint, method, parameter, test_category)
        tests = self._read_json(self.tests_file)
        return fp in tests

    def record_test(
        self,
        target: str,
        endpoint: str,
        method: str,
        parameter: Optional[str] = None,
        test_category: str = "general",
        result: str = "SUCCESS",
        evidence_reference: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], bool]:
        """
        Records a test run in the state.
        Returns (test_record, is_new).
        """
        fp = generate_test_fingerprint(target, endpoint, method, parameter, test_category)
        tests = self._read_json(self.tests_file)
        is_new = fp not in tests

        record = {
            "test_id": f"TEST-{fp[:8].upper()}",
            "fingerprint": fp,
            "target": target,
            "endpoint": endpoint,
            "method": method.upper(),
            "parameter": parameter or "",
            "category": test_category.lower(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "result": result,
            "evidence_reference": evidence_reference,
        }

        tests[fp] = record
        self._atomic_write_json(self.tests_file, tests)
        return record, is_new

    def get_tests(self) -> List[Dict[str, Any]]:
        """Returns all recorded test runs."""
        tests = self._read_json(self.tests_file)
        return list(tests.values())

    # ---------------- Hypothesis Management ----------------

    def add_hypothesis(self, hypothesis: Dict[str, Any]) -> Dict[str, Any]:
        """Records a researcher hypothesis for targeted verification."""
        hypos = self._read_json(self.hypotheses_file)
        if not isinstance(hypos, list):
            hypos = []

        hypo_id = hypothesis.get("id") or f"HYP-{len(hypos)+1:03d}"
        record = dict(hypothesis)
        record["id"] = hypo_id
        record["created_at"] = datetime.now(timezone.utc).isoformat()
        if "status" not in record:
            record["status"] = "PENDING_VERIFICATION"

        hypos.append(record)
        self._atomic_write_json(self.hypotheses_file, hypos)
        return record

    def get_hypotheses(self) -> List[Dict[str, Any]]:
        """Returns all hypotheses."""
        hypos = self._read_json(self.hypotheses_file)
        return hypos if isinstance(hypos, list) else []

    # ---------------- Finding Management & Deduplication ----------------

    def record_finding(
        self,
        finding: Finding | Dict[str, Any],
        engine_source: Optional[str] = None,
    ) -> Tuple[Finding, bool, Optional[str]]:
        """
        Canonical gateway for cross-engine finding persistence and deduplication.
        Ensures state/findings.json is the authoritative registry across all security engines.
        Preserves engine provenance, correlates duplicate findings, and merges supporting evidence.
        Returns (finding, is_duplicate, duplicate_of_id).
        """
        # Convert dictionary to normalized Finding object if needed
        if isinstance(finding, dict):
            f_id = finding.get("finding_id") or finding.get("id") or finding.get("candidate_id")
            title = finding.get("title") or f"Vulnerability on {finding.get('affected_endpoint') or finding.get('endpoint', '/')}"
            summary = finding.get("summary") or (finding.get("description", "")[:200] if finding.get("description") else title)
            asset = finding.get("affected_asset") or finding.get("asset") or "target.local"
            endpoint = finding.get("affected_endpoint") or finding.get("endpoint") or "/"
            vuln_type = finding.get("vulnerability_type") or finding.get("vuln_type") or finding.get("family") or "Security Flaw"
            severity = finding.get("severity", "MEDIUM")
            confidence = str(finding.get("confidence", "HIGH")).upper()
            if confidence == "VALIDATED":
                confidence = "CONFIRMED"
            elif confidence not in {"CONFIRMED", "HIGH", "MEDIUM", "LOW"}:
                confidence = "HIGH"
            raw_state = finding.get("lifecycle_state") or finding.get("lifecycle", "CANDIDATE")
            desc = finding.get("description") or summary
            root_cause = finding.get("root_cause") or "Identified security defect."
            prereqs = finding.get("prerequisites") or "Standard network access."
            repro = finding.get("reproduction_steps") or ["Send verified request sequence to affected endpoint."]
            exp = finding.get("expected_result") or "System enforces authorization and validation boundaries."
            obs = finding.get("observed_result") or desc
            impact = finding.get("security_impact") or "Potential integrity or confidentiality compromise."
            remediation = finding.get("remediation") or "Apply appropriate validation and access controls."
            scope_ref = finding.get("scope_reference") or "Target in authorized scope."
            evidence = finding.get("evidence") or []
            prov = finding.get("provenance") or {}
            val_notes = finding.get("validation_notes") or finding.get("notes")

            # Determine lifecycle state safely
            try:
                state_enum = FindingLifecycle(raw_state)
            except Exception:
                state_enum = FindingLifecycle.CANDIDATE

            # If marked VALIDATED without evidence, safely set to NEEDS_MANUAL_REVIEW
            if state_enum == FindingLifecycle.VALIDATED and not evidence:
                state_enum = FindingLifecycle.NEEDS_MANUAL_REVIEW
                if not val_notes:
                    val_notes = "Candidate recorded without attached evidence; flagged for manual review."
            elif state_enum == FindingLifecycle.VALIDATED and not val_notes:
                val_notes = "Verified evidence attached from engine recording."

            finding_obj = Finding(
                finding_id=f_id,
                title=title,
                summary=summary,
                affected_asset=asset,
                affected_endpoint=endpoint,
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=confidence,
                lifecycle_state=state_enum,
                description=desc,
                root_cause=root_cause,
                prerequisites=prereqs,
                reproduction_steps=repro,
                expected_result=exp,
                observed_result=obs,
                security_impact=impact,
                remediation=remediation,
                scope_reference=scope_ref,
                evidence=evidence,
                provenance=prov,
                validation_notes=val_notes,
                parameter=finding.get("parameter"),
                duplicate_of=finding.get("duplicate_of"),
            )
        else:
            finding_obj = finding

        # Record engine provenance
        if not isinstance(finding_obj.provenance, dict):
            finding_obj.provenance = {}
        if engine_source:
            finding_obj.provenance["engine_source"] = engine_source
            corr = set(finding_obj.provenance.get("correlated_engines", []))
            corr.add(engine_source)
            finding_obj.provenance["correlated_engines"] = sorted(list(corr))

        findings = self._read_json(self.findings_file)
        if not isinstance(findings, dict):
            findings = {}
        existing_list = list(findings.values())

        # Cross-engine deduplication evaluation
        is_dup = False
        dup_id = None
        if finding_obj.finding_id not in findings:
            is_dup, dup_id = FindingDeduplicator.check_duplicate(
                candidate_asset=finding_obj.affected_asset,
                candidate_endpoint=finding_obj.affected_endpoint,
                candidate_vuln=finding_obj.vulnerability_type,
                candidate_root_cause=finding_obj.root_cause,
                existing_findings=existing_list,
                candidate_parameter=finding_obj.parameter,
            )

        if is_dup and dup_id:
            finding_obj.duplicate_of = dup_id
            # Merge supporting evidence into existing canonical finding without discarding
            if dup_id in findings:
                existing_entry = findings[dup_id]
                existing_evidence = existing_entry.get("evidence", [])
                seen_digests = {
                    e.get("metadata", {}).get("sha256")
                    for e in existing_evidence
                    if isinstance(e, dict) and e.get("metadata", {}).get("sha256")
                }
                seen_contents = {
                    e.get("content") for e in existing_evidence if isinstance(e, dict) and e.get("content")
                }
                for new_ev in finding_obj.evidence:
                    if not isinstance(new_ev, dict):
                        continue
                    new_digest = new_ev.get("metadata", {}).get("sha256")
                    new_content = new_ev.get("content")
                    if (new_digest and new_digest in seen_digests) or (new_content and new_content in seen_contents):
                        continue
                    sanitized_ev = dict(new_ev)
                    if "content" in sanitized_ev and isinstance(sanitized_ev["content"], str):
                        sanitized_ev["content"] = sanitize_sensitive_data(sanitized_ev["content"])
                    existing_evidence.append(sanitized_ev)
                existing_entry["evidence"] = existing_evidence

                # Correlate source engines in provenance
                existing_prov = existing_entry.get("provenance", {})
                if not isinstance(existing_prov, dict):
                    existing_prov = {}
                corr_engines = set(existing_prov.get("correlated_engines", []))
                if engine_source:
                    corr_engines.add(engine_source)
                if finding_obj.provenance.get("engine_source"):
                    corr_engines.add(finding_obj.provenance["engine_source"])
                existing_prov["correlated_engines"] = sorted(list(corr_engines))
                existing_entry["provenance"] = existing_prov
                existing_entry["updated_at"] = datetime.now(timezone.utc).isoformat()
                findings[dup_id] = existing_entry
                self._atomic_write_json(self.findings_file, findings)
            return finding_obj, True, dup_id

        # Persist new finding to canonical state/findings.json (Finding.to_dict ensures evidence sanitization)
        findings[finding_obj.finding_id] = finding_obj.to_dict()
        self._atomic_write_json(self.findings_file, findings)
        return finding_obj, False, None

    def save_finding(self, finding: Finding) -> Tuple[Finding, bool, Optional[str]]:
        """
        Saves or updates finding in local program state with cross-engine deduplication.
        Returns (finding, is_duplicate, duplicate_of_id).
        """
        return self.record_finding(finding)

    def sync_all_engine_findings(self) -> int:
        """
        Safely inspects engine-specific state files and synchronizes any previously
        un-indexed findings into canonical state/findings.json.
        Preserves existing data without deleting or overwriting.
        Returns count of newly indexed findings.
        """
        engine_files = [
            (os.path.join(self.state_dir, "security.json"), "validation"),
            (os.path.join(self.state_dir, "authorization.json"), "authorization"),
            (os.path.join(self.state_dir, "injection.json"), "injection"),
            (os.path.join(self.state_dir, "cloud.json"), "cloud_security"),
            (os.path.join(self.state_dir, "business_logic.json"), "business_logic"),
            (os.path.join(self.state_dir, "xss.json"), "xss"),
            (os.path.join(self.state_dir, "ssrf.json"), "ssrf"),
            (os.path.join(self.state_dir, "authentication.json"), "authentication"),
        ]

        indexed_count = 0
        canonical_findings = self._read_json(self.findings_file)
        if not isinstance(canonical_findings, dict):
            canonical_findings = {}

        for state_path, engine_name in engine_files:
            if not os.path.isfile(state_path):
                continue
            try:
                state_data = self._read_json(state_path)
                if not isinstance(state_data, dict):
                    continue
                raw_finds = state_data.get("findings", {})
                if not raw_finds and "candidates" in state_data:
                    raw_finds = state_data.get("candidates", {})
                if isinstance(raw_finds, dict):
                    items = list(raw_finds.values())
                elif isinstance(raw_finds, list):
                    items = raw_finds
                else:
                    items = []

                for item in items:
                    if not isinstance(item, dict):
                        continue
                    item_id = item.get("finding_id") or item.get("id") or item.get("candidate_id")
                    if item_id and item_id in canonical_findings:
                        continue
                    self.record_finding(item, engine_source=engine_name)
                    canonical_findings = self._read_json(self.findings_file)
                    indexed_count += 1
            except Exception:
                continue

        return indexed_count

    def get_findings(self, lifecycle_state: Optional[str] = None) -> List[Finding]:
        """Returns findings, optionally filtered by lifecycle state."""
        findings_dict = self._read_json(self.findings_file)
        result = []
        for d in findings_dict.values():
            try:
                f = Finding.from_dict(d)
                if lifecycle_state is None or f.lifecycle_state.value == lifecycle_state:
                    result.append(f)
            except Exception:
                pass
        return result

    # ---------------- Coverage Tracking ----------------

    def update_coverage(self, category: str, status: str) -> Dict[str, str]:
        """Updates coverage status for a testing category."""
        valid_statuses = {"not_tested", "partial", "high"}
        if status not in valid_statuses:
            raise ValueError(f"Invalid coverage status '{status}'. Must be one of {valid_statuses}")

        cov = self._read_json(self.coverage_file)
        if not isinstance(cov, dict):
            cov = dict(DEFAULT_COVERAGE)

        cov[category] = status
        self._atomic_write_json(self.coverage_file, cov)
        return cov

    def get_coverage(self) -> Dict[str, str]:
        """Returns current coverage matrix."""
        cov = self._read_json(self.coverage_file)
        if not isinstance(cov, dict):
            return dict(DEFAULT_COVERAGE)
        return cov

    # ---------------- Reconnaissance State ----------------

    def get_recon_state(self) -> Any:
        """Returns a ReconStateManager instance for this program."""
        from framework.recon.state import ReconStateManager
        return ReconStateManager(self.program_dir)

    # ---------------- Web Application State ----------------

    def get_webapp_state(self) -> Any:
        """Returns a WebAppStateManager instance for this program."""
        from framework.webapp.state import WebAppStateManager
        return WebAppStateManager(self.program_dir)

    # ---------------- JavaScript Intelligence State ----------------

    def get_javascript_state(self) -> Any:
        """Returns a JavaScriptStateManager instance for this program."""
        from framework.javascript.state import JavaScriptStateManager
        return JavaScriptStateManager(self.program_dir)

    # ---------------- API Security State ----------------

    def get_api_state(self) -> Any:
        """Returns an ApiStateManager instance for this program."""
        from framework.api.state import ApiStateManager
        return ApiStateManager(self.program_dir)

    # ---------------- Security Validation State ----------------

    def get_security_state(self) -> Any:
        """Returns a SecurityStateManager instance for this program."""
        from framework.validation.state import SecurityStateManager
        return SecurityStateManager(self.program_dir)

