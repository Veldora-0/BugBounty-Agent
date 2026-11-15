"""
Phase 22.4: Attack-Path Reporting Engine.

Provides multi-format reporting (JSON, Markdown, Terminal) for correlated attack paths,
feasibility assessments, validation plans, and empirical evidence provenance.

Core Invariants:
1. Anti-Inflation: Individual finding severities and compound impact ratings are never inflated.
2. Provenance Transparency: Clearly distinguishes between OBSERVED, SIMULATED, and INFERRED evidence.
3. State Separation: Decouples HYPOTHESIS, PARTIALLY_VALIDATED, and FULLY_VALIDATED chains.
4. Zero-Secret Reporting: Strictly asserts no raw credentials, tokens, or private keys in reports.
5. Deterministic Serialization: Produces consistent, auditable outputs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional, Set

from framework.attack_path.model import (
    AttackGraph,
    AttackGraphEdge,
    AttackGraphNode,
    AttackPath,
    CapabilityType,
    ChainState,
    EdgeType,
    NodeType,
    RelationshipState,
    assert_no_raw_secrets,
)
from framework.attack_path.state import AttackPathStateManager
from framework.attack_path.validator import (
    ChainValidationPlan,
    ValidationAuditEvent,
    ValidationPlanStatus,
)


@dataclass
class AttackPathReportData:
    """Canonical data model for attack path reports."""
    report_id: str
    generated_at: str
    program_name: str
    scope_context: Dict[str, Any]
    summary_stats: Dict[str, Any]
    attack_paths: List[Dict[str, Any]]
    validation_plans: List[Dict[str, Any]]
    recent_audit_events: List[Dict[str, Any]]
    limitations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at,
            "program_name": self.program_name,
            "scope_context": self.scope_context,
            "summary_stats": self.summary_stats,
            "attack_paths": self.attack_paths,
            "validation_plans": self.validation_plans,
            "recent_audit_events": self.recent_audit_events,
            "limitations": self.limitations,
        }


class AttackPathReporter:
    """
    Renders authoritative reports from attack graph state, candidate paths,
    validation plans, and audit logs.
    """

    def __init__(
        self,
        state_manager: Optional[AttackPathStateManager] = None,
        graph: Optional[AttackGraph] = None,
        paths: Optional[List[AttackPath]] = None,
        plans: Optional[Dict[str, ChainValidationPlan]] = None,
        audit_log: Optional[List[ValidationAuditEvent]] = None,
        program_name: str = "default-program",
        scope_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.state_manager = state_manager
        self.program_name = program_name
        self.scope_info = scope_info or {"status": "IN_SCOPE", "policy": "STRICT_DEFAULT_DENY"}

        # Resolve authoritative graph
        if graph is not None:
            self.graph = graph
        elif self.state_manager is not None:
            self.graph = self.state_manager.load_graph()
        else:
            self.graph = AttackGraph()

        # Resolve paths
        self.paths = list(paths or [])

        # Resolve plans
        if plans is not None:
            self.plans = dict(plans)
        elif self.state_manager is not None:
            self.plans = self.state_manager.load_plans()
        else:
            self.plans = {}

        # Resolve audit log
        if audit_log is not None:
            self.audit_log = list(audit_log)
        elif self.state_manager is not None:
            self.audit_log = self.state_manager.load_audit_events()
        else:
            self.audit_log = []

    def get_summary_stats(self) -> Dict[str, Any]:
        """Calculates authoritative aggregate statistics."""
        total_paths = len(self.paths)
        fully_validated = sum(1 for p in self.paths if p.state == ChainState.FULLY_VALIDATED)
        partially_validated = sum(1 for p in self.paths if p.state == ChainState.PARTIALLY_VALIDATED)
        hypotheses = sum(1 for p in self.paths if p.state == ChainState.HYPOTHESIS)
        blocked_or_refuted = sum(1 for p in self.paths if p.state in (ChainState.BLOCKED, ChainState.REFUTED))

        total_plans = len(self.plans)
        pending_approval = sum(1 for p in self.plans.values() if p.status == ValidationPlanStatus.PENDING_APPROVAL)
        approved = sum(1 for p in self.plans.values() if p.status == ValidationPlanStatus.APPROVED)
        rejected = sum(1 for p in self.plans.values() if p.status == ValidationPlanStatus.REJECTED)
        revoked = sum(1 for p in self.plans.values() if p.status == ValidationPlanStatus.REVOKED)
        dispatched = sum(1 for p in self.plans.values() if p.status == ValidationPlanStatus.DISPATCHED)
        completed = sum(1 for p in self.plans.values() if p.status in (
            ValidationPlanStatus.COMPLETED,
            ValidationPlanStatus.EVIDENCE_VERIFIED,
            ValidationPlanStatus.RELATIONSHIP_VALIDATED,
            ValidationPlanStatus.CHAIN_VALIDATED,
        ))

        return {
            "graph_node_count": self.graph.node_count(),
            "graph_edge_count": self.graph.edge_count(),
            "total_attack_paths": total_paths,
            "fully_validated_paths": fully_validated,
            "partially_validated_paths": partially_validated,
            "hypothetical_paths": hypotheses,
            "blocked_or_refuted_paths": blocked_or_refuted,
            "total_validation_plans": total_plans,
            "plans_pending_approval": pending_approval,
            "plans_approved": approved,
            "plans_rejected": rejected,
            "plans_revoked": revoked,
            "plans_dispatched": dispatched,
            "plans_completed": completed,
            "audit_events_recorded": len(self.audit_log),
        }

    def build_report_data(self) -> AttackPathReportData:
        """Constructs the canonical sanitized report data structure."""
        now_iso = datetime.now(timezone.utc).isoformat()
        stats = self.get_summary_stats()

        serialized_paths = []
        for p in self.paths:
            # Enrich path with detailed node & edge semantics
            path_nodes = []
            for nid in p.node_ids:
                n = self.graph.get_node(nid)
                if n:
                    path_nodes.append({
                        "node_id": n.node_id,
                        "node_type": n.node_type.value,
                        "label": n.label,
                        "asset": n.attributes.get("asset", "N/A"),
                        "scope_status": n.scope_status,
                    })

            path_edges = []
            for eid in p.edge_ids:
                e = self.graph.get_edge(eid)
                if e:
                    prov_data = e.provenance.to_dict() if e.provenance else None
                    path_edges.append({
                        "edge_id": e.edge_id,
                        "source_id": e.source_id,
                        "destination_id": e.destination_id,
                        "edge_type": e.edge_type.value,
                        "state": e.state.value,
                        "provenance": prov_data,
                    })

            serialized_paths.append({
                "path_id": p.path_id,
                "state": p.state.value,
                "feasibility": p.feasibility,
                "compound_impact": p.compound_impact,
                "fingerprint": p.fingerprint,
                "hop_count": len(p.edge_ids),
                "nodes": path_nodes,
                "edges": path_edges,
            })

        serialized_plans = [plan.to_dict() for plan in self.plans.values()]
        recent_audit = [evt.to_dict() for evt in self.audit_log[-50:]]

        limitations = [
            "Attack paths without full LINK_VALIDATED constituent edges remain hypotheses or partially validated.",
            "Active validation is strictly gated by operator approval and dynamic anti-TOCTOU scope re-verification.",
            "Raw credentials and sensitive authorization tokens are strictly scrubbed from all outputs.",
            "Testing operations are non-destructive and rate-limited to preserve target stability.",
        ]

        report = AttackPathReportData(
            report_id=f"RPT-PATH-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            generated_at=now_iso,
            program_name=self.program_name,
            scope_context=self.scope_info,
            summary_stats=stats,
            attack_paths=serialized_paths,
            validation_plans=serialized_plans,
            recent_audit_events=recent_audit,
            limitations=limitations,
        )

        # Enforce zero-secret compliance on assembled report data
        assert_no_raw_secrets(report.to_dict(), "AttackPathReportData")
        return report

    def generate_json(self, indent: int = 2) -> str:
        """Serializes report into canonical JSON string."""
        data = self.build_report_data().to_dict()
        return json.dumps(data, indent=indent, sort_keys=True)

    def generate_dict(self) -> Dict[str, Any]:
        """Returns the canonical report data as a Python dictionary."""
        return self.build_report_data().to_dict()

    def generate_markdown(self) -> str:
        """Renders comprehensive, report-ready Markdown."""
        rep = self.build_report_data()
        stats = rep.summary_stats

        lines = [
            f"# Attack-Path Correlation & Vulnerability Chaining Report",
            f"",
            f"**Program:** `{rep.program_name}`  ",
            f"**Report ID:** `{rep.report_id}`  ",
            f"**Generated At (UTC):** `{rep.generated_at}`  ",
            f"**Scope Posture:** `{rep.scope_context.get('policy', 'STRICT_DEFAULT_DENY')}`  ",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary & Graph Metrics",
            f"",
            f"| Metric | Count | Description |",
            f"| :--- | :--- | :--- |",
            f"| **Graph Nodes** | `{stats['graph_node_count']}` | Entities across assets, endpoints, principals, findings, and capabilities |",
            f"| **Graph Edges** | `{stats['graph_edge_count']}` | Semantic directed relationships |",
            f"| **Total Attack Paths** | `{stats['total_attack_paths']}` | Identified multi-hop composite attack paths |",
            f"| **Fully Validated Chains** | `{stats['fully_validated_paths']}` | All constituent edges verified with empirical evidence |",
            f"| **Partially Validated Paths** | `{stats['partially_validated_paths']}` | At least one validated edge, remaining edges theoretical |",
            f"| **Hypothetical Paths** | `{stats['hypothetical_paths']}` | Feasible candidate paths awaiting empirical validation |",
            f"| **Active Validation Plans** | `{stats['total_validation_plans']}` | Structured validation plans ({stats['plans_approved']} approved, {stats['plans_pending_approval']} pending) |",
            f"",
            f"> [!IMPORTANT]",
            f"> **Anti-Inflation Policy:** Component finding severities and compound impacts are never inflated. A composite chain is marked `FULLY_VALIDATED` if and only if every hop has verified empirical proof.",
            f"",
            f"---",
            f"",
            f"## 2. Attack-Path Inventory",
            f"",
        ]

        if not rep.attack_paths:
            lines.append("*No attack paths discovered or loaded in current session.*")
            lines.append("")
        else:
            for idx, p in enumerate(rep.attack_paths, 1):
                state_badge = f"**{p['state']}**"
                if p["state"] == "FULLY_VALIDATED":
                    state_badge = "🟩 **FULLY_VALIDATED**"
                elif p["state"] == "PARTIALLY_VALIDATED":
                    state_badge = "🟨 **PARTIALLY_VALIDATED**"
                elif p["state"] == "HYPOTHESIS":
                    state_badge = "🟦 **HYPOTHESIS**"

                lines.extend([
                    f"### Path {idx}: `{p['path_id']}`",
                    f"- **Status:** {state_badge}",
                    f"- **Feasibility:** `{p['feasibility']}`",
                    f"- **Compound Impact:** `{p['compound_impact']}`",
                    f"- **Hop Count:** `{p['hop_count']}`",
                    f"- **Fingerprint:** `{p['fingerprint']}`",
                    f"",
                    f"#### Traversal Sequence:",
                    f"```text",
                ])
                node_labels = [f"[{n['node_type']}] {n['label']} ({n['asset']})" for n in p["nodes"]]
                lines.append(" ->\n  ".join(node_labels))
                lines.extend([
                    f"```",
                    f"",
                    f"#### Constituent Relationships:",
                    f"| Edge ID | Source -> Destination | Edge Type | Relationship State | Evidence / Provenance |",
                    f"| :--- | :--- | :--- | :--- | :--- |",
                ])
                for e in p["edges"]:
                    prov = e.get("provenance")
                    prov_desc = "Theoretical (Unverified)"
                    if prov:
                        prov_desc = f"{prov.get('authenticity_class')} ({prov.get('causality_proof_type')})"
                    lines.append(
                        f"| `{e['edge_id']}` | `{e['source_id']}` -> `{e['destination_id']}` | `{e['edge_type']}` | `{e['state']}` | {prov_desc} |"
                    )
                lines.append("")

        lines.extend([
            f"---",
            f"",
            f"## 3. Validation Plans & Human Approval Records",
            f"",
        ])

        if not rep.validation_plans:
            lines.append("*No validation plans registered.*")
            lines.append("")
        else:
            lines.extend([
                f"| Plan ID | Target Asset & Endpoint | Method | Status | Approval Details | Version & Hash |",
                f"| :--- | :--- | :--- | :--- | :--- | :--- |",
            ])
            for plan in rep.validation_plans:
                appr = plan.get("approval")
                appr_str = "None (Awaiting Review)"
                if appr:
                    appr_str = f"Approved by `{appr.get('approved_by')}` (Expires: {appr.get('expires_at')})"
                    if appr.get("revoked"):
                        appr_str = f"REVOKED: {appr.get('revocation_reason')}"
                lines.append(
                    f"| `{plan['plan_id']}` | `{plan['target_asset']}` `{plan['target_endpoint']}` | `{plan['validation_method']}` | **{plan['status']}** | {appr_str} | v{plan['version']} (`{plan['plan_hash'][:8]}...`) |"
                )
            lines.append("")

        lines.extend([
            f"---",
            f"",
            f"## 4. Methodological Safeguards & Limitations",
            f"",
        ])
        for lim in rep.limitations:
            lines.append(f"- {lim}")
        lines.append("")

        return "\n".join(lines)

    def generate_terminal_summary(self) -> str:
        """Renders a concise, human-readable ASCII summary for CLI output."""
        rep = self.build_report_data()
        stats = rep.summary_stats

        sep = "=" * 78
        lines = [
            sep,
            "             BUGBOUNTY-AGENT: ATTACK-PATH CORRELATION SUMMARY             ",
            sep,
            f" Program:               {rep.program_name}",
            f" Report ID:             {rep.report_id}",
            f" Scope Enforcement:     {rep.scope_context.get('status', 'IN_SCOPE')} ({rep.scope_context.get('policy', 'STRICT')})",
            f" Graph Size:            {stats['graph_node_count']} nodes, {stats['graph_edge_count']} edges",
            "",
            " [PATH METRICS]",
            f"   Total Candidate Paths:      {stats['total_attack_paths']}",
            f"   - Fully Validated:          {stats['fully_validated_paths']}",
            f"   - Partially Validated:      {stats['partially_validated_paths']}",
            f"   - Hypothetical:             {stats['hypothetical_paths']}",
            f"   - Blocked / Refuted:        {stats['blocked_or_refuted_paths']}",
            "",
            " [VALIDATION PLANNING & APPROVAL]",
            f"   Total Validation Plans:     {stats['total_validation_plans']}",
            f"   - Pending Approval:         {stats['plans_pending_approval']}",
            f"   - Approved (Ready):         {stats['plans_approved']}",
            f"   - Completed:                {stats['plans_completed']}",
            f"   - Rejected / Revoked:       {stats['plans_rejected'] + stats['plans_revoked']}",
            sep,
        ]

        if rep.attack_paths:
            lines.append(" TOP DISCOVERED ATTACK PATHS:")
            for p in rep.attack_paths[:5]:
                nodes_chain = " -> ".join([n["node_id"] for n in p["nodes"]])
                lines.append(f"   [{p['state']}] {p['path_id']} ({p['feasibility']})")
                lines.append(f"     Path: {nodes_chain}")
            if len(rep.attack_paths) > 5:
                lines.append(f"   ... and {len(rep.attack_paths) - 5} more paths. Use 'bb-chain list' to inspect all.")
            lines.append(sep)

        return "\n".join(lines)

    def save_report(self, output_path: str, report_format: str = "markdown") -> str:
        """
        Saves report to the specified file path in the chosen format.
        Enforces zero-secret assertions before writing to disk.
        """
        abs_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)

        fmt = report_format.lower().strip()
        if fmt == "json":
            content = self.generate_json()
        elif fmt in ("md", "markdown"):
            content = self.generate_markdown()
        elif fmt in ("terminal", "txt", "text"):
            content = self.generate_terminal_summary()
        else:
            raise ValueError(f"Unsupported report format '{report_format}'. Supported: json, markdown, terminal")

        assert_no_raw_secrets(content, f"save_report({output_path})")

        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(content)

        return abs_path
