"""Offline, scope-aware research planning and public disclosure relevance."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit, urlunsplit

from framework.common.evidence import sanitize_sensitive_data
from framework.scope.engine import ScopeEngine


class PlanningInputError(ValueError):
    """Raised when local planning inputs are missing or malformed."""


class CoverageIndex:
    """Read-only snapshot of local program coverage filtered through current scope."""

    def __init__(self, program_dir: str, scope_engine: ScopeEngine) -> None:
        self.program_dir = os.path.abspath(program_dir)
        if os.path.islink(self.program_dir):
            raise PlanningInputError("Program directory must not be a symbolic link")
        self.scope_engine = scope_engine
        self.state_dir = os.path.join(self.program_dir, "state")
        self.assets: List[Dict[str, Any]] = []
        self.endpoints: List[Dict[str, Any]] = []
        self.technologies: Dict[str, List[str]] = {}
        self.tests: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.coverage: Dict[str, Any] = {}
        self._load()

    @staticmethod
    def _read(path: str, default: Any) -> Any:
        if os.path.islink(path):
            raise PlanningInputError(f"Planning input '{os.path.basename(path)}' must not be a symbolic link")
        if not os.path.isfile(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as stream:
                value = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise PlanningInputError(f"Cannot read planning input '{os.path.basename(path)}': {exc}") from exc
        return value

    def _load(self) -> None:
        if os.path.islink(self.state_dir):
            raise PlanningInputError("Program state directory must not be a symbolic link")
        raw_assets = self._read(os.path.join(self.state_dir, "assets.json"), {})
        if isinstance(raw_assets, dict) and isinstance(raw_assets.get("assets"), dict):
            raw_assets = raw_assets["assets"]
        self.assets = _records(raw_assets, "assets.json")
        self.endpoints = _records(self._read(os.path.join(self.state_dir, "endpoints.json"), {}), "endpoints.json")
        self.tests = _records(self._read(os.path.join(self.state_dir, "tests.json"), {}), "tests.json")
        self.findings = _records(self._read(os.path.join(self.state_dir, "findings.json"), {}), "findings.json")
        raw_tech = self._read(os.path.join(self.state_dir, "technologies.json"), {})
        if not isinstance(raw_tech, dict):
            raise PlanningInputError("technologies.json must contain an object")
        self.technologies = {
            _norm(host): [_clean_text(t, 100) for t in values if isinstance(t, (str, int, float))]
            for host, values in raw_tech.items() if isinstance(values, list)
        }
        raw_coverage = self._read(os.path.join(self.state_dir, "coverage.json"), {})
        if not isinstance(raw_coverage, dict):
            raise PlanningInputError("coverage.json must contain an object")
        self.coverage = raw_coverage

        scoped_assets = []
        for asset in self.assets:
            target = _asset_target(asset)
            if target and self.scope_engine.is_in_scope(target):
                row = dict(asset)
                row["_target"] = target
                scoped_assets.append(row)
        self.assets = scoped_assets

        scoped_endpoints = []
        for endpoint in self.endpoints:
            url = str(endpoint.get("url") or endpoint.get("endpoint") or "").strip()
            if url and self.scope_engine.is_in_scope(url):
                row = dict(endpoint)
                row["_target"] = url
                row["_host"] = _host(url)
                scoped_endpoints.append(row)
        self.endpoints = scoped_endpoints

        scoped_targets = {_norm(a["_target"]) for a in self.assets}
        scoped_hosts = {_host(a["_target"]) for a in self.assets}
        scoped_endpoints = {_norm(e["_target"]) for e in self.endpoints}
        # Retain only test history whose target is currently in-scope and inventoried.
        self.tests = [t for t in self.tests if _norm(t.get("target", "")) in scoped_targets | scoped_endpoints
                      or _host(str(t.get("target", ""))) in scoped_hosts]
        self.findings = [f for f in self.findings
                         if str(f.get("lifecycle_state", "")).upper() == "VALIDATED"
                         and (_norm(f.get("affected_asset", "")) in scoped_targets
                              or _host(str(f.get("affected_asset", ""))) in scoped_hosts)]

    def to_dict(self) -> Dict[str, Any]:
        known_categories = {row[0] for row in VULNERABILITY_FAMILIES}
        categories = sorted({_category(t.get("category", "general")) for t in self.tests
                             if _category(t.get("category", "general")) in known_categories})
        allowed_coverage = {"authentication", "authorization", "api", "javascript", "uploads",
                            "business_logic", "cloud", "injection", "ssrf", "upload"}
        return {
            "scope_verified": True,
            "assets_in_scope": len(self.assets),
            "endpoints_in_scope": len(self.endpoints),
            "technologies": sorted({_clean_text(x, 100) for values in self.technologies.values() for x in values}, key=str.lower),
            "tests_in_scope": len(self.tests),
            "tested_categories": categories,
            "validated_findings_in_scope": len(self.findings),
            "coverage": {str(k): str(v) for k, v in self.coverage.items()
                         if str(k).lower() in allowed_coverage
                         and str(v).lower() in {"not_tested", "partial", "high"}},
        }


VULNERABILITY_FAMILIES: Tuple[Tuple[str, int, int, int, Tuple[str, ...]], ...] = (
    ("authorization", 5, 3, 2, ("api", "endpoint", "account", "tenant", "user")),
    ("authentication", 5, 3, 2, ("login", "session", "auth", "account")),
    ("business_logic", 4, 2, 2, ("checkout", "payment", "order", "workflow", "api")),
    ("api", 4, 3, 2, ("api", "graphql", "rest", "json")),
    ("injection", 5, 2, 2, ("api", "search", "query", "form", "parameter")),
    ("javascript", 3, 3, 1, ("javascript", "spa", "web", "script")),
    ("upload", 4, 2, 2, ("upload", "file", "attachment")),
    ("ssrf", 5, 2, 2, ("url", "webhook", "import", "fetch", "api")),
    ("cloud", 4, 2, 1, ("cloud", "storage", "bucket", "s3", "gcs")),
)

_INCONCLUSIVE = {"INCONCLUSIVE", "FAILED", "ERROR", "TIMEOUT", "UNKNOWN"}
_COVERED = {"CONFIRMED", "REJECTED", "COMPLETED", "COVERED", "TESTED"}
_TEST_FRESH_DAYS = 90


class ResearchPlanner:
    """Produces prioritized hypotheses only; it never dispatches target requests."""

    def __init__(self, index: CoverageIndex) -> None:
        self.index = index

    def recommend(self, budget: int = 20, limit: int = 50,
                  research_reports: Optional[Sequence[Dict[str, Any]]] = None) -> Dict[str, Any]:
        if budget < 0 or limit < 1:
            raise ValueError("budget must be >= 0 and limit must be >= 1")
        now = datetime.now(timezone.utc)
        candidates: List[Dict[str, Any]] = []
        skipped: List[Dict[str, str]] = []
        surfaces = self.index.endpoints or [
            {"_target": a["_target"], "_host": _host(a["_target"]), "method": "", "_asset_only": True}
            for a in self.index.assets
        ]
        for surface in surfaces:
            target = surface["_target"]
            host = surface.get("_host") or _host(target)
            techs = self.index.technologies.get(_norm(host), [])
            endpoint_text = target.lower()
            for category, impact, confidence_base, cost, signals in VULNERABILITY_FAMILIES:
                matched = [t for t in techs if any(s in t.lower() for s in signals)]
                related_reports = sorted((r for r in research_reports or []
                                          if _methodology_matches(r, category)),
                                         key=lambda row: row.get("report_id", ""))
                tests = [t for t in self.index.tests
                         if _norm(t.get("target", "")) in {_norm(target), _norm(host)}
                         and _category(t.get("category", "")) == category]
                latest = _latest_test(tests)
                latest_result = str(latest.get("result", "")).upper() if latest else ""
                if latest and _fresh(latest.get("timestamp"), now) and latest_result in _COVERED:
                    skipped.append({"target": _display_target(target), "category": category,
                                    "reason": "A recent test already covers this target and category."})
                    continue
                finding = next((f for f in self.index.findings
                                if _category(f.get("vulnerability_type", f.get("family", ""))) == category
                                and (_norm(f.get("affected_asset", "")) == _norm(host)
                                     or _host(str(f.get("affected_endpoint", ""))) == host)), None)
                if finding:
                    skipped.append({"target": _display_target(target), "category": category,
                                    "reason": "An in-scope validated finding already exists for this category."})
                    continue
                endpoint_signals = [s for s in signals if s in endpoint_text]
                if not matched and not endpoint_signals and category not in {"authorization", "authentication", "api"}:
                    # Keep discovery hypotheses explainable; low relevance is recorded as skipped.
                    skipped.append({"target": _display_target(target), "category": category,
                                    "reason": "No matching technology or endpoint signal in current inventory."})
                    continue
                stale_or_inconclusive = bool(latest)
                confidence = min(5, confidence_base + (1 if matched or endpoint_signals else 0))
                safety = 5 if category in {"javascript", "cloud", "api"} else 4
                freshness = 2 if stale_or_inconclusive else 5
                score = round((impact * 6 + confidence * 5 + safety * 4 + (6 - cost) * 3 + freshness * 2))
                if related_reports:
                    score = min(100, score + 5)
                why = []
                if matched:
                    why.append("technology match: " + ", ".join(sorted(matched, key=str.lower)))
                if endpoint_signals:
                    why.append("endpoint signal: " + ", ".join(endpoint_signals))
                if not why:
                    why.append("coverage gap for a core web security category")
                if stale_or_inconclusive:
                    why.append("previous result was inconclusive or is stale")
                if related_reports:
                    why.append(f"public methodology match: {len(related_reports)} attributed reference(s)")
                safe_target = _display_target(target)
                candidate_id = _digest(category + "|" + _norm(safe_target))[:16]
                candidates.append({
                    "recommendation_id": "REC-" + candidate_id,
                    "target": safe_target,
                    "endpoint": None if surface.get("_asset_only") else safe_target,
                    "category": category,
                    "title": f"Review {category.replace('_', ' ')} controls for {host}",
                    "rationale": "; ".join(why),
                    "potential_impact": impact,
                    "confidence": confidence,
                    "safety": safety,
                    "estimated_cost": cost,
                    "estimated_requests": max(1, cost),
                    "score": score,
                    "status": "RECOMMENDATION_ONLY",
                    "active_testing_authorized": False,
                    "requires_operator_approval": True,
                    "planning_fingerprint": _digest(_norm(safe_target) + "|" + category),
                    "public_research_refs": [r["report_id"] for r in related_reports],
                    "public_research_sources": [
                        {"report_id": r["report_id"], "title": r["title"],
                         "source_url": r["source_url"], "attribution": r["source_attribution"],
                         "published_at": r["published_at"], "disclosure_status": r["disclosure_status"],
                         "technologies": r["technologies"], "technique_summary": r["technique_summary"]}
                        for r in related_reports
                    ],
                })
        candidates.sort(key=lambda x: (-x["score"], x["target"], x["category"]))
        selected: List[Dict[str, Any]] = []
        remaining = budget
        for item in candidates:
            if len(selected) >= limit:
                break
            if item["estimated_requests"] > remaining:
                continue
            selected.append(item)
            remaining -= item["estimated_requests"]
        return {
            "generated_at": now.isoformat(),
            "scope_verified": True,
            "budget": {"request_limit": budget, "reserved_requests": budget - remaining,
                       "remaining_requests": remaining},
            "recommendations": selected,
            "skipped": skipped,
            "execution_performed": False,
            "operator_approval_required": True,
        }


class AriseResearchManager:
    """Stores a target-independent, compact public methodology library for the agent."""

    MAX_REFERENCES = 1000
    ALLOWED_HOSTS = ("hackerone.com", "bugcrowd.com", "google.com", "yeswehack.com",
                     "intigriti.com", "microsoft.com", "github.com", "owasp.org", "cisa.gov",
                     "exploit-db.com", "portswigger.net", "mitre.org", "nist.gov",
                     "projectdiscovery.io")

    def __init__(self, knowledge_dir: str) -> None:
        self.knowledge_dir = os.path.abspath(knowledge_dir)
        self.path = os.path.join(self.knowledge_dir, "methodology.json")

    def refresh(self, discoveries: Optional[Sequence[Dict[str, Any]]] = None,
                checked_sources: Optional[Sequence[str]] = None,
                unchecked_sources: Optional[Sequence[str]] = None) -> Dict[str, Any]:
        existing = _records(CoverageIndex._read(self.path, []), "methodology.json")
        if len(existing) > self.MAX_REFERENCES:
            raise PlanningInputError(f"methodology.json exceeds the {self.MAX_REFERENCES}-reference limit")
        if not discoveries and not checked_sources and not unchecked_sources:
            kept = [self._validate_report(item) for item in existing]
            return {"added": 0, "retained": len(kept), "removed": [], "unchecked_sources": [],
                    "checked_sources": [], "reports": kept, "checked_at": _now(),
                    "target_requests_performed": 0}
        records: Dict[str, Dict[str, Any]] = {}
        for item in existing:
            clean = self._validate_report(item)
            records[clean["report_id"]] = clean
        added = 0
        for item in discoveries or []:
            clean = self._validate_report(item)
            if clean["report_id"] not in records:
                added += 1
            records[clean["report_id"]] = clean
        if len(records) > self.MAX_REFERENCES:
            raise PlanningInputError(f"Adding these references would exceed the {self.MAX_REFERENCES}-reference limit")

        kept = []
        unavailable = [_source_domain(x) for x in (unchecked_sources or []) if str(x).strip()]
        checked = [_source_domain(x) for x in (checked_sources or []) if str(x).strip()]
        for report in records.values():
            source_state = _source_state(report["source_host"], checked, unavailable)
            report["source_check_evaluated_at"] = _now()
            if source_state == "UNAVAILABLE":
                report["source_check_status"] = "UNAVAILABLE"
                report["source_check_detail"] = "Source was unavailable; methodology retained for later review."
            elif source_state == "NOT_CHECKED":
                report["source_check_status"] = "NOT_CHECKED"
                report["source_check_detail"] = "Source was not rechecked; methodology retained."
            else:
                report["source_check_status"] = "CHECKED"
                report["source_checked_at"] = _now()
                report.pop("source_check_detail", None)
            report["status"] = "METHODOLOGY_REFERENCE"
            kept.append(report)
        self._write(kept)
        return {
            "added": added,
            "retained": len(kept),
            "removed": [],
            "unchecked_sources": unavailable,
            "checked_sources": checked,
            "reports": kept,
            "checked_at": _now(),
            "target_requests_performed": 0,
        }

    def load(self) -> List[Dict[str, Any]]:
        """Load and validate references for planning without checking sources or writing state."""
        rows = _records(CoverageIndex._read(self.path, []), "methodology.json")
        if len(rows) > self.MAX_REFERENCES:
            raise PlanningInputError(f"methodology.json exceeds the {self.MAX_REFERENCES}-reference limit")
        return [self._validate_report(row) for row in rows]

    def _validate_report(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raise PlanningInputError("Each public research record must be an object")
        url = str(raw.get("source_url", "")).strip()
        if any(char.isspace() for char in url):
            raise PlanningInputError("Research source URL cannot contain whitespace")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme != "https" or not host or parts.username or parts.password or not any(
            host == allowed or host.endswith("." + allowed) for allowed in self.ALLOWED_HOSTS
        ):
            raise PlanningInputError("Research source URL must use HTTPS on an approved public-source domain")
        try:
            port = parts.port
        except ValueError as exc:
            raise PlanningInputError("Research source URL has an invalid port") from exc
        if port not in (None, 443):
            raise PlanningInputError("Research source URL must use the standard HTTPS port")
        if len(url) > 500:
            raise PlanningInputError("Research source URL exceeds 500 characters")
        disclosure_status = str(raw.get("disclosure_status", "")).strip().upper().replace("-", "_")
        if disclosure_status in {"DISCLOSED", "PUBLICLY_DISCLOSED"}:
            normalized_public_status = "PUBLICLY_DISCLOSED"
        elif disclosure_status in {"PUBLIC", "PUBLICLY_AVAILABLE", "OFFICIAL_REFERENCE"}:
            normalized_public_status = "PUBLICLY_AVAILABLE"
        else:
            raise PlanningInputError("Research records must explicitly confirm public availability; private or undisclosed material is rejected")
        safe_url = urlunsplit(("https", host, parts.path[:300], "", ""))
        title = _clean_text(raw.get("title", ""), 200)
        technique = _clean_text(raw.get("technique_summary", ""), 600)
        if not title or not technique:
            raise PlanningInputError("Research records require a title and concise technique_summary")
        author = _clean_text(raw.get("author", ""), 120)
        attribution = _clean_text(raw.get("source_attribution", ""), 160)
        if not author and not attribution:
            raise PlanningInputError("Research records require author or source attribution")
        technologies = _string_list(raw.get("technologies", []), 30)
        families = [_category(x) for x in _string_list(raw.get("vulnerability_families", []), 20)]
        families = [f for f in families if f in {row[0] for row in VULNERABILITY_FAMILIES}]
        report_id = "ARISE-" + _digest(safe_url)[:16]
        return {
            "report_id": report_id,
            "source_url": safe_url,
            "source_host": host,
            "disclosure_status": normalized_public_status,
            "title": title,
            "author": author,
            "published_at": _clean_text(raw.get("published_at", ""), 40),
            "technologies": technologies,
            "vulnerability_families": families,
            "technique_summary": technique,
            "source_attribution": attribution or author,
        }

    def _write(self, records: Sequence[Dict[str, Any]]) -> None:
        from framework.common.config import ensure_private_directory

        agent_data_dir = os.path.dirname(self.knowledge_dir)
        try:
            ensure_private_directory(agent_data_dir)
            ensure_private_directory(self.knowledge_dir)
        except Exception as exc:
            raise PlanningInputError(f"Cannot secure the Bug-Bounty agent knowledge directory: {exc}") from exc
        if os.path.islink(self.path):
            raise PlanningInputError("methodology.json must not be a symbolic link")
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile("w", dir=self.knowledge_dir, encoding="utf-8", delete=False) as stream:
                json.dump(list(records), stream, indent=2, sort_keys=True)
                temp_name = stream.name
            if os.name != "nt":
                os.chmod(temp_name, 0o600)
            os.replace(temp_name, self.path)
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)



def _methodology_matches(report: Dict[str, Any], category: str) -> bool:
    """Retrieve methodology across targets by vulnerability family, not target identity."""
    return category in report.get("vulnerability_families", [])


def _records(value: Any, filename: str) -> List[Dict[str, Any]]:
    if isinstance(value, dict):
        rows = value.values()
    elif isinstance(value, list):
        rows = value
    else:
        raise PlanningInputError(f"{filename} must contain an object or list")
    result = list(rows)
    if any(not isinstance(row, dict) for row in result):
        raise PlanningInputError(f"{filename} contains a malformed record")
    return [dict(row) for row in result]


def _asset_target(asset: Dict[str, Any]) -> str:
    return str(asset.get("hostname") or asset.get("normalized") or asset.get("value") or asset.get("url") or "").strip()


def _host(value: str) -> str:
    text = str(value or "").strip()
    if "://" in text:
        return (urlsplit(text).hostname or "").lower().rstrip(".")
    return text.split("/", 1)[0].split(":", 1)[0].lower().rstrip(".")


def _norm(value: Any) -> str:
    return _display_target(str(value or "")).lower().rstrip("/")


def _display_target(value: str) -> str:
    text = str(value or "").strip()
    if "://" not in text:
        return sanitize_sensitive_data(text)
    parts = urlsplit(text)
    host = parts.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parts.port
    except ValueError:
        port = None
    authority = f"{host}:{port}" if port else host
    clean = urlunsplit((parts.scheme.lower(), authority, parts.path, "", ""))
    return sanitize_sensitive_data(clean)


def _category(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")
    aliases = {"idor": "authorization", "bola": "authorization", "authz": "authorization",
               "auth": "authentication", "ssrf_testing": "ssrf", "xss": "javascript",
               "file_upload": "upload", "business_logic_testing": "business_logic"}
    return aliases.get(text, text)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clean_text(value: Any, limit: int) -> str:
    text = sanitize_sensitive_data(str(value or "")).strip()
    if len(text) > limit:
        raise PlanningInputError(f"Text field exceeds {limit} characters; store a concise summary, not report content")
    return text


def _string_list(value: Any, limit: int) -> List[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise PlanningInputError(f"Expected a list of at most {limit} text values")
    return sorted({_clean_text(v, 100) for v in value if str(v).strip()}, key=str.lower)


def _latest_test(tests: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return max(tests, key=lambda t: str(t.get("timestamp", "")), default=None)


def _source_state(host: str, checked: Sequence[str], unavailable: Sequence[str]) -> str:
    def matches(values: Sequence[str]) -> bool:
        return any(host == value or host.endswith("." + value) or value.endswith("." + host) for value in values)
    if matches(unavailable):
        return "UNAVAILABLE"
    if matches(checked):
        return "CHECKED"
    return "NOT_CHECKED"


def _source_domain(value: Any) -> str:
    token = _clean_text(value, 200).lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9.-]+", token) or token.startswith(".") or ".." in token:
        raise PlanningInputError("Source check identifiers must be DNS hostnames, not URLs")
    allowed = AriseResearchManager.ALLOWED_HOSTS
    if not any(token == base or token.endswith("." + base) for base in allowed):
        raise PlanningInputError("Source check hostname is outside the approved public-source domain list")
    return token


def _fresh(timestamp: Any, now: datetime) -> bool:
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age_days = (now - parsed.astimezone(timezone.utc)).total_seconds() / 86400
        return 0 <= age_days <= _TEST_FRESH_DAYS
    except (TypeError, ValueError):
        return False
