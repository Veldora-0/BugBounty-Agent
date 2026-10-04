"""
DOM XSS Intelligence & Source-to-Sink Analysis Engine for BugBounty-Agent.

Statically identifies untrusted DOM sources, dangerous sinks (including modern
framework APIs like React dangerouslySetInnerHTML, Vue v-html, Angular bypassSecurityTrustHtml,
and jQuery html/append), detects sanitizer usage (e.g. DOMPurify), and maps data flows.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from framework.xss.model import (
    XssCandidate,
    XssCategory,
    XssConfidence,
    XssEvidence,
    XssSink,
    XssSource,
)


# DOM Input Sources
DOM_SOURCE_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    ("location.search", "URL query parameters", re.compile(r"\b(?:window\.)?location\.search\b")),
    ("location.hash", "URL fragment identifier", re.compile(r"\b(?:window\.)?location\.hash\b")),
    ("location.href", "Full URL string", re.compile(r"\b(?:window\.)?location\.href\b")),
    ("location.pathname", "URL path component", re.compile(r"\b(?:window\.)?location\.pathname\b")),
    ("document.URL", "Document URL property", re.compile(r"\bdocument\.URL\b")),
    ("document.referrer", "HTTP Referrer header in DOM", re.compile(r"\bdocument\.referrer\b")),
    ("window.name", "Window name property", re.compile(r"\b(?:window\.)?name\b")),
    ("localStorage", "Web LocalStorage access", re.compile(r"\blocalStorage\.(?:getItem|[a-zA-Z0-9_]+)\b")),
    ("sessionStorage", "Web SessionStorage access", re.compile(r"\bsessionStorage\.(?:getItem|[a-zA-Z0-9_]+)\b")),
    ("document.cookie", "Document Cookie read", re.compile(r"\bdocument\.cookie\b")),
    ("postMessage_event", "Cross-origin message data", re.compile(r"\b(?:event|e)\.data\b")),
]

# DOM Execution & Markup Sinks
DOM_SINK_PATTERNS: List[Tuple[str, str, Optional[str], bool, re.Pattern]] = [
    # (name, sink_type, framework, is_framework_dangerous, regex)
    # Direct DOM
    ("innerHTML", "markup", None, False, re.compile(r"\.(?:innerHTML|outerHTML)\s*=")),
    ("document.write", "markup", None, False, re.compile(r"\bdocument\.writeln?\s*\(")),
    ("insertAdjacentHTML", "markup", None, False, re.compile(r"\.insertAdjacentHTML\s*\(")),

    # Code Execution
    ("eval", "execution", None, False, re.compile(r"\beval\s*\(")),
    ("setTimeout_string", "execution", None, False, re.compile(r"\bsetTimeout\s*\(\s*[\"']")),
    ("setInterval_string", "execution", None, False, re.compile(r"\bsetInterval\s*\(\s*[\"']")),
    ("Function_constructor", "execution", None, False, re.compile(r"\bnew\s+Function\s*\(")),

    # Script Element Injection
    ("script.src", "script_injection", None, False, re.compile(r"\b[a-zA-Z0-9_]*script[a-zA-Z0-9_]*\.src\s*=")),
    ("script.textContent", "script_injection", None, False, re.compile(r"\b[a-zA-Z0-9_]*script[a-zA-Z0-9_]*\.(?:text|textContent|innerText)\s*=")),

    # Navigation / Client-side Open Redirect / XSS
    ("location.assign", "navigation", None, False, re.compile(r"\b(?:window\.)?location\.(?:assign|replace)\s*\(")),
    ("location.href_set", "navigation", None, False, re.compile(r"\b(?:window\.)?location\.href\s*=")),

    # Modern Framework Dangerous APIs
    ("dangerouslySetInnerHTML", "markup", "React", True, re.compile(r"\bdangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:")),
    ("v-html", "markup", "Vue", True, re.compile(r"""\bv-html\s*=\s*["'][^"']+["']""")),
    ("bypassSecurityTrustHtml", "markup", "Angular", True, re.compile(r"\bbypassSecurityTrustHtml\s*\(")),
    ("bypassSecurityTrustScript", "execution", "Angular", True, re.compile(r"\bbypassSecurityTrustScript\s*\(")),

    # jQuery Sinks
    ("jquery_html", "markup", "jQuery", True, re.compile(r"\$\([^)]+\)\.html\s*\(")),
    ("jquery_append", "markup", "jQuery", True, re.compile(r"\$\([^)]+\)\.(?:append|prepend|after|before|wrap)\s*\(")),
]

# Client-Side Sanitization Signatures
SANITIZER_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("DOMPurify", re.compile(r"\bDOMPurify\.sanitize\b", re.IGNORECASE)),
    ("sanitizeHtml", re.compile(r"\bsanitizeHtml\b", re.IGNORECASE)),
    ("xssFilters", re.compile(r"\bxssFilters\b", re.IGNORECASE)),
    ("encodeURIComponent", re.compile(r"\bencodeURIComponent\b")),
    ("escapeHTML", re.compile(r"\b(?:escapeHtml|escapeHTML|he\.encode)\b", re.IGNORECASE)),
]


class DomXssEngine:
    """
    Analyzes JavaScript codebases and intelligence states to identify DOM XSS
    candidates, source-to-sink pathways, and framework-specific dangerous patterns.
    """

    @classmethod
    def analyze_script_text(
        cls,
        script_content: str,
        file_path: str = "inline",
        target_asset: str = "",
        endpoint: str = "",
    ) -> List[XssCandidate]:
        """
        Statically scans script content for sources, sinks, sanitizers,
        and constructs correlated XssCandidate records.
        """
        if not script_content or len(script_content.strip()) == 0:
            return []

        lines = script_content.splitlines()

        # 1. Identify sources
        sources_found: List[XssSource] = []
        for line_idx, line in enumerate(lines, 1):
            if len(line) > 1000:  # Skip huge minified lines for regex speed, sample start
                sample = line[:1000]
            else:
                sample = line

            for src_name, desc, pat in DOM_SOURCE_PATTERNS:
                if pat.search(sample):
                    sources_found.append(
                        XssSource(
                            source_type="dom_source",
                            name=src_name,
                            file_path=file_path,
                            line_number=line_idx,
                            snippet=line.strip()[:150],
                            details={"description": desc},
                        )
                    )

        # 2. Identify sinks
        sinks_found: List[XssSink] = []
        for line_idx, line in enumerate(lines, 1):
            sample = line[:1000] if len(line) > 1000 else line
            for sink_name, sink_type, framework, is_dangerous, pat in DOM_SINK_PATTERNS:
                if pat.search(sample):
                    sinks_found.append(
                        XssSink(
                            sink_type=sink_type,
                            name=sink_name,
                            framework=framework,
                            file_path=file_path,
                            line_number=line_idx,
                            snippet=line.strip()[:150],
                            is_framework_dangerous=is_dangerous,
                            details={},
                        )
                    )

        # 3. Check for sanitizers
        sanitizers_found: List[str] = []
        for s_name, s_pat in SANITIZER_PATTERNS:
            if s_pat.search(script_content):
                sanitizers_found.append(s_name)

        has_sanitizer = len(sanitizers_found) > 0

        # 4. Synthesize Candidates
        candidates: List[XssCandidate] = []

        # Case A: Correlated Source & Sink in same script file/context
        if sources_found and sinks_found:
            for sink in sinks_found:
                # Find closest or matching source
                matched_source = sources_found[0]
                for src in sources_found:
                    if src.line_number and sink.line_number:
                        if abs(src.line_number - sink.line_number) < abs(matched_source.line_number - sink.line_number):
                            matched_source = src

                # Taint path heuristic
                is_direct_flow = cls._check_direct_flow(script_content, matched_source.name, sink.name)

                if has_sanitizer:
                    conf = XssConfidence.REJECTED
                    state = "FILTERED"
                    sev = "INFORMATIONAL"
                    lifecycle = "REJECTED"
                    notes = f"DOM source {matched_source.name} and sink {sink.name} detected, but sanitized via {', '.join(sanitizers_found)}."
                elif is_direct_flow:
                    conf = XssConfidence.SUSPECTED
                    state = "UNFILTERED"
                    sev = "HIGH" if sink.is_framework_dangerous or sink.sink_type in ("execution", "markup") else "MEDIUM"
                    lifecycle = "OBSERVED"
                    notes = f"Direct or proximate data flow detected from DOM source '{matched_source.name}' to sink '{sink.name}' without sanitization."
                else:
                    conf = XssConfidence.SUSPECTED
                    state = "UNFILTERED"
                    sev = "MEDIUM"
                    lifecycle = "OBSERVED"
                    notes = f"DOM source '{matched_source.name}' and sink '{sink.name}' co-occur in the same script without verified sanitization."

                cand = XssCandidate(
                    category=XssCategory.DOM,
                    target_asset=target_asset,
                    endpoint=endpoint or file_path,
                    parameter=matched_source.name,
                    confidence=conf,
                    lifecycle_state=lifecycle,
                    severity=sev,
                    source=matched_source,
                    sink=sink,
                    evidence=XssEvidence(
                        canary_token=f"dom_trace_{sink.name}",
                        context_snippet=sink.snippet or "",
                        transformations_observed={"sanitizers": ",".join(sanitizers_found) if sanitizers_found else "none"},
                    ),
                    notes=notes,
                )
                candidates.append(cand)

        # Case B: Dangerous framework sink without explicit source (e.g. dangerouslySetInnerHTML or v-html)
        elif sinks_found:
            for sink in sinks_found:
                if sink.is_framework_dangerous:
                    cand = XssCandidate(
                        category=XssCategory.DOM,
                        target_asset=target_asset,
                        endpoint=endpoint or file_path,
                        parameter=None,
                        confidence=XssConfidence.OBSERVED,
                        lifecycle_state="OBSERVED",
                        severity="LOW",
                        source=None,
                        sink=sink,
                        evidence=XssEvidence(
                            canary_token=f"sink_{sink.name}",
                            context_snippet=sink.snippet or "",
                        ),
                        notes=f"Framework dangerous sink '{sink.name}' ({sink.framework or 'generic'}) observed in frontend code.",
                    )
                    candidates.append(cand)

        return candidates

    @classmethod
    def _check_direct_flow(cls, code: str, source_name: str, sink_name: str) -> bool:
        """
        Heuristic check for direct flow: e.g.
        element.innerHTML = location.hash;
        eval(location.search);
        var q = location.search; ... element.innerHTML = q;
        """
        # Exact one-line assignment: sink = ... source
        escaped_src = re.escape(source_name)
        if re.search(rf"\.(?:innerHTML|outerHTML)\s*=\s*[^;\n]*{escaped_src}", code):
            return True
        if re.search(rf"\b(?:document\.write|eval)\s*\(\s*[^;\n]*{escaped_src}", code):
            return True
        if re.search(rf"\bdangerouslySetInnerHTML\s*=\s*\{{[^}}]*{escaped_src}", code):
            return True
        return False

    @classmethod
    def analyze_javascript_intelligence(
        cls,
        js_state_dict: Dict[str, Any],
        target_asset: str = "",
    ) -> List[XssCandidate]:
        """
        Consumes Phase 4 javascript.json state and evaluates discovered endpoints,
        routes, and scripts for DOM XSS vulnerability patterns.
        """
        candidates: List[XssCandidate] = []
        # Scripts or endpoints in state
        scripts = js_state_dict.get("scripts", [])
        for script_info in scripts:
            content = script_info.get("content") or script_info.get("raw_text") or ""
            url = script_info.get("url") or script_info.get("file_path") or ""
            if content:
                found = cls.analyze_script_text(
                    script_content=content,
                    file_path=url,
                    target_asset=target_asset,
                    endpoint=url,
                )
                candidates.extend(found)

        return candidates
