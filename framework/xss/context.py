"""
HTML Context & Transformation Analyzer for BugBounty-Agent XSS Engine.

Performs fine-grained, stateful lexical analysis of HTTP responses to determine
the precise execution context of reflected input and verify whether contextual
neutralization (HTML entity, URL, or JavaScript escaping) was applied.
"""

from __future__ import annotations

import html
from html.parser import HTMLParser
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from framework.xss.model import ReflectionState, XssContextType


# Patterns for encoding detection
ENTITY_PATTERNS = {
    "<": [re.compile(r"&lt;", re.IGNORECASE), re.compile(r"&#60;"), re.compile(r"&#x3c;", re.IGNORECASE)],
    ">": [re.compile(r"&gt;", re.IGNORECASE), re.compile(r"&#62;"), re.compile(r"&#x3e;", re.IGNORECASE)],
    '"': [re.compile(r"&quot;", re.IGNORECASE), re.compile(r"&#34;"), re.compile(r"&#x22;", re.IGNORECASE)],
    "'": [re.compile(r"&#39;"), re.compile(r"&#x27;", re.IGNORECASE), re.compile(r"&apos;", re.IGNORECASE)],
    "&": [re.compile(r"&amp;", re.IGNORECASE), re.compile(r"&#38;"), re.compile(r"&#x26;", re.IGNORECASE)],
}

URL_ENCODED_PATTERNS = {
    "<": [re.compile(r"%3c", re.IGNORECASE)],
    ">": [re.compile(r"%3e", re.IGNORECASE)],
    '"': [re.compile(r"%22", re.IGNORECASE)],
    "'": [re.compile(r"%27", re.IGNORECASE)],
    "&": [re.compile(r"%26", re.IGNORECASE)],
}

JS_ESCAPED_PATTERNS = {
    '"': [re.compile(r'\\"'), re.compile(r"\\u0022", re.IGNORECASE), re.compile(r"\\x22", re.IGNORECASE)],
    "'": [re.compile(r"\\'"), re.compile(r"\\u0027", re.IGNORECASE), re.compile(r"\\x27", re.IGNORECASE)],
    "<": [re.compile(r"\\u003c", re.IGNORECASE), re.compile(r"\\x3c", re.IGNORECASE)],
    ">": [re.compile(r"\\u003e", re.IGNORECASE), re.compile(r"\\x3e", re.IGNORECASE)],
}

EVENT_HANDLER_NAMES = {
    "onload", "onerror", "onclick", "onmouseover", "onfocus", "onblur",
    "onchange", "onsubmit", "onkeydown", "onkeyup", "onkeypress", "onloadstart",
    "onmouseenter", "onmouseleave", "onpointerdown", "onpointerup", "ontoggle",
}

URL_ATTRIBUTE_NAMES = {
    "href", "src", "action", "formaction", "data", "poster", "cite",
}


class ContextAnalysisResult:
    """Detailed outcome of context and transformation analysis."""

    def __init__(
        self,
        canary_reflected: bool = False,
        context_type: XssContextType = XssContextType.UNKNOWN,
        reflection_state: ReflectionState = ReflectionState.ABSENT,
        context_snippet: str = "",
        tag_name: Optional[str] = None,
        attribute_name: Optional[str] = None,
        quote_style: Optional[str] = None,  # '"', "'", or None (unquoted)
        is_defended: bool = False,
        is_exploitable_context: bool = False,
        transformations: Optional[Dict[str, str]] = None,
    ):
        self.canary_reflected = canary_reflected
        self.context_type = context_type
        self.reflection_state = reflection_state
        self.context_snippet = context_snippet
        self.tag_name = tag_name
        self.attribute_name = attribute_name
        self.quote_style = quote_style
        self.is_defended = is_defended
        self.is_exploitable_context = is_exploitable_context
        self.transformations = transformations or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_reflected": self.canary_reflected,
            "context_type": self.context_type.value,
            "reflection_state": self.reflection_state.value,
            "context_snippet": self.context_snippet,
            "tag_name": self.tag_name,
            "attribute_name": self.attribute_name,
            "quote_style": self.quote_style,
            "is_defended": self.is_defended,
            "is_exploitable_context": self.is_exploitable_context,
            "transformations": self.transformations,
        }


class HtmlContextAnalyzer:
    """
    Stateful analyzer determining the HTML/JS/JSON context of reflected inputs
    and checking contextual defenses.
    """

    @classmethod
    def analyze(
        cls,
        response_body: str,
        canary_token: str,
        content_type: str = "text/html",
        probe_chars: str = "\"'<>",
    ) -> ContextAnalysisResult:
        """
        Analyzes the response body to locate the canary token and classify its context.
        """
        if not response_body or not canary_token:
            return ContextAnalysisResult(
                canary_reflected=False,
                reflection_state=ReflectionState.ABSENT,
            )

        # 1. Check for JSON context if content-type or structure is JSON
        if "application/json" in content_type.lower() or (
            response_body.strip().startswith(("{", "[")) and response_body.strip().endswith(("}", "]"))
        ):
            json_res = cls._check_json_context(response_body, canary_token)
            if json_res:
                return json_res

        # 2. Check for exact canary occurrence in raw body
        idx = response_body.find(canary_token)
        if idx == -1:
            # Check if canary token itself was transformed (e.g. entity encoded or URL encoded)
            encoded_res = cls._check_encoded_canary(response_body, canary_token)
            if encoded_res:
                return encoded_res
            return ContextAnalysisResult(
                canary_reflected=False,
                reflection_state=ReflectionState.ABSENT,
            )

        # Snippet window
        snippet_start = max(0, idx - 40)
        snippet_end = min(len(response_body), idx + len(canary_token) + 40)
        snippet = response_body[snippet_start:snippet_end]

        # 3. Analyze surrounding HTML syntax using stateful lexical scan
        ctx_type, tag_name, attr_name, quote_style = cls._classify_html_context(response_body, idx)

        # 4. Analyze character transformations for probe characters
        transformations = cls._detect_transformations(response_body, canary_token, probe_chars)

        # 5. Evaluate defensive neutralization vs exploitability
        reflection_state, is_defended, is_exploitable = cls._evaluate_defense_state(
            ctx_type, quote_style, transformations, response_body, idx, canary_token
        )

        return ContextAnalysisResult(
            canary_reflected=True,
            context_type=ctx_type,
            reflection_state=reflection_state,
            context_snippet=snippet,
            tag_name=tag_name,
            attribute_name=attr_name,
            quote_style=quote_style,
            is_defended=is_defended,
            is_exploitable_context=is_exploitable,
            transformations=transformations,
        )

    @classmethod
    def _check_json_context(cls, body: str, canary: str) -> Optional[ContextAnalysisResult]:
        """Checks if body is valid JSON containing the canary token."""
        try:
            parsed = json.loads(body)
            # Find in serialized or raw
            if canary in body:
                idx = body.find(canary)
                snippet = body[max(0, idx - 30):min(len(body), idx + len(canary) + 30)]
                return ContextAnalysisResult(
                    canary_reflected=True,
                    context_type=XssContextType.JSON_STRING,
                    reflection_state=ReflectionState.ENCODED,
                    context_snippet=snippet,
                    is_defended=True,
                    is_exploitable_context=False,
                )
        except Exception:
            pass
        return None

    @classmethod
    def _check_encoded_canary(cls, body: str, canary: str) -> Optional[ContextAnalysisResult]:
        """Checks if the canary was encoded with HTML entities."""
        entity_encoded = html.escape(canary)
        if entity_encoded != canary and entity_encoded in body:
            idx = body.find(entity_encoded)
            snippet = body[max(0, idx - 30):min(len(body), idx + len(entity_encoded) + 30)]
            return ContextAnalysisResult(
                canary_reflected=True,
                context_type=XssContextType.HTML_BODY,
                reflection_state=ReflectionState.ENCODED,
                context_snippet=snippet,
                is_defended=True,
                is_exploitable_context=False,
                transformations={"all": "html_entity_encoded"},
            )
        return None

    @classmethod
    def _classify_html_context(
        cls, body: str, canary_idx: int
    ) -> Tuple[XssContextType, Optional[str], Optional[str], Optional[str]]:
        """
        Classifies the syntactic context of canary_idx within body.
        Returns (XssContextType, tag_name, attribute_name, quote_style).
        """
        prefix = body[:canary_idx]

        # 1. HTML Comment: <!-- ... canary ... -->
        last_comment_open = prefix.rfind("<!--")
        last_comment_close = prefix.rfind("-->")
        if last_comment_open > last_comment_close:
            return XssContextType.HTML_COMMENT, None, None, None

        # 2. Inside <script> ... canary ... </script>
        script_open = [m.start() for m in re.finditer(r"<script\b", prefix, re.IGNORECASE)]
        script_close = [m.start() for m in re.finditer(r"</script>", prefix, re.IGNORECASE)]
        if script_open and (not script_close or max(script_open) > max(script_close)):
            return XssContextType.SCRIPT_BLOCK, "script", None, None

        # 3. Inside <style> ... canary ... </style>
        style_open = [m.start() for m in re.finditer(r"<style\b", prefix, re.IGNORECASE)]
        style_close = [m.start() for m in re.finditer(r"</style>", prefix, re.IGNORECASE)]
        if style_open and (not style_close or max(style_open) > max(style_close)):
            return XssContextType.STYLE_BLOCK, "style", None, None

        # 4. Check if inside an HTML tag: <tag ... canary ... >
        last_tag_open = prefix.rfind("<")
        last_tag_close = prefix.rfind(">")

        if last_tag_open > last_tag_close:
            # We are inside an unclosed HTML tag!
            tag_slice = prefix[last_tag_open + 1:]
            tag_match = re.match(r"^([a-zA-Z0-9_-]+)", tag_slice)
            tag_name = tag_match.group(1).lower() if tag_match else "unknown"

            rest = tag_slice[len(tag_name):]
            current_attr = None
            current_quote = None
            i = 0
            while i < len(rest):
                while i < len(rest) and rest[i].isspace():
                    i += 1
                if i >= len(rest):
                    break
                name_match = re.match(r"^([a-zA-Z0-9_:-]+)", rest[i:])
                if not name_match:
                    i += 1
                    continue
                attr_candidate = name_match.group(1).lower()
                i += len(name_match.group(0))
                while i < len(rest) and rest[i].isspace():
                    i += 1
                if i < len(rest) and rest[i] == "=":
                    i += 1
                    while i < len(rest) and rest[i].isspace():
                        i += 1
                    if i < len(rest) and rest[i] in ('"', "'"):
                        q = rest[i]
                        i += 1
                        val_start = i
                        close_q = rest.find(q, val_start)
                        if close_q == -1:
                            current_attr = attr_candidate
                            current_quote = q
                            break
                        else:
                            i = close_q + 1
                    else:
                        val_start = i
                        while i < len(rest) and not rest[i].isspace():
                            i += 1
                        if i >= len(rest):
                            current_attr = attr_candidate
                            current_quote = None
                else:
                    current_attr = attr_candidate
                    current_quote = None

            if current_attr:
                if current_attr in EVENT_HANDLER_NAMES or current_attr.startswith("on"):
                    return XssContextType.EVENT_HANDLER, tag_name, current_attr, current_quote
                elif current_attr in URL_ATTRIBUTE_NAMES:
                    return XssContextType.URL_ATTRIBUTE, tag_name, current_attr, current_quote
                else:
                    return XssContextType.HTML_ATTRIBUTE, tag_name, current_attr, current_quote

            return XssContextType.HTML_ATTRIBUTE_NAME, tag_name, None, None

        # 5. Default to HTML Body Text
        return XssContextType.HTML_BODY, None, None, None

    @classmethod
    def _detect_transformations(cls, body: str, canary: str, probe_chars: str) -> Dict[str, str]:
        """Detects if probe characters around canary experienced transformations."""
        transformations: Dict[str, str] = {}
        idx = body.find(canary)
        if idx == -1:
            return transformations

        # Examine adjacent text (10 chars after canary)
        post_window = body[idx + len(canary):idx + len(canary) + 20]

        for char in probe_chars:
            # Check HTML entity encoding
            for ent_pat in ENTITY_PATTERNS.get(char, []):
                if ent_pat.search(post_window):
                    transformations[char] = "html_entity"
                    break

            # Check URL encoding
            if char not in transformations:
                for url_pat in URL_ENCODED_PATTERNS.get(char, []):
                    if url_pat.search(post_window):
                        transformations[char] = "url_encoded"
                        break

            # Check JS escaping
            if char not in transformations:
                for js_pat in JS_ESCAPED_PATTERNS.get(char, []):
                    if js_pat.search(post_window):
                        transformations[char] = "js_escaped"
                        break

            # Check verbatim presence
            if char not in transformations and char in post_window:
                transformations[char] = "unfiltered"

        return transformations

    @classmethod
    def _evaluate_defense_state(
        cls,
        ctx_type: XssContextType,
        quote_style: Optional[str],
        transformations: Dict[str, str],
        body: str,
        canary_idx: int,
        canary: str,
    ) -> Tuple[ReflectionState, bool, bool]:
        """
        Evaluates whether reflection is defended, unencoded, or exploitable.
        Returns (ReflectionState, is_defended, is_exploitable).
        """
        # Case 1: HTML_BODY
        if ctx_type == XssContextType.HTML_BODY:
            has_lt = transformations.get("<") == "unfiltered"
            has_gt = transformations.get(">") == "unfiltered"
            ent_lt = transformations.get("<") == "html_entity"
            ent_gt = transformations.get(">") == "html_entity"

            if ent_lt or ent_gt:
                # Properly defended by entity encoding!
                return ReflectionState.ENCODED, True, False
            if has_lt and has_gt:
                # Unfiltered markup delimiters in body
                return ReflectionState.UNFILTERED, False, True
            return ReflectionState.UNFILTERED, False, False

        # Case 2: HTML_ATTRIBUTE
        if ctx_type == XssContextType.HTML_ATTRIBUTE:
            target_quote = quote_style or '"'
            quote_trans = transformations.get(target_quote)

            if quote_trans in ("html_entity", "js_escaped"):
                # Quote delimiter escaped, cannot break attribute
                return ReflectionState.ENCODED, True, False
            elif quote_trans == "unfiltered":
                # Raw quote allowed break-out
                return ReflectionState.UNFILTERED, False, True
            elif quote_style is None:
                # Unquoted attribute: spaces or '>' break out
                return ReflectionState.UNFILTERED, False, True
            return ReflectionState.UNFILTERED, False, False

        # Case 3: SCRIPT_BLOCK
        if ctx_type == XssContextType.SCRIPT_BLOCK:
            # In script block, HTML entity encoding (&quot;) DOES NOT protect JavaScript execution
            # JS escaping (\' or \") is required.
            quote_trans = transformations.get('"') or transformations.get("'")
            if quote_trans == "html_entity":
                return ReflectionState.INSUFFICIENTLY_ENCODED, False, True
            elif quote_trans == "js_escaped":
                return ReflectionState.ENCODED, True, False
            elif quote_trans == "unfiltered":
                return ReflectionState.UNFILTERED, False, True
            return ReflectionState.UNFILTERED, False, True

        # Case 4: EVENT_HANDLER
        if ctx_type == XssContextType.EVENT_HANDLER:
            quote_trans = transformations.get('"') or transformations.get("'")
            if quote_trans == "unfiltered":
                return ReflectionState.UNFILTERED, False, True
            elif quote_trans in ("html_entity", "js_escaped"):
                return ReflectionState.ENCODED, True, False
            return ReflectionState.UNFILTERED, False, True

        # Case 5: URL_ATTRIBUTE
        if ctx_type == XssContextType.URL_ATTRIBUTE:
            # Check if canary begins with javascript: or data:
            prefix = body[max(0, canary_idx - 15):canary_idx].lower()
            if "javascript:" in prefix or "javascript:" in canary.lower():
                return ReflectionState.UNFILTERED, False, True
            return ReflectionState.UNFILTERED, False, False

        # Case 6: HTML_COMMENT
        if ctx_type == XssContextType.HTML_COMMENT:
            if "--" in canary or "-->" in body[canary_idx:canary_idx + len(canary) + 5]:
                return ReflectionState.UNFILTERED, False, True
            return ReflectionState.ENCODED, True, False

        return ReflectionState.UNFILTERED, False, False
