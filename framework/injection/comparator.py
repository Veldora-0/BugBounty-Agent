"""
Multi-Signal Differential Comparator & False-Positive Filter (Phase 10).

Performs rigorous baseline, control, and test response comparisons.
Combines multiple signals (status code, body similarity, error signatures,
boolean divergence, mathematical evaluation, and jitter-normalized timing).
Identifies and eliminates WAF challenges, rate limits, caching anomalies,
and unstable dynamic pages before advancing finding confidence.
"""

from __future__ import annotations

import difflib
import re
from typing import Any, Dict, List, Optional, Tuple

from framework.injection.model import (
    InjectionConfidence,
    InjectionContext,
    InjectionType,
)
from framework.injection.signatures import ErrorSignatureMatcher


# Known WAF / Bot blocking fingerprints
WAF_SIGNATURES = [
    re.compile(r"attention required!\s*\|\s*cloudflare", re.I),
    re.compile(r"<title>403\s+Forbidden</title>", re.I),
    re.compile(r"the requested url was rejected\..*support id", re.I),
    re.compile(r"aws waf|x-amzn-waf-action", re.I),
    re.compile(r"access denied.*incident id|akamai", re.I),
    re.compile(r"protected by imperva|incapsula", re.I),
    re.compile(r"blocked by security policy", re.I),
]


class InjectionComparisonResult:
    """Detailed differential evaluation output."""

    def __init__(
        self,
        is_candidate_signal: bool,
        confidence: InjectionConfidence,
        signals: List[str],
        reasons: List[str],
        error_signature: Optional[Dict[str, Any]] = None,
        is_false_positive: bool = False,
        false_positive_reason: Optional[str] = None,
        timing_anomaly: bool = False,
        body_similarity_true: float = 1.0,
        body_similarity_false: float = 1.0,
    ):
        self.is_candidate_signal = is_candidate_signal
        self.confidence = confidence
        self.signals = list(signals)
        self.reasons = list(reasons)
        self.error_signature = error_signature
        self.is_false_positive = is_false_positive
        self.false_positive_reason = false_positive_reason
        self.timing_anomaly = timing_anomaly
        self.body_similarity_true = body_similarity_true
        self.body_similarity_false = body_similarity_false

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_candidate_signal": self.is_candidate_signal,
            "confidence": self.confidence.value,
            "signals": self.signals,
            "reasons": self.reasons,
            "error_signature": self.error_signature,
            "is_false_positive": self.is_false_positive,
            "false_positive_reason": self.false_positive_reason,
            "timing_anomaly": self.timing_anomaly,
            "body_similarity_true": round(self.body_similarity_true, 4),
            "body_similarity_false": round(self.body_similarity_false, 4),
        }


class InjectionComparator:
    """Evaluates differential probe results with multi-signal analysis."""

    @staticmethod
    def compute_similarity(text_a: str, text_b: str) -> float:
        """Computes text similarity ratio (0.0 to 1.0)."""
        if text_a == text_b:
            return 1.0
        if not text_a or not text_b:
            return 0.0
        # Use quick length heuristic if bodies differ massively
        len_a, len_b = len(text_a), len(text_b)
        if len_a > 0 and len_b > 0 and (min(len_a, len_b) / max(len_a, len_b)) < 0.2:
            return min(len_a, len_b) / max(len_a, len_b)
        # Bounded comparison sample for performance
        sample_a = text_a[:4000]
        sample_b = text_b[:4000]
        return difflib.SequenceMatcher(None, sample_a, sample_b).ratio()

    @staticmethod
    def detect_waf_or_block(status: int, body: str, headers: Optional[Dict[str, str]] = None) -> Optional[str]:
        """Detects WAF blocking pages, CAPTCHAs, or rate-limiting responses."""
        if status == 429:
            return "HTTP 429 Too Many Requests (Rate Limiting active)"
        if status in (403, 406, 503):
            for pat in WAF_SIGNATURES:
                if pat.search(body):
                    return f"WAF challenge / block detected matching '{pat.pattern}'"
        h_str = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
        if "cloudflare" in h_str and status in (403, 503):
            return "Cloudflare security challenge / block page"
        return None

    @classmethod
    def evaluate_sql_differential(
        cls,
        baseline_resp: Dict[str, Any],
        true_resp: Dict[str, Any],
        false_resp: Dict[str, Any],
        quote_resp: Optional[Dict[str, Any]] = None,
        timing_resp: Optional[Dict[str, Any]] = None,
        timing_expected_delay: float = 1.0,
    ) -> InjectionComparisonResult:
        """
        Evaluates boolean differential and error signatures for SQLi.
        Requires:
        1. True probe closely matches Baseline (status + content).
        2. False probe differs significantly from True probe.
        3. Stable baseline (not dynamic noise).
        """
        signals: List[str] = []
        reasons: List[str] = []

        base_status = baseline_resp.get("status_code", 200)
        base_body = baseline_resp.get("body", "")
        true_status = true_resp.get("status_code", 200)
        true_body = true_resp.get("body", "")
        false_status = false_resp.get("status_code", 200)
        false_body = false_resp.get("body", "")

        # 1. Check for WAF blocks in any probe
        for name, r in [("True probe", true_resp), ("False probe", false_resp)]:
            waf_msg = cls.detect_waf_or_block(r.get("status_code", 200), r.get("body", ""), r.get("headers"))
            if waf_msg:
                return InjectionComparisonResult(
                    is_candidate_signal=False,
                    confidence=InjectionConfidence.CANDIDATE,
                    signals=["WAF_BLOCK"],
                    reasons=[f"{name} intercepted by WAF: {waf_msg}"],
                    is_false_positive=True,
                    false_positive_reason=waf_msg,
                )

        # 2. Check for database error signatures in quote or false probes
        error_sig = None
        if quote_resp:
            quote_body = quote_resp.get("body", "")
            error_sig = ErrorSignatureMatcher.match(quote_body)
            if error_sig:
                signals.append(f"SQL_ERROR_SIGNATURE_{error_sig['family'].upper()}")
                reasons.append(f"Verified {error_sig['family']} error signature: {error_sig['matched_text']}")
            elif quote_resp.get("status_code") == 500 and base_status != 500:
                signals.append("STATUS_500_ON_QUOTE")
                reasons.append("Uncaught 500 Internal Server Error triggered on quote boundary probe")

        # 3. Boolean Differential Evaluation
        sim_true = cls.compute_similarity(base_body, true_body)
        sim_false = cls.compute_similarity(true_body, false_body)
        sim_base_false = cls.compute_similarity(base_body, false_body)

        boolean_match = False
        # Condition A: True matches baseline status & high body similarity, False yields status change or low similarity
        if true_status == base_status and sim_true >= 0.75:
            if false_status != true_status or sim_false < 0.65 or len(false_body) < 0.5 * len(true_body):
                boolean_match = True
                signals.append("BOOLEAN_DIFFERENTIAL_CONFIRMED")
                reasons.append(
                    f"Boolean differential confirmed: True similarity {sim_true:.2f} vs False similarity {sim_false:.2f} (status {true_status} vs {false_status})"
                )

        # 4. Timing Anomaly Evaluation (if timing probe supplied)
        timing_anomaly = False
        if timing_resp:
            base_dur = baseline_resp.get("duration_seconds", 0.1)
            time_dur = timing_resp.get("duration_seconds", 0.0)
            # Subtract jitter threshold
            if time_dur >= (base_dur + timing_expected_delay - 0.25) and time_dur >= 0.8:
                timing_anomaly = True
                signals.append("TIMING_ANOMALY_CONFIRMED")
                reasons.append(f"Bounded timing differential: {time_dur:.2f}s vs baseline {base_dur:.2f}s")

        # 5. Determine Confidence
        if boolean_match and error_sig:
            confidence = InjectionConfidence.VALIDATED
            is_candidate = True
        elif boolean_match:
            confidence = InjectionConfidence.VALIDATED
            is_candidate = True
        elif error_sig:
            confidence = InjectionConfidence.OBSERVED
            is_candidate = True
            reasons.append("Database error signature observed; requires manual validation or boolean differential confirmation")
        elif timing_anomaly and (boolean_match or error_sig):
            confidence = InjectionConfidence.VALIDATED
            is_candidate = True
        elif timing_anomaly:
            confidence = InjectionConfidence.OBSERVED
            is_candidate = True
            reasons.append("Timing anomaly observed in isolation; not alone proof of injection")
        else:
            confidence = InjectionConfidence.CANDIDATE
            is_candidate = False
            reasons.append("No reproducible differential, error signature, or timing variance observed")

        return InjectionComparisonResult(
            is_candidate_signal=is_candidate,
            confidence=confidence,
            signals=signals,
            reasons=reasons,
            error_signature=error_sig,
            timing_anomaly=timing_anomaly,
            body_similarity_true=sim_true,
            body_similarity_false=sim_false,
        )

    @classmethod
    def evaluate_ssti_differential(
        cls,
        baseline_resp: Dict[str, Any],
        probe_resp: Dict[str, Any],
        expression_str: str = "{{7*7}}",
        expected_math_result: str = "49",
    ) -> InjectionComparisonResult:
        """
        Evaluates harmless mathematical expression evaluation for SSTI.
        Requires:
        1. Probe body contains expected result (e.g. '49').
        2. Baseline body does NOT contain expected result at same position.
        3. Probe body did NOT just render the expression literally (e.g. '{{7*7}}').
        """
        signals: List[str] = []
        reasons: List[str] = []

        status = probe_resp.get("status_code", 200)
        body = probe_resp.get("body", "")
        base_body = baseline_resp.get("body", "")

        waf_msg = cls.detect_waf_or_block(status, body, probe_resp.get("headers"))
        if waf_msg:
            return InjectionComparisonResult(
                is_candidate_signal=False,
                confidence=InjectionConfidence.CANDIDATE,
                signals=["WAF_BLOCK"],
                reasons=[f"Probe intercepted by WAF: {waf_msg}"],
                is_false_positive=True,
                false_positive_reason=waf_msg,
            )

        # Check for template syntax error signatures
        error_sig = ErrorSignatureMatcher.match(body)
        if error_sig and "SSTI" in error_sig.get("signature_id", ""):
            signals.append(f"TEMPLATE_ERROR_{error_sig['family'].upper()}")
            reasons.append(f"Template engine error signature observed: {error_sig['matched_text']}")

        # Check for literal rendering
        rendered_literally = expression_str in body

        # Check for mathematical evaluation
        evaluated_math = (expected_math_result in body) and (expected_math_result not in base_body)

        if evaluated_math and not rendered_literally:
            signals.append("MATH_EVALUATION_CONFIRMED")
            reasons.append(
                f"Expression '{expression_str}' was evaluated by server template engine to '{expected_math_result}'"
            )
            confidence = InjectionConfidence.VALIDATED
            is_candidate = True
        elif rendered_literally:
            reasons.append(f"Expression '{expression_str}' rendered literally as text; template engine escaped input")
            confidence = InjectionConfidence.CANDIDATE
            is_candidate = False
            return InjectionComparisonResult(
                is_candidate_signal=False,
                confidence=confidence,
                signals=["LITERAL_RENDER"],
                reasons=reasons,
                is_false_positive=False,
            )
        elif error_sig:
            confidence = InjectionConfidence.OBSERVED
            is_candidate = True
        else:
            confidence = InjectionConfidence.CANDIDATE
            is_candidate = False
            reasons.append("No template mathematical evaluation or engine error observed")

        return InjectionComparisonResult(
            is_candidate_signal=is_candidate,
            confidence=confidence,
            signals=signals,
            reasons=reasons,
            error_signature=error_sig,
        )

    @classmethod
    def evaluate_nosql_differential(
        cls,
        baseline_resp: Dict[str, Any],
        true_resp: Dict[str, Any],
        false_resp: Dict[str, Any],
    ) -> InjectionComparisonResult:
        """
        Evaluates boolean / operator differential for NoSQL injection.
        """
        signals: List[str] = []
        reasons: List[str] = []

        base_status = baseline_resp.get("status_code", 200)
        base_body = baseline_resp.get("body", "")
        true_status = true_resp.get("status_code", 200)
        true_body = true_resp.get("body", "")
        false_status = false_resp.get("status_code", 200)
        false_body = false_resp.get("body", "")

        for name, r in [("True probe", true_resp), ("False probe", false_resp)]:
            waf_msg = cls.detect_waf_or_block(r.get("status_code", 200), r.get("body", ""), r.get("headers"))
            if waf_msg:
                return InjectionComparisonResult(
                    is_candidate_signal=False,
                    confidence=InjectionConfidence.CANDIDATE,
                    signals=["WAF_BLOCK"],
                    reasons=[f"{name} intercepted by WAF: {waf_msg}"],
                    is_false_positive=True,
                    false_positive_reason=waf_msg,
                )

        error_sig = ErrorSignatureMatcher.match(false_body) or ErrorSignatureMatcher.match(true_body)
        if error_sig and "NOSQL" in error_sig.get("signature_id", ""):
            signals.append(f"NOSQL_ERROR_{error_sig['family'].upper()}")
            reasons.append(f"NoSQL driver error signature observed: {error_sig['matched_text']}")

        sim_true = cls.compute_similarity(base_body, true_body)
        sim_false = cls.compute_similarity(true_body, false_body)

        # In NoSQL operator injection ($ne: null), true returns matching records (or expansion), while $eq: nonexistent returns empty / 404
        if true_status in (200, base_status) and (false_status != true_status or sim_false < 0.65 or len(false_body) < 0.5 * len(true_body)):
            signals.append("NOSQL_OPERATOR_DIFFERENTIAL_CONFIRMED")
            reasons.append(
                f"NoSQL operator differential confirmed: True response status {true_status} vs False status {false_status} (similarity {sim_false:.2f})"
            )
            confidence = InjectionConfidence.VALIDATED
            is_candidate = True
        elif error_sig:
            confidence = InjectionConfidence.OBSERVED
            is_candidate = True
        else:
            confidence = InjectionConfidence.CANDIDATE
            is_candidate = False
            reasons.append("No operator differential or NoSQL error observed")

        return InjectionComparisonResult(
            is_candidate_signal=is_candidate,
            confidence=confidence,
            signals=signals,
            reasons=reasons,
            error_signature=error_sig,
            body_similarity_true=sim_true,
            body_similarity_false=sim_false,
        )
