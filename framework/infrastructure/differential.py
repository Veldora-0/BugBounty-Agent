"""
Differential Soft-404 and SPA Catch-All Detection Engine for BugBounty-Agent.

Provides multi-factor differential response analysis:
- Normalizes dynamic tokens (timestamps, CSRF tokens, nonces, request IDs).
- Evaluates status code deltas, Content-Type deltas, redirect targets, and token similarity.
- Rejects SPA catch-alls and custom error pages without naive 200-rejections.
- Invariant: Never rejects a candidate solely because the baseline random path returned 200.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urlunparse


# Dynamic token regex patterns to strip before similarity calculation
DYNAMIC_PATTERNS = [
    # ISO timestamps and date strings
    re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"),
    re.compile(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2}\s+(?:GMT|UTC|[A-Z]{3})\b", re.IGNORECASE),
    # Nonces and CSRF tokens in attributes
    re.compile(r"""(?:nonce|csrf[-_]?token|csrf[-_]?param|authenticity[-_]?token|__requestverificationtoken)=["'][^"']+["']""", re.IGNORECASE),
    # Standalone hex or base64 hashes (>= 24 chars)
    re.compile(r"\b[0-9a-fA-F]{24,64}\b"),
    re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}(?:\.[a-zA-Z0-9_\-]+)?\b"),
    # HTML comments
    re.compile(r"<!--[\s\S]*?-->"),
]


@dataclass
class DifferentialComparisonResult:
    """Outcome of differential response comparison between candidate and baseline."""
    is_soft_404: bool
    similarity_score: float
    status_matches: bool
    content_type_matches: bool
    redirect_target_matches: bool
    reasons: List[str] = field(default_factory=list)
    normalized_candidate_length: int = 0
    normalized_baseline_length: int = 0


class DifferentialSoft404Engine:
    """
    Multi-factor differential comparison engine to accurately identify soft-404s.
    """

    @staticmethod
    def generate_baseline_path(origin_or_url: str) -> str:
        """
        Generates a deterministic non-existent path on the target origin.
        """
        parsed = urlparse(origin_or_url)
        origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else origin_or_url
        seed = hashlib.sha256(origin.lower().encode("utf-8")).hexdigest()[:10]
        return f"/__bb_differential_baseline_{seed}__"

    @staticmethod
    def normalize_body(body: str) -> str:
        """
        Strips dynamic tokens, collapses whitespace, and normalizes text.
        """
        if not body:
            return ""
        norm = body
        for pattern in DYNAMIC_PATTERNS:
            norm = pattern.sub(" ", norm)
        # Collapse multiple whitespace characters
        norm = re.sub(r"\s+", " ", norm).strip().lower()
        return norm

    @staticmethod
    def calculate_token_similarity(text1: str, text2: str) -> float:
        """
        Calculates Jaccard similarity over word token sets.
        Returns float between 0.0 and 1.0.
        """
        if not text1 and not text2:
            return 1.0
        if not text1 or not text2:
            return 0.0

        # Tokenize by non-alphanumeric boundaries
        tokens1: Set[str] = set(re.findall(r"\w{2,}", text1))
        tokens2: Set[str] = set(re.findall(r"\w{2,}", text2))

        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0

        intersection = len(tokens1.intersection(tokens2))
        union = len(tokens1.union(tokens2))
        return float(intersection) / float(union) if union > 0 else 0.0

    @classmethod
    def evaluate(
        cls,
        candidate_status: int,
        candidate_headers: Dict[str, str],
        candidate_body: str,
        baseline_status: int,
        baseline_headers: Dict[str, str],
        baseline_body: str,
        candidate_final_url: str = "",
        baseline_final_url: str = "",
        candidate_has_structural_signature: bool = False,
    ) -> DifferentialComparisonResult:
        """
        Evaluates candidate response against baseline non-existent path response.
        Enforces:
        - Candidate is never rejected solely because baseline returned HTTP 200.
        - Similarity comparison accounts for dynamic tokens and Content-Type deltas.
        - Redirect catch-alls are detected and classified as soft-404.
        """
        reasons: List[str] = []

        # Extract Content-Types
        cand_ct = candidate_headers.get("Content-Type", candidate_headers.get("content-type", "")).lower()
        base_ct = baseline_headers.get("Content-Type", baseline_headers.get("content-type", "")).lower()
        ct_cand_main = cand_ct.split(";")[0].strip()
        ct_base_main = base_ct.split(";")[0].strip()
        ct_matches = bool(ct_cand_main and ct_base_main and ct_cand_main == ct_base_main)

        # Status matches
        status_matches = (candidate_status == baseline_status)

        # Check redirect catch-all
        redirect_matches = False
        if candidate_final_url and baseline_final_url and candidate_final_url != "" and baseline_final_url != "":
            parsed_cand = urlparse(candidate_final_url)
            parsed_base = urlparse(baseline_final_url)
            if parsed_cand.path and parsed_cand.path == parsed_base.path and parsed_cand.path not in ("/", ""):
                redirect_matches = True
                reasons.append(f"Redirect catch-all: both candidate and baseline redirected to '{parsed_cand.path}'")

        # 1. Obvious standard 404 / 410 response on candidate
        if candidate_status in (404, 410):
            return DifferentialComparisonResult(
                is_soft_404=False,
                similarity_score=0.0,
                status_matches=status_matches,
                content_type_matches=ct_matches,
                redirect_target_matches=redirect_matches,
                reasons=["Candidate returned standard HTTP 404/410 Not Found"],
                normalized_candidate_length=len(candidate_body),
                normalized_baseline_length=len(baseline_body),
            )

        # 2. Baseline was standard 404, candidate returned 200
        if baseline_status in (404, 410) and candidate_status == 200:
            reasons.append("Baseline returned 404 while candidate returned 200")
            return DifferentialComparisonResult(
                is_soft_404=False,
                similarity_score=0.0,
                status_matches=False,
                content_type_matches=ct_matches,
                redirect_target_matches=redirect_matches,
                reasons=reasons,
                normalized_candidate_length=len(candidate_body),
                normalized_baseline_length=len(baseline_body),
            )

        # 3. Redirect catch-all check
        if redirect_matches:
            return DifferentialComparisonResult(
                is_soft_404=True,
                similarity_score=1.0,
                status_matches=status_matches,
                content_type_matches=ct_matches,
                redirect_target_matches=True,
                reasons=reasons,
                normalized_candidate_length=len(candidate_body),
                normalized_baseline_length=len(baseline_body),
            )

        # 4. Content-Type Delta & Structural Signature Check
        # If baseline is HTML (e.g. SPA index.html), but candidate is text/plain, application/json, or binary stream
        # with a confirmed valid structural signature, it is NOT a soft-404!
        if "text/html" in base_ct and "text/html" not in cand_ct and candidate_has_structural_signature:
            reasons.append(
                f"Content-Type delta: candidate ({ct_cand_main}) is distinct from baseline HTML ({ct_base_main}) "
                f"and exhibits verified structural signature"
            )
            return DifferentialComparisonResult(
                is_soft_404=False,
                similarity_score=0.0,
                status_matches=status_matches,
                content_type_matches=False,
                redirect_target_matches=False,
                reasons=reasons,
                normalized_candidate_length=len(candidate_body),
                normalized_baseline_length=len(baseline_body),
            )

        # 5. Normalized Body Similarity Analysis
        norm_cand = cls.normalize_body(candidate_body)
        norm_base = cls.normalize_body(baseline_body)
        sim = cls.calculate_token_similarity(norm_cand, norm_base)

        # If both are HTML and similarity is high (> 0.85), classify as soft-404 catch-all
        if ct_matches and "text/html" in ct_cand_main and sim >= 0.85:
            reasons.append(
                f"High body similarity ({sim:.2f} >= 0.85) to baseline non-existent path: classified as soft-404 catch-all"
            )
            return DifferentialComparisonResult(
                is_soft_404=True,
                similarity_score=sim,
                status_matches=status_matches,
                content_type_matches=True,
                redirect_target_matches=False,
                reasons=reasons,
                normalized_candidate_length=len(norm_cand),
                normalized_baseline_length=len(norm_base),
            )

        # If candidate has verified structural signature and low similarity to baseline
        if candidate_has_structural_signature:
            reasons.append(f"Candidate exhibits valid structural signature with similarity {sim:.2f} to baseline")
            return DifferentialComparisonResult(
                is_soft_404=False,
                similarity_score=sim,
                status_matches=status_matches,
                content_type_matches=ct_matches,
                redirect_target_matches=False,
                reasons=reasons,
                normalized_candidate_length=len(norm_cand),
                normalized_baseline_length=len(norm_base),
            )

        # If similarity is very high regardless of Content-Type
        if sim >= 0.90:
            reasons.append(f"Identical or near-identical body ({sim:.2f} >= 0.90) to baseline: classified as catch-all")
            return DifferentialComparisonResult(
                is_soft_404=True,
                similarity_score=sim,
                status_matches=status_matches,
                content_type_matches=ct_matches,
                redirect_target_matches=False,
                reasons=reasons,
                normalized_candidate_length=len(norm_cand),
                normalized_baseline_length=len(norm_base),
            )

        # Default case: distinct enough
        reasons.append(f"Distinct response: similarity {sim:.2f} is below catch-all threshold")
        return DifferentialComparisonResult(
            is_soft_404=False,
            similarity_score=sim,
            status_matches=status_matches,
            content_type_matches=ct_matches,
            redirect_target_matches=False,
            reasons=reasons,
            normalized_candidate_length=len(norm_cand),
            normalized_baseline_length=len(norm_base),
        )
