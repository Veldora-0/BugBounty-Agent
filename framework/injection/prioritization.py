"""
Parameter Prioritization Engine for BugBounty-Agent (Phase 10).

Scores candidate injection parameters from 0 to 100 with clear human-readable
justifications based on semantic roles, locations, endpoints, and technology context.

CRITICAL INVARIANT:
Priority is NOT vulnerability severity or finding confidence.
Priority measures the likelihood and value of testing a parameter for injection.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from framework.injection.model import (
    InjectionCandidate,
    InjectionContext,
    InjectionType,
)

# Semantic keyword mappings for parameter names
SQL_SEARCH_KEYWORDS: Set[str] = {
    "q", "query", "search", "filter", "where", "find", "keyword", "term",
    "lookup", "text", "s", "k", "keywords", "pattern", "sql",
}

SQL_ORDER_KEYWORDS: Set[str] = {
    "sort", "order", "orderby", "sort_by", "sortby", "direction", "dir",
    "order_by", "column", "col", "sort_column",
}

SQL_PAGINATION_KEYWORDS: Set[str] = {
    "limit", "offset", "page", "per_page", "size", "page_size", "count",
    "skip", "top", "take",
}

SQL_IDENTIFIER_KEYWORDS: Set[str] = {
    "id", "user_id", "userid", "account_id", "item_id", "product_id",
    "doc_id", "uid", "uuid", "order_id", "org_id", "team_id", "group_id",
    "cat_id", "category_id", "post_id", "article_id", "comment_id",
}

NOSQL_OPERATOR_KEYWORDS: Set[str] = {
    "where", "filter", "query", "selector", "criteria", "json", "mongo",
    "aggregate", "match", "lookup", "find", "document", "pipeline",
}

SSTI_KEYWORDS: Set[str] = {
    "template", "tpl", "render", "view", "layout", "preview", "msg",
    "message", "email_template", "body", "format", "theme", "html",
    "markdown", "expression", "formula", "text_template", "report",
}

COMMAND_KEYWORDS: Set[str] = {
    "cmd", "exec", "command", "file", "filename", "path", "doc", "pdf",
    "convert", "image", "img", "tool", "ip", "host", "ping", "domain",
    "address", "dest", "tar", "zip", "archive", "export",
}

# Known backend tech indicators
SQL_TECHS = {"mysql", "mariadb", "postgresql", "postgres", "sqlite", "oracle", "mssql", "sqlserver", "django", "rails", "laravel", "hibernate"}
NOSQL_TECHS = {"mongo", "mongodb", "couchdb", "dynamodb", "firestore", "rethinkdb"}
SSTI_TECHS = {"jinja", "jinja2", "twig", "freemarker", "velocity", "handlebars", "thymeleaf", "mako", "tornado"}


class InjectionPrioritizer:
    """
    Evaluates endpoint parameters and produces a 0-100 priority score
    with human-readable reasons and inferred injection context.
    """

    @classmethod
    def evaluate(
        cls,
        parameter_name: str,
        endpoint: str,
        parameter_location: str = "QUERY",
        method: str = "GET",
        inferred_input_type: str = "STRING",
        technologies: Optional[List[str]] = None,
        is_authenticated: bool = False,
        content_type: str = "",
        schema_info: Optional[Dict[str, Any]] = None,
    ) -> Tuple[int, List[str], InjectionType, InjectionContext]:
        """
        Calculates priority score (0-100), reasons, suggested family, and context.
        """
        score = 40  # Neutral baseline
        reasons: List[str] = []
        techs = [t.lower() for t in (technologies or [])]
        clean_param = parameter_name.strip().lower()
        clean_loc = parameter_location.strip().upper()
        clean_type = inferred_input_type.strip().upper()

        suggested_family = InjectionType.SQL
        suggested_context = InjectionContext.SQL_STRING

        # 1. Semantic Parameter Role
        if clean_param in SQL_ORDER_KEYWORDS:
            score += 25
            reasons.append("ordering/sort semantic role (SQL ORDER BY candidate)")
            suggested_family = InjectionType.SQL
            suggested_context = InjectionContext.SQL_ORDER_BY
        elif clean_param in SQL_PAGINATION_KEYWORDS:
            score += 15
            reasons.append("pagination semantic role (SQL LIMIT/OFFSET candidate)")
            suggested_family = InjectionType.SQL
            suggested_context = InjectionContext.SQL_LIMIT
        elif clean_param in SQL_SEARCH_KEYWORDS:
            score += 22
            reasons.append("query/search semantic role (SQL filter candidate)")
            suggested_family = InjectionType.SQL
            suggested_context = InjectionContext.SQL_FILTER
        elif clean_param in SQL_IDENTIFIER_KEYWORDS:
            score += 20
            reasons.append("entity identifier lookup (SQL ID candidate)")
            suggested_family = InjectionType.SQL
            suggested_context = InjectionContext.SQL_NUMERIC if clean_type in ("INTEGER", "NUMERIC") else InjectionContext.SQL_STRING
        elif clean_param in SSTI_KEYWORDS:
            score += 25
            reasons.append("template/render semantic role (SSTI candidate)")
            suggested_family = InjectionType.SSTI
            suggested_context = InjectionContext.TEMPLATE_EXPRESSION
        elif clean_param in NOSQL_OPERATOR_KEYWORDS and ("json" in content_type.lower() or clean_loc == "JSON"):
            score += 24
            reasons.append("JSON filter/query structure (NoSQL query candidate)")
            suggested_family = InjectionType.NOSQL
            suggested_context = InjectionContext.NOSQL_QUERY
        elif clean_param in COMMAND_KEYWORDS:
            score += 18
            reasons.append("file/process utility role (command argument candidate)")
            suggested_family = InjectionType.COMMAND
            suggested_context = InjectionContext.COMMAND_ARGUMENT

        # 2. Parameter Location
        if clean_loc == "PATH":
            score += 12
            reasons.append("path parameter (dynamic routing / backend entity lookup)")
        elif clean_loc == "QUERY":
            score += 8
            reasons.append("query parameter (direct server query manipulation)")
        elif clean_loc == "JSON":
            score += 10
            reasons.append("JSON body parameter (structured API payload)")
        elif clean_loc == "FORM":
            score += 6
            reasons.append("form body parameter")
        elif clean_loc == "HEADER":
            score -= 10
            reasons.append("HTTP header (lower typical direct query injection surface)")

        # 3. Inferred Input Type
        if clean_type in ("INTEGER", "NUMERIC"):
            score += 8
            reasons.append("numeric input type (unquoted numeric SQL candidate)")
            if suggested_family == InjectionType.SQL and suggested_context == InjectionContext.SQL_STRING:
                suggested_context = InjectionContext.SQL_NUMERIC
        elif clean_type in ("OBJECT", "DICT", "JSON_OBJECT"):
            score += 10
            reasons.append("object/dictionary input type (potential NoSQL operator injection)")
            if suggested_family in (InjectionType.SQL, InjectionType.UNKNOWN):
                suggested_family = InjectionType.NOSQL
                suggested_context = InjectionContext.NOSQL_OPERATOR

        # 4. Technology Context (Phases 2-5)
        has_sql_tech = any(any(st in t for st in SQL_TECHS) for t in techs)
        has_nosql_tech = any(any(nst in t for nst in NOSQL_TECHS) for t in techs)
        has_ssti_tech = any(any(sst in t for sst in SSTI_TECHS) for t in techs)

        if has_sql_tech:
            score += 10
            reasons.append(f"SQL database / ORM detected in application tech stack")
        if has_nosql_tech:
            score += 12
            reasons.append("NoSQL document database detected in application tech stack")
            if suggested_family == InjectionType.SQL and ("json" in content_type.lower() or clean_loc == "JSON"):
                suggested_family = InjectionType.NOSQL
                suggested_context = InjectionContext.NOSQL_QUERY
        if has_ssti_tech:
            score += 15
            reasons.append("template engine detected in application tech stack")
            if clean_param in SSTI_KEYWORDS or "render" in endpoint.lower() or "template" in endpoint.lower():
                suggested_family = InjectionType.SSTI
                suggested_context = InjectionContext.TEMPLATE_EXPRESSION

        # 5. Endpoint Type & Semantics
        lower_ep = endpoint.lower()
        if "/api/" in lower_ep or "/v1/" in lower_ep or "/v2/" in lower_ep:
            score += 6
            reasons.append("REST/API endpoint architecture")
        if any(w in lower_ep for w in ("search", "find", "query", "filter")):
            score += 8
            reasons.append("search/filter endpoint path")
        if any(w in lower_ep for w in ("export", "render", "preview", "report", "pdf", "generate")):
            score += 10
            reasons.append("rendering / document generation endpoint path")

        # 6. Authentication Context
        if is_authenticated:
            score += 6
            reasons.append("authenticated context (privileged backend handler access)")

        # 7. Low-priority Demotions
        if clean_param in ("csrf", "token", "nonce", "_csrf", "authenticity_token", "state"):
            score -= 40
            reasons.append("anti-CSRF security token (unlikely query sink)")
        elif clean_param in ("lang", "locale", "tz", "timezone", "theme", "mode", "version", "v"):
            score -= 10
            reasons.append("presentation/localization setting")

        # Clamp score to 0..100
        final_score = max(0, min(100, score))

        return final_score, reasons, suggested_family, suggested_context

    @classmethod
    def rank_candidates(cls, candidates: List[InjectionCandidate]) -> List[InjectionCandidate]:
        """
        Sorts candidates deterministically by priority score descending,
        then candidate_id ascending.
        """
        return sorted(
            candidates,
            key=lambda c: (-c.priority_score, c.candidate_id),
        )
