"""
Crawl Policy & Budget Configuration for BugBounty-Agent Web Application Intelligence.

Centralizes crawling limits, safety ceilings, response size bounds, and same-origin rules.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class CrawlPolicy:
    """
    Centralized crawl policy and safety budgets for web application intelligence.
    Enforces conservative default bounds across pages, requests, depths, and responses.
    """
    max_pages: int = 500
    max_depth: int = 3
    max_requests: int = 2000
    max_response_bytes: int = 2 * 1024 * 1024  # 2 MB response ceiling
    max_links_per_page: int = 200
    max_forms_per_page: int = 50
    max_resources_per_page: int = 200
    same_origin_only: bool = True
    follow_redirects: bool = True
    max_redirects: int = 5
    passive_only: bool = False
    include_robots: bool = True
    include_sitemaps: bool = True
    include_js_resources: bool = True
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BugBounty-Agent/3.0"
