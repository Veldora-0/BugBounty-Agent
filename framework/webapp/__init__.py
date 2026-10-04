"""
Web Application Intelligence Package for BugBounty-Agent.

Exposes WebApplication, WebPage, WebEndpoint, ParameterObservation, FormObservation,
CookieObservation, ResourceObservation, LinkObservation, WebAppGraph, WebAppStateManager,
CrawlPolicy, and WebApplicationIntelligenceEngine.
"""

from framework.webapp.engine import WebApplicationIntelligenceEngine
from framework.webapp.graph import AppRelationship, AppRelationType, WebAppGraph
from framework.webapp.model import (
    CookieObservation,
    FormObservation,
    LinkObservation,
    ParameterLocation,
    ParameterObservation,
    ResourceObservation,
    ResourceType,
    WebApplication,
    WebEndpoint,
    WebPage,
    canonicalize_url,
    is_same_origin,
)
from framework.webapp.parser import parse_page_html
from framework.webapp.policy import CrawlPolicy
from framework.webapp.state import WebAppStateManager

__all__ = [
    "WebApplicationIntelligenceEngine",
    "WebAppStateManager",
    "WebAppGraph",
    "AppRelationship",
    "AppRelationType",
    "CrawlPolicy",
    "WebApplication",
    "WebPage",
    "WebEndpoint",
    "ParameterObservation",
    "FormObservation",
    "CookieObservation",
    "ResourceObservation",
    "LinkObservation",
    "ParameterLocation",
    "ResourceType",
    "canonicalize_url",
    "is_same_origin",
    "parse_page_html",
]
