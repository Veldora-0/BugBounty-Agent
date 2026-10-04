"""
Safe, Bounded HTML and Metadata Parser for BugBounty-Agent Web Application Intelligence.

Extracts links, forms, inputs, scripts, stylesheets, images, iframes, media,
and document metadata from HTML content using standard library html.parser
without executing JavaScript or risking memory blowups.
"""

from __future__ import annotations

from html.parser import HTMLParser
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

from framework.webapp.model import (
    FormObservation,
    LinkObservation,
    ParameterLocation,
    ParameterObservation,
    ResourceObservation,
    ResourceType,
    canonicalize_url,
    is_same_origin,
)


def classify_resource_type(url: str, tag: str) -> ResourceType:
    """Classifies resource type based on HTML tag and file extension."""
    if tag == "script":
        return ResourceType.JS
    if tag == "link":
        clean = url.lower().split("?")[0]
        if clean.endswith(".css"):
            return ResourceType.CSS
        if clean.endswith((".woff", ".woff2", ".ttf", ".eot", ".otf")):
            return ResourceType.FONT
        if clean.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico")):
            return ResourceType.IMAGE
        if clean.endswith(".json"):
            return ResourceType.JSON
        return ResourceType.OTHER
    if tag in ("img", "image"):
        return ResourceType.IMAGE
    if tag in ("video", "audio", "source"):
        return ResourceType.MEDIA
    clean = url.lower().split("?")[0]
    if clean.endswith(".js"):
        return ResourceType.JS
    if clean.endswith(".css"):
        return ResourceType.CSS
    if clean.endswith(".wasm"):
        return ResourceType.WASM
    if clean.endswith(".json"):
        return ResourceType.JSON
    return ResourceType.OTHER


class BoundedHTMLParser(HTMLParser):
    """
    Robust, bounded HTML parser extracting application elements deterministically.
    Enforces maximum limits per page to avoid denial of service on malicious documents.
    """

    def __init__(
        self,
        base_url: str,
        max_links: int = 200,
        max_forms: int = 50,
        max_resources: int = 200,
    ):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.max_links = max_links
        self.max_forms = max_forms
        self.max_resources = max_resources

        self.title: Optional[str] = None
        self._in_title = False
        self._title_buffer: List[str] = []

        self.meta_generator: Optional[str] = None
        self.canonical_url: Optional[str] = None
        self.base_href: Optional[str] = None

        self.links: List[str] = []
        self.resources: List[Tuple[str, ResourceType, str]] = []  # (url, type, tag)

        # Forms tracking
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        tag = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs if k}

        effective_base = self.base_href or self.base_url

        if tag == "base" and "href" in attr_dict:
            b_val = attr_dict["href"].strip()
            if b_val:
                self.base_href = urljoin(self.base_url, b_val)
            return

        if self._in_title and tag in ("body", "div", "p", "a", "form", "section", "article", "nav", "main", "h1", "h2", "h3", "h4", "h5", "h6"):
            self._in_title = False
            full_title = "".join(self._title_buffer).strip()
            self.title = re.sub(r"\s+", " ", full_title) if full_title else None

        if tag == "title":
            self._in_title = True
            return

        if tag == "meta":
            name = attr_dict.get("name", "").lower()
            prop = attr_dict.get("property", "").lower()
            content = attr_dict.get("content", "").strip()
            if name == "generator":
                self.meta_generator = content
            elif name == "canonical" or prop == "og:url":
                if content:
                    self.canonical_url = urljoin(effective_base, content)
            return

        # Links (a, area)
        if tag in ("a", "area") and len(self.links) < self.max_links:
            href = attr_dict.get("href", "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                resolved = urljoin(effective_base, href)
                self.links.append(resolved)

        # Resources (script, link, img, iframe, source, video, audio)
        if len(self.resources) < self.max_resources:
            res_url = None
            if tag == "script" and "src" in attr_dict:
                res_url = attr_dict["src"].strip()
            elif tag == "link" and "href" in attr_dict:
                rel = attr_dict.get("rel", "").lower()
                if rel in ("stylesheet", "icon", "shortcut icon", "preload", "prefetch") or attr_dict["href"].endswith((".css", ".js")):
                    res_url = attr_dict["href"].strip()
            elif tag in ("img", "iframe", "source", "video", "audio") and "src" in attr_dict:
                res_url = attr_dict["src"].strip()

            if res_url and not res_url.startswith(("data:", "javascript:")):
                resolved = urljoin(effective_base, res_url)
                r_type = classify_resource_type(resolved, tag)
                self.resources.append((resolved, r_type, tag))

        # Forms
        if tag == "form":
            if self._current_form is not None:
                # Close unclosed form
                self.forms.append(self._current_form)
            if len(self.forms) < self.max_forms:
                act = attr_dict.get("action", "").strip() or effective_base
                method = attr_dict.get("method", "GET").strip().upper() or "GET"
                enctype = attr_dict.get("enctype", "application/x-www-form-urlencoded").strip().lower()
                self._current_form = {
                    "action": urljoin(effective_base, act),
                    "method": method,
                    "enctype": enctype,
                    "inputs": {},  # name -> type
                }
            return

        if self._current_form is not None:
            if tag == "input":
                iname = attr_dict.get("name", "").strip()
                itype = attr_dict.get("type", "text").strip().lower() or "text"
                if iname:
                    self._current_form["inputs"][iname] = itype
            elif tag == "textarea":
                iname = attr_dict.get("name", "").strip()
                if iname:
                    self._current_form["inputs"][iname] = "textarea"
            elif tag == "select":
                iname = attr_dict.get("name", "").strip()
                if iname:
                    self._current_form["inputs"][iname] = "select"
            elif tag == "button":
                iname = attr_dict.get("name", "").strip()
                btype = attr_dict.get("type", "submit").strip().lower()
                if iname:
                    self._current_form["inputs"][iname] = f"button:{btype}"

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
            full_title = "".join(self._title_buffer).strip()
            self.title = re.sub(r"\s+", " ", full_title) if full_title else None
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_buffer.append(data)

    def close(self) -> None:
        if self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        super().close()


def parse_page_html(
    html_content: str,
    page_url: str,
    max_links: int = 200,
    max_forms: int = 50,
    max_resources: int = 200,
) -> Dict[str, Any]:
    """
    Parses HTML content safely with bounded resource extraction.
    Returns structured dictionary with title, links, resources, and forms.
    """
    parser = BoundedHTMLParser(
        base_url=page_url,
        max_links=max_links,
        max_forms=max_forms,
        max_resources=max_resources,
    )
    try:
        parser.feed(html_content)
        parser.close()
    except Exception:
        pass

    return {
        "title": parser.title,
        "meta_generator": parser.meta_generator,
        "canonical_url": parser.canonical_url,
        "links": parser.links,
        "resources": parser.resources,
        "forms": parser.forms,
    }
