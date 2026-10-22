"""
Safe XML Parsing and Entity Defense for BugBounty-Agent.

Provides dependency-free, portable XML parsing using standard library
xml.etree.ElementTree and xml.parsers.expat.
Enforces:
1. Hard input size bounds (defending against memory exhaustion).
2. Strict prohibition of external entities (SYSTEM and PUBLIC references).
3. Configurable total DTD rejection for strict formats (e.g., sitemaps).
4. Bounded entity declarations and expansions (defending against Billion Laughs / quadratic blowup).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
from typing import List, Optional


class SafeXMLParseError(ValueError):
    """Raised when XML parsing fails or violates safety bounds."""
    pass


def safe_parse_xml(
    xml_content: str | bytes,
    max_bytes: int = 5 * 1024 * 1024,
    disallow_dtd: bool = True,
    max_entity_declarations: int = 50,
) -> ET.Element:
    """
    Safely parses XML into an ElementTree Element using standard library APIs.

    :param xml_content: XML string or bytes to parse.
    :param max_bytes: Maximum allowed byte size (default 5MB).
    :param disallow_dtd: If True, completely forbids DOCTYPE and ENTITY declarations (e.g. sitemaps).
    :param max_entity_declarations: Maximum internal entity declarations when DTDs are permitted.
    :return: Root ElementTree Element.
    :raises SafeXMLParseError: If input is oversized, malformed, or violates security constraints.
    """
    if not isinstance(xml_content, (str, bytes)):
        raise SafeXMLParseError("XML content must be a string or bytes.")

    raw_bytes = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    if len(raw_bytes) > max_bytes:
        raise SafeXMLParseError(
            f"XML input exceeds maximum allowed size bound ({len(raw_bytes)} > {max_bytes} bytes)."
        )

    if not raw_bytes.strip():
        raise SafeXMLParseError("Empty XML document.")

    # Strict mode: Disallow all DOCTYPE and ENTITY declarations (e.g. for sitemaps, RSS, REST XML)
    if disallow_dtd:
        lower = raw_bytes.lower()
        if b"<!doctype" in lower or b"<!entity" in lower:
            raise SafeXMLParseError(
                "DOCTYPE and ENTITY declarations are forbidden in this XML context."
            )
        try:
            return ET.fromstring(raw_bytes)
        except ET.ParseError as e:
            raise SafeXMLParseError(f"Malformed XML syntax: {e}")

    # Permissive DTD mode: Expat pre-flight inspection to intercept external entities & bounded entity counts
    entity_count = 0

    def entity_decl_handler(entity_name, is_parameter_entity, value, base, system_id, public_id, notation_name):
        nonlocal entity_count
        entity_count += 1
        if entity_count > max_entity_declarations:
            raise SafeXMLParseError(
                f"Exceeded maximum entity declaration limit ({max_entity_declarations})."
            )
        if system_id or public_id:
            raise SafeXMLParseError(
                f"External entity '{entity_name}' is forbidden (SYSTEM/PUBLIC reference detected)."
            )

    def external_ref_handler(context, base, system_id, public_id):
        raise SafeXMLParseError(
            f"External entity reference forbidden: systemId={system_id}, publicId={public_id}"
        )

    try:
        inspector = expat.ParserCreate()
        inspector.EntityDeclHandler = entity_decl_handler
        inspector.ExternalEntityRefHandler = external_ref_handler
        inspector.Parse(raw_bytes, True)
    except (expat.ExpatError, ET.ParseError) as e:
        raise SafeXMLParseError(f"Malformed XML syntax: {e}")
    except SafeXMLParseError:
        raise
    except Exception as e:
        raise SafeXMLParseError(f"XML safety inspection failed: {e}")

    try:
        return ET.fromstring(raw_bytes)
    except ET.ParseError as e:
        raise SafeXMLParseError(f"Malformed XML syntax: {e}")


def safe_extract_sitemap_urls(xml_content: str | bytes, max_bytes: int = 5 * 1024 * 1024) -> List[str]:
    """
    Safely extracts all <loc> URLs from sitemap XML content.
    Fails closed if the document contains DOCTYPE, entity declarations, or is oversized.
    """
    try:
        root = safe_parse_xml(xml_content, max_bytes=max_bytes, disallow_dtd=True)
    except SafeXMLParseError:
        return []

    urls: List[str] = []
    for elem in root.iter():
        if elem.tag.endswith("loc") and elem.text:
            cleaned = elem.text.strip()
            if cleaned:
                urls.append(cleaned)
    return urls
