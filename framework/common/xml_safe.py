"""
Safe XML Parsing and Entity Defense for BugBounty-Agent.

Provides dependency-free, portable XML parsing using standard library
xml.etree.ElementTree and xml.parsers.expat.
Enforces:
1. Hard input size bounds (defending against memory exhaustion).
2. Strict prohibition of external entities (SYSTEM and PUBLIC references).
3. Configurable total DTD rejection for strict formats (e.g., sitemaps).
4. Strict cumulative character budget and entity expansion defense (Billion Laughs / quadratic blowup).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
import xml.parsers.expat as expat
from typing import List, Optional


class SafeXMLParseError(ValueError):
    """Base error raised when XML parsing fails or violates safety bounds."""
    pass


class XmlBombSecurityError(SafeXMLParseError):
    """Raised specifically when entity expansion or amplification limits are exceeded."""
    pass


class ProhibitedDtdSecurityError(SafeXMLParseError):
    """Raised when DOCTYPE or ENTITY declarations are detected in strict mode."""
    pass


class ExternalEntitySecurityError(SafeXMLParseError):
    """Raised when external SYSTEM or PUBLIC entities are referenced."""
    pass


def safe_parse_xml(
    xml_content: str | bytes,
    max_bytes: int = 5 * 1024 * 1024,
    disallow_dtd: bool = True,
    max_entity_declarations: int = 20,
    max_expanded_chars: int = 50_000,
) -> ET.Element:
    """
    Safely parses XML into an ElementTree Element using standard library APIs.

    :param xml_content: XML string or bytes to parse.
    :param max_bytes: Maximum allowed byte size (default 5MB).
    :param disallow_dtd: If True, completely forbids DOCTYPE and ENTITY declarations (e.g. sitemaps).
    :param max_entity_declarations: Maximum internal entity declarations when DTDs are permitted.
    :param max_expanded_chars: Cumulative character budget for expanded text and attributes.
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
            raise ProhibitedDtdSecurityError(
                "DOCTYPE and ENTITY declarations are forbidden in strict XML mode."
            )

        def strict_doctype_handler(doctype_name, system_id, public_id, has_internal_subset):
            raise ProhibitedDtdSecurityError("DOCTYPE declarations are forbidden in strict XML mode.")

        def strict_entity_handler(entity_name, is_parameter_entity, value, base, system_id, public_id, notation_name):
            raise ProhibitedDtdSecurityError("ENTITY declarations are forbidden in strict XML mode.")

        try:
            inspector = expat.ParserCreate()
            inspector.StartDoctypeDeclHandler = strict_doctype_handler
            inspector.EntityDeclHandler = strict_entity_handler
            inspector.Parse(raw_bytes, True)
        except SafeXMLParseError:
            raise
        except (expat.ExpatError, ET.ParseError) as e:
            raise SafeXMLParseError(f"Malformed XML syntax: {e}")
        except Exception as e:
            raise SafeXMLParseError(f"XML safety inspection failed: {e}")

        try:
            return ET.fromstring(raw_bytes)
        except ET.ParseError as e:
            raise SafeXMLParseError(f"Malformed XML syntax: {e}")

    # Permissive DTD mode: Pre-flight inspection with Expat
    # Enforces declaration counts, cumulative expansion character budgets, and blocks external entities
    entity_count = 0
    total_expanded_chars = 0

    def entity_decl_handler(entity_name, is_parameter_entity, value, base, system_id, public_id, notation_name):
        nonlocal entity_count
        entity_count += 1
        if entity_count > max_entity_declarations:
            raise XmlBombSecurityError(
                f"Exceeded maximum entity declaration limit ({entity_count} > {max_entity_declarations})."
            )
        if system_id or public_id:
            raise ExternalEntitySecurityError(
                f"External entity '{entity_name}' is forbidden (SYSTEM/PUBLIC reference detected)."
            )

    def external_ref_handler(context, base, system_id, public_id):
        raise ExternalEntitySecurityError(
            f"External entity reference forbidden: systemId={system_id}, publicId={public_id}"
        )

    def char_data_handler(data):
        nonlocal total_expanded_chars
        total_expanded_chars += len(data)
        if total_expanded_chars > max_expanded_chars:
            raise XmlBombSecurityError(
                f"XML entity expansion exceeded cumulative character budget ({total_expanded_chars} > {max_expanded_chars})."
            )

    def start_element_handler(name, attrs):
        nonlocal total_expanded_chars
        for k, v in attrs.items():
            total_expanded_chars += len(v)
            if total_expanded_chars > max_expanded_chars:
                raise XmlBombSecurityError(
                    f"XML attribute entity expansion exceeded cumulative character budget ({total_expanded_chars} > {max_expanded_chars})."
                )

    try:
        inspector = expat.ParserCreate()
        inspector.EntityDeclHandler = entity_decl_handler
        inspector.ExternalEntityRefHandler = external_ref_handler
        inspector.CharacterDataHandler = char_data_handler
        inspector.StartElementHandler = start_element_handler

        # Configure built-in Expat Billion Laughs attack protection when supported
        if hasattr(inspector, "SetBillionLaughsAttackProtectionActivationThreshold"):
            try:
                inspector.SetBillionLaughsAttackProtectionActivationThreshold(max(1024, max_expanded_chars // 2))
            except Exception:
                pass
        if hasattr(inspector, "SetBillionLaughsAttackProtectionMaximumAmplification"):
            try:
                inspector.SetBillionLaughsAttackProtectionMaximumAmplification(5.0)
            except Exception:
                pass

        inspector.Parse(raw_bytes, True)
    except SafeXMLParseError:
        raise
    except expat.ExpatError as e:
        msg = str(e).lower()
        if "amplification" in msg or "billion laughs" in msg or "entity expansion" in msg:
            raise XmlBombSecurityError(f"XML entity expansion defense triggered: {e}")
        raise SafeXMLParseError(f"Malformed XML syntax: {e}")
    except ET.ParseError as e:
        raise SafeXMLParseError(f"Malformed XML syntax: {e}")
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
