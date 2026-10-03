"""
Tests for API Provider and Credential Management.
"""

import os
import tempfile
import pytest

from framework.tools.providers import ProviderManager, KNOWN_PROVIDERS


def test_credential_detection_from_secrets_file():
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write("# Test secrets\n")
        tf.write("SHODAN_API_KEY=mock_shodan_key_12345\n")
        tf.write("PDCP_API_KEY=\"mock_pdcp_token_abcde\"\n")
        temp_file = tf.name

    try:
        mgr = ProviderManager(secrets_file=temp_file)
        assert mgr.has_credential("SHODAN_API_KEY") is True
        assert mgr.get_credential("SHODAN_API_KEY") == "mock_shodan_key_12345"
        assert mgr.has_credential("PDCP_API_KEY") is True
        assert mgr.get_credential("PDCP_API_KEY") == "mock_pdcp_token_abcde"
        assert mgr.has_credential("NONEXISTENT_KEY") is False

        # Provider check
        shodan_st = mgr.check_provider("shodan")
        assert shodan_st["configured"] is True
        assert "SHODAN_API_KEY" in shodan_st["configured_vars"]

        # Missing provider
        censys_st = mgr.check_provider("censys")
        assert censys_st["configured"] is False
        assert "CENSYS_API_TOKEN" in censys_st["missing_vars"]

    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_provider_status_does_not_leak_secret_value():
    with tempfile.NamedTemporaryFile("w", delete=False) as tf:
        tf.write("VT_API_KEY=my_ultra_secret_virustotal_key\n")
        temp_file = tf.name

    try:
        mgr = ProviderManager(secrets_file=temp_file)
        st = mgr.check_provider("virustotal")

        # The serialized status dict must never contain the raw secret string
        serialized = str(st)
        assert "my_ultra_secret_virustotal_key" not in serialized
        assert st["configured"] is True
    finally:
        if os.path.exists(temp_file):
            os.remove(temp_file)


def test_all_providers_coverage():
    mgr = ProviderManager(secrets_file="/nonexistent/secrets.env")
    all_st = mgr.get_all_providers_status()
    assert len(all_st) >= 8
    assert "projectdiscovery-cloud" in all_st
    assert "shodan" in all_st
    assert "censys" in all_st
    assert "wpscan" in all_st
