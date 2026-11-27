import ipaddress

from framework.assets.asn import TeamCymruAsnResolver


class Result:
    returncode = 0
    stdout = '"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"\n'


def test_team_cymru_provider_parses_and_caches_public_ip(monkeypatch):
    calls = []
    monkeypatch.setattr("framework.assets.asn.subprocess.run", lambda *a, **k: calls.append((a, k)) or Result())
    resolver = TeamCymruAsnResolver(dig_path="dig")
    assert resolver("8.8.8.8")["asn"] == "AS15169"
    assert resolver("8.8.8.8")["cidr"] == "8.8.8.0/24"
    assert resolver("8.8.8.8")["source"] == "Team Cymru IP-to-ASN"
    assert len(calls) == 1
    assert "8.8.8.8.origin.asn.cymru.com." in calls[0][0][0][-1]


def test_team_cymru_provider_does_not_query_non_global_or_invalid(monkeypatch):
    calls = []
    monkeypatch.setattr("framework.assets.asn.subprocess.run", lambda *a, **k: calls.append(a))
    resolver = TeamCymruAsnResolver(dig_path="dig")
    assert resolver("127.0.0.1") == {}
    assert resolver("10.0.0.1") == {}
    assert resolver("not-an-ip") == {}
    assert not calls


def test_team_cymru_provider_enforces_query_budget_and_network_match(monkeypatch):
    class WrongNetwork:
        returncode = 0
        stdout = '"15169 | 1.1.1.0/24 | US | arin | 1992-12-01"'
    monkeypatch.setattr("framework.assets.asn.subprocess.run", lambda *a, **k: WrongNetwork())
    resolver = TeamCymruAsnResolver(dig_path="dig", max_queries=1)
    assert resolver("8.8.8.8") == {}
    assert resolver("1.1.1.1") == {}
    assert resolver.queries == 1


def test_default_unknown_cidr_handles_ipv6():
    from framework.assets.engine import AssetIntelligenceEngine
    result = AssetIntelligenceEngine().resolve_asn("2001:4860:4860::8888")
    assert result["cidr"] == "2001:4860:4860::8888/128"
