import pytest

from test_engine import analyze_capture, fixture
from test_protocols import items


@pytest.mark.parametrize("name", list(fixture.EXPECTATIONS))
@pytest.mark.parametrize("format", ["pcap", "pcapng"])
def test_documented_fixture_expectations(client, name, format):
    capture = analyze_capture(client, fixture.fixtures()[name], format)
    expected = fixture.EXPECTATIONS[name]
    assert capture["packet_count"] == expected["packets"]
    assert client.get(f"/api/captures/{capture['id']}/flows").json()["total"] == expected["flows"]
    assert sorted({f["rule_id"] for f in items(client, capture["id"], "findings")}) == expected["findings"]
