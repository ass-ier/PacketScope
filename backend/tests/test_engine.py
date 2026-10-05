import importlib.util
import time
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("fixture_generator", Path(__file__).parents[2] / "fixtures/generate.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def analyze_capture(client, records, format="pcap"):
    response = client.post("/api/captures", files={"file": (f"synthetic.{format}", fixture.encode(records, format))})
    assert response.status_code == 201, response.text
    capture = response.json()
    assert client.post(f"/api/captures/{capture['id']}/analyze").status_code == 202
    for _ in range(500):
        status = client.get(f"/api/captures/{capture['id']}/analysis").json()
        if status["analysis_status"] in ("completed", "failed"):
            assert status["analysis_status"] == "completed", status
            return status
        time.sleep(.01)
    pytest.fail("Analysis job did not finish")


@pytest.mark.parametrize("format", ["pcap", "pcapng"])
def test_packets_flows_bytes_and_detail(client, format):
    records = fixture.conversation()
    capture = analyze_capture(client, records, format)
    cid = capture["id"]
    assert capture["packet_count"] == 7
    assert capture["duration"] == pytest.approx(.06, abs=1e-6)
    flows = client.get(f"/api/captures/{cid}/flows").json()["items"]
    assert len(flows) == 1
    flow = flows[0]
    assert flow["state"] == "closed"
    assert flow["bytes_sent"] == sum(len(records[i][1]) for i in (0, 2, 3, 5))
    assert flow["bytes_received"] == sum(len(records[i][1]) for i in (1, 4, 6))
    assert len(client.get(f"/api/captures/{cid}/hosts").json()["items"]) == 2
    detail = client.get(f"/api/captures/{cid}/packets/4?hex_view=true").json()
    assert detail["capture_sha256"] == capture["sha256"]
    assert detail["decoded"]["metadata_fields"]["tcp"]["sequence"] == 101
    assert "47 45 54" in detail["hex"]
    assert client.get(f"/api/captures/{cid}/packets?q=host:10.0.0.10").json()["total"] == 7
    assert client.get(f"/api/captures/{cid}/packets?q=port:no").status_code == 422


def test_retransmissions_tuple_reuse_and_ipv6(client):
    capture = analyze_capture(client, fixture.fixtures()["syn-retransmissions"])
    assert client.get(f"/api/captures/{capture['id']}/flows").json()["total"] == 1
    capture = analyze_capture(client, fixture.fixtures()["periodic"])
    assert client.get(f"/api/captures/{capture['id']}/flows").json()["total"] == 8
    capture = analyze_capture(client, fixture.fixtures()["ipv6"])
    hosts = client.get(f"/api/captures/{capture['id']}/hosts").json()["items"]
    assert {host["ip"] for host in hosts} == {"2001:db8::10", "2001:db8::20"}


def test_empty_malformed_and_unknown(client):
    capture = analyze_capture(client, [])
    assert capture["packet_count"] == 0 and "Empty capture" in capture["warnings"][0]
    capture = analyze_capture(client, [(fixture.EPOCH, b"\x00")])
    assert capture["warnings"] and capture["packet_count"] == 1
    assert client.get(f"/api/captures/{capture['id']}/packets").json()["items"][0]["protocol"] == "Malformed"
