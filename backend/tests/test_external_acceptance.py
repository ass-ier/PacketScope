"""Optional independent fixtures supplied by the coordinating session, never bundled."""
import json
import os
import time
from pathlib import Path

import pytest

from test_protocols import items

ROOT = os.environ.get("PACKETSCOPE_ACCEPTANCE_FIXTURES")
pytestmark = pytest.mark.skipif(not ROOT, reason="Independent acceptance fixtures not configured")


@pytest.mark.parametrize("format", ["pcap", "pcapng"])
@pytest.mark.parametrize("name", ["normal", "dns-collision", "port-scan", "tuple-reuse", "syn-retransmissions"])
def test_independent_capture_semantics(client, name, format):
    root = Path(ROOT)
    manifest = json.loads((root / "manifest.json").read_text())["fixtures"][name]
    file = manifest["files"][format]
    response = client.post("/api/captures", files={"file":(file["filename"], (root / file["filename"]).read_bytes())})
    assert response.status_code == 201
    capture = response.json()
    assert capture["sha256"] == file["sha256"]
    client.post(f"/api/captures/{capture['id']}/analyze")
    for _ in range(500):
        capture = client.get(f"/api/captures/{capture['id']}").json()
        if capture["analysis_status"] in ("completed", "failed"):
            break
        time.sleep(.01)
    assert capture["analysis_status"] == "completed", capture
    assert capture["packet_count"] == manifest["packet_count"]
    assert capture["duration"] == pytest.approx(manifest["duration_seconds"], abs=1e-6)
    cid = capture["id"]
    flows = items(client, cid, "flows")
    assert sum(f["bytes_sent"] + f["bytes_received"] for f in flows) == manifest["wire_bytes"]
    findings = items(client, cid, "findings")
    if name == "normal":
        assert not findings
        http = items(client, cid, "http")
        assert len(http) == 1 and http[0]["status_code"] == 200 and http[0]["body_size"] == 3
        tls = items(client, cid, "tls")
        assert len(tls) == 1 and tls[0]["sni"] == "fixture.test"
        assert not items(client, cid, "certificates")
        assert len(items(client, cid, "dns")) == 1
    elif name == "dns-collision":
        for query in items(client, cid, "dns"):
            expected = manifest["expected"]["correlations"][query["source_ip"]]
            assert query["name"] == expected["name"]
            answers = client.get(f"/api/entities/dns/{query['id']}").json()["answers"]
            assert answers[0]["value"] == expected["answer"]
    elif name == "port-scan":
        assert any(f["rule_id"] == "port-scan" for f in findings)
        assert len({f["destination_port"] for f in flows}) == 50
    elif name == "tuple-reuse":
        assert len(flows) == 8 and len(items(client, cid, "http")) == 8
        beacon = next(f for f in findings if f["rule_id"] == "beacon")
        assert beacon["statistics"]["intervals"] == [60] * 7
    else:
        assert len(flows) == 1 and not findings
