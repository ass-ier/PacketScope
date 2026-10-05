import hashlib
import io

import pytest
import stix2
from pypdf import PdfReader

from test_engine import analyze_capture, fixture


@pytest.mark.parametrize("format", ["pdf", "markdown", "json", "stix"])
def test_reports_preserve_evidence_and_analyst_assessment(client, format):
    capture = analyze_capture(client, fixture.fixtures()["port-scan"] + fixture.dns_pair(start=4))
    case = client.post("/api/cases", json={"title":"Report fixture investigation"}).json()
    client.post(f"/api/cases/{case['id']}/links", json={"kind":"capture", "entity_id":capture["id"]})
    client.patch(f"/api/cases/{case['id']}", json={"verdict":"Suspicious", "confidence":"Medium", "reasoning":"Verify authorized inventory before concluding compromise."})
    response = client.post("/api/reports", json={"capture_id":capture["id"], "case_id":case["id"], "format":format})
    assert response.status_code == 201, response.text
    report = response.json()
    download = client.get(f"/api/reports/{report['id']}/download")
    assert download.status_code == 200 and hashlib.sha256(download.content).hexdigest() == report["sha256"]
    if format == "pdf":
        reader = PdfReader(io.BytesIO(download.content))
        text = " ".join(" ".join(page.extract_text() for page in reader.pages).split())
        assert len(reader.pages) >= 2
    else:
        text = download.text
    assert capture["sha256"] in text
    assert "Verify authorized inventory" in text
    assert "port-scan" in text
    if format == "stix":
        parsed = stix2.parse(text, allow_custom=True)
        assert any(obj.type == "observed-data" for obj in parsed.objects)
        assert not any(obj.type == "indicator" for obj in parsed.objects)
    if format == "json":
        data = download.json()
        assert data["entities"]["Evidence"] and data["entities"]["Network Flows"]
        assert len(data["entities"]["Packet Summaries"]) == capture["packet_count"]
        assert data["analyst_assessment"]["verdict"] == "Suspicious"


def test_report_refuses_unlinked_case_and_changed_capture(client):
    capture = analyze_capture(client, fixture.conversation())
    case = client.post("/api/cases", json={"title":"Unlinked"}).json()
    assert client.post("/api/reports", json={"capture_id":capture["id"], "case_id":case["id"], "format":"json"}).status_code == 422
    path = client.app.state.settings.data_dir / "captures" / capture["filename"]
    path.write_bytes(path.read_bytes() + b"changed")
    assert client.post("/api/reports", json={"capture_id":capture["id"], "format":"json"}).status_code == 409
