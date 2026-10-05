import hashlib

import httpx

from app.services.intelligence import PROVIDERS
from test_engine import analyze_capture, fixture
from test_protocols import items


def test_comparison_and_explicit_safe_extraction(client):
    left = analyze_capture(client, fixture.dns_pair())
    right = analyze_capture(client, fixture.dns_pair("new.fixture.test") + fixture.conversation(start=1))
    comparison = client.post("/api/captures/compare", json={"baseline_id":left["id"], "comparison_id":right["id"]}).json()
    assert "new.fixture.test" in comparison["differences"]["domains"]["added"]["values"]
    http = items(client, right["id"], "http")[0]
    assert client.post(f"/api/http/{http['id']}/extract", json={}).status_code == 422
    response = client.post(f"/api/http/{http['id']}/extract", json={"acknowledge_untrusted":True})
    assert response.status_code == 201, response.text
    extracted = response.json()
    assert extracted["sha256"] == hashlib.sha256(b"Benign fixture\n").hexdigest()
    downloaded = client.get(f"/api/files/{extracted['id']}/download")
    assert downloaded.content == b"Benign fixture\n"
    assert "attachment" in downloaded.headers["content-disposition"]
    assert ".untrusted" in downloaded.headers["content-disposition"]
    assert downloaded.headers["content-type"] == "application/octet-stream"
    handoff = client.get(f"/api/files/{extracted['id']}/reversescope").json()
    assert handoff["sha256"] == extracted["sha256"] and "body" not in handoff
    assert handoff["capture_sha256"] == right["sha256"]
    assert client.post(f"/api/http/{http['id']}/extract", json={"acknowledge_untrusted":True}).json()["id"] == extracted["id"]


def test_truncated_body_not_extractable(client):
    data = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"
    capture = analyze_capture(client, [(fixture.EPOCH, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=80, dport=40000, payload=data))])
    http = items(client, capture["id"], "http")[0]
    assert not http["body_complete"]
    assert client.post(f"/api/http/{http['id']}/extract", json={"acknowledge_untrusted":True}).status_code == 409


def test_intelligence_off_and_mocked_explicit_success_failure(client, monkeypatch):
    capture = analyze_capture(client, fixture.dns_pair())
    ioc = next(i for i in items(client, capture["id"], "iocs") if i["type"] == "domain")
    assert not client.get("/api/intelligence/providers").json()["external_enabled"]
    assert client.post(f"/api/iocs/{ioc['id']}/lookup", json={"provider":"dns", "consent_to_share_indicator":True}).status_code == 409
    monkeypatch.setenv("PACKETSCOPE_EXTERNAL_ENABLED", "true")
    monkeypatch.setattr(PROVIDERS["dns"], "lookup", lambda _: {"status":0, "answers":[]})
    assert client.post(f"/api/iocs/{ioc['id']}/lookup", json={"provider":"dns"}).status_code == 422
    response = client.post(f"/api/iocs/{ioc['id']}/lookup", json={"provider":"dns", "consent_to_share_indicator":True})
    assert response.status_code == 200 and response.json()["result"] == {"status":0, "answers":[]}
    def fail(_):
        raise httpx.ConnectError("Synthetic network failure")
    monkeypatch.setattr(PROVIDERS["dns"], "lookup", fail)
    assert client.post(f"/api/iocs/{ioc['id']}/lookup", json={"provider":"dns", "consent_to_share_indicator":True}).status_code == 502
    assert client.get(f"/api/iocs/{ioc['id']}/intelligence").json()[0]["status"] == "failed"
