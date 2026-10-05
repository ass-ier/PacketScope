import json

import stix2

from app.services.ioc import normalize
from test_engine import analyze_capture, fixture
from test_protocols import items


def test_normalization():
    assert normalize("domain", "EXAMPLE.Test.") == "example.test"
    assert normalize("ipv6", "2001:0db8:0:0::1") == "2001:db8::1"
    assert normalize("url", "HTTP://Example.Test:80/file#fragment") == "http://example.test/file"
    assert normalize("domain", "198.51.100.1") is None
    assert normalize("url", "javascript:alert(1)") is None
    assert normalize("domain", "invalid\n.test") is None


def test_ioc_dedup_evidence_search_and_exports(client):
    capture = analyze_capture(client, fixture.dns_pair() + fixture.conversation(start=1) + fixture.fixtures()["normal-tls"])
    cid = capture["id"]
    iocs = items(client, cid, "iocs")
    domains = [ioc for ioc in iocs if ioc["type"] == "domain" and ioc["value"] == "fixture.test"]
    assert len(domains) == 1
    detail = client.get(f"/api/entities/iocs/{domains[0]['id']}").json()
    assert len(detail["evidence"]) >= 3 and detail["flows"] and detail["hosts"]
    assert all(e["capture_id"] == cid and e["frame_number"] > 0 for e in detail["evidence"])
    search = client.get("/api/search?q=fixture.test").json()["results"]
    assert {entry["kind"] for entry in search} >= {"captures", "dns", "http", "tls", "iocs"}
    assert "fixture.test" in client.get(f"/api/captures/{cid}/iocs/export?format=txt").text
    assert "capture_sha256" in client.get(f"/api/captures/{cid}/iocs/export?format=csv").text
    assert client.get(f"/api/captures/{cid}/iocs/export?format=json").json()["classification"] == "observed"
    response = client.get(f"/api/captures/{cid}/iocs/export?format=stix")
    bundle = stix2.parse(response.text, allow_custom=True)
    types = {obj.type for obj in bundle.objects}
    assert "observed-data" in types and "indicator" not in types
    assert "x-packetscope-fingerprint" in types
    assert any(capture["sha256"] in json.dumps(obj) for obj in response.json()["objects"])


def test_observed_email_hashes_and_stix_file_semantics(client):
    payload = (b"GET /artifact HTTP/1.1\r\nHost: fixture.test\r\nFrom: +analyst@example.test\r\n"
               b"X-Observed-MD5: " + b"a"*32 + b"\r\nX-Observed-SHA1: " + b"b"*40 +
               b"\r\nX-Observed-SHA256: " + b"c"*64 + b"\r\n\r\n")
    capture = analyze_capture(client, [(fixture.EPOCH, fixture.packet(payload=payload))])
    cid = capture["id"]
    values = {(i["type"], i["value"]) for i in items(client, cid, "iocs")}
    assert values >= {("email","+analyst@example.test"), ("md5","a"*32), ("sha1","b"*40), ("sha256","c"*64)}
    csv = client.get(f"/api/captures/{cid}/iocs/export?format=csv").text
    assert "'+analyst@example.test" in csv
    parsed = stix2.parse(client.get(f"/api/captures/{cid}/iocs/export?format=stix").text, allow_custom=True)
    assert len([obj for obj in parsed.objects if obj.type == "file"]) == 3
