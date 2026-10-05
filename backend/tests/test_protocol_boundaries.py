import hashlib
import socket
import struct

import dpkt
import httpx
import pytest
import stix2

from app.services.intelligence import DNSProvider, RDAP, VirusTotal
from app.services.ioc import normalize
from test_engine import analyze_capture, fixture
from test_protocols import certificate_record, items


@pytest.mark.parametrize("kind,value", [
    (28, "2001:db8::44"), (5, "alias.fixture.test"), (15, "10 mail.fixture.test"),
    (2, "ns.fixture.test"), (16, "benign text"), (12, "host.fixture.test"), (33, "1 2 443 service.fixture.test"),
])
def test_supported_dns_answer_types(client, kind, value):
    question = dpkt.dns.DNS.Q(name="fixture.test", type=kind)
    query = dpkt.dns.DNS(id=10, qd=[question])
    fields = {
        28: {"ip6":socket.inet_pton(socket.AF_INET6, "2001:db8::44")}, 5: {"cname":value},
        15: {"preference":10, "mxname":"mail.fixture.test"}, 2: {"nsname":value},
        16: {"text":[b"benign text"]}, 12: {"ptrname":value},
        33: {"priority":1, "weight":2, "port":443, "srvname":"service.fixture.test"},
    }
    answer = dpkt.dns.DNS.RR(name="fixture.test", type=kind, ttl=123, **fields[kind])
    response = dpkt.dns.DNS(id=10, qr=1, qd=[question], an=[answer])
    records = [(fixture.EPOCH, fixture.packet(dst=fixture.DNS, sport=51000, dport=53, payload=bytes(query), udp=True)),
               (fixture.EPOCH+.1, fixture.packet(src=fixture.DNS, dst=fixture.CLIENT, sport=53, dport=51000, payload=bytes(response), udp=True))]
    capture = analyze_capture(client, records)
    dns = items(client, capture["id"], "dns")[0]
    actual = client.get(f"/api/entities/dns/{dns['id']}").json()["answers"][0]
    assert actual["value"] == value and actual["ttl"] == 123


def test_dns_over_tcp_and_unmatched_response(client):
    question = dpkt.dns.DNS(id=77, qd=[dpkt.dns.DNS.Q(name="tcp.fixture.test")])
    response = dpkt.dns.DNS(id=77, qr=1, qd=question.qd, an=[])
    query_bytes, response_bytes = bytes(question), bytes(response)
    records = [(fixture.EPOCH, fixture.packet(dport=53, payload=len(query_bytes).to_bytes(2, "big") + query_bytes)),
               (fixture.EPOCH+.1, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=53, dport=40000,
                                                payload=len(response_bytes).to_bytes(2, "big") + response_bytes))]
    capture = analyze_capture(client, records)
    assert items(client, capture["id"], "dns")[0]["response_code"] == 0
    capture = analyze_capture(client, [records[1]])
    assert not items(client, capture["id"], "dns")
    assert any("Unmatched DNS response" in w for w in capture["warnings"])


def test_chunked_and_pipelined_http_bodies(client):
    requests = b"GET /one HTTP/1.1\r\nHost: fixture.test\r\n\r\nGET /two HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
    responses = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\ntwo"
    capture = analyze_capture(client, [(fixture.EPOCH, fixture.packet(payload=requests)),
                                       (fixture.EPOCH+.1, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=80, dport=40000, payload=responses))])
    http = items(client, capture["id"], "http")
    assert len(http) == 2 and all(h["body_complete"] for h in http)
    for session in http:
        extracted = client.post(f"/api/http/{session['id']}/extract", json={"acknowledge_untrusted":True}).json()
        expected = session["uri"].strip("/").encode()
        assert client.get(f"/api/files/{extracted['id']}/download").content == expected


def test_tls_negotiated_version_and_exact_ja3(client):
    hello = b"\x03\x03" + bytes(32) + b"\x00\x13\x01\x00" + b"\x00\x06\x00\x2b\x00\x02\x03\x04"
    encrypted = b"\x17\x03\x03\x00\x04test"
    records = [(fixture.EPOCH, fixture.packet(dport=443, payload=fixture.client_hello())),
               (fixture.EPOCH+.1, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=443, dport=40000,
                                                payload=fixture.tls_handshake(2, hello) + encrypted))]
    capture = analyze_capture(client, records)
    tls = items(client, capture["id"], "tls")[0]
    expected = "771,4865-47,0-10-11,23,0"
    assert tls["ja3"] == hashlib.md5(expected.encode(), usedforsecurity=False).hexdigest()
    assert tls["version"] == "TLS 1.3" and tls["cipher_suite"] == "0x1301"
    assert tls["metadata_fields"]["encrypted_records_observed"]
    assert tls["metadata_fields"]["certificate_visibility"] == "unavailable"


def test_expired_certificate_capture_time_and_stix_certificate(client):
    message, cert = certificate_record()
    after_expiry = 1767225600.0
    records = [(after_expiry, fixture.packet(dport=443, payload=fixture.client_hello())),
               (after_expiry+.1, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=443, dport=40000, payload=message))]
    capture = analyze_capture(client, records)
    finding = next(f for f in items(client, capture["id"], "findings") if f["rule_id"] == "tls-certificate")
    assert "Expired at capture time" in finding["statistics"]["reasons"]
    bundle = stix2.parse(client.get(f"/api/captures/{capture['id']}/iocs/export?format=stix").text, allow_custom=True)
    assert any(obj.type == "x509-certificate" for obj in bundle.objects)


def test_suspicious_connection_requires_combined_context(client):
    records = []
    for i in range(3):
        records += [(fixture.EPOCH+i*20, fixture.packet(dport=4444, sport=42000+i, payload=b"benign "*100, seq=100)),
                    (fixture.EPOCH+i*20+.1, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=4444,
                                                          dport=42000+i, payload=b"response", seq=700))]
    capture = analyze_capture(client, records)
    assert any(f["rule_id"] == "suspicious-connection" for f in items(client, capture["id"], "findings"))
    capture = analyze_capture(client, [records[0]])
    assert not items(client, capture["id"], "findings")


def test_idle_tuple_separation_and_tcp_reset(client):
    records = [(fixture.EPOCH, fixture.packet(payload=b"benign", dport=9000)),
               (fixture.EPOCH+121, fixture.packet(payload=b"benign", dport=9000, seq=1000)),
               (fixture.EPOCH+122, fixture.packet(dport=9000, seq=1006, flags=4))]
    capture = analyze_capture(client, records)
    flows = items(client, capture["id"], "flows")
    assert len(flows) == 2 and any(flow["state"] == "reset" for flow in flows)


def test_big_endian_nanosecond_pcap(client):
    packet = fixture.packet(flags=2)
    content = struct.pack(">IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    content += struct.pack(">IIII", 1000, 123456789, len(packet), len(packet)) + packet
    capture = client.post("/api/captures", files={"file":("nano.pcap", content)}).json()
    client.post(f"/api/captures/{capture['id']}/analyze")
    from test_hardening import wait_status
    status = wait_status(client, capture["id"])
    assert status["analysis_status"] == "completed" and status["start_time"] == pytest.approx(1000.123456789)


def test_provider_adapters_use_only_mock_transport(monkeypatch):
    real_client = httpx.Client
    calls = []
    def handler(request):
        calls.append(request)
        if "arin.net" in request.url.host:
            return httpx.Response(200, json={"name":"TEST-NET", "country":"ZZ"})
        if "cloudflare" in request.url.host:
            return httpx.Response(200, json={"Status":3})
        return httpx.Response(200, json={"data":{"attributes":{"last_analysis_stats":{"harmless":1}}}})
    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(transport=transport, **kwargs))
    from types import SimpleNamespace
    assert RDAP().lookup(SimpleNamespace(value="198.51.100.1"))["name"] == "TEST-NET"
    assert DNSProvider().lookup(SimpleNamespace(value="fixture.test"))["status"] == 3
    monkeypatch.setenv("PACKETSCOPE_VT_API_KEY", "synthetic-not-a-secret")
    assert VirusTotal().lookup(SimpleNamespace(type="sha256", value="a"*64))["last_analysis_stats"]["harmless"] == 1
    assert all(request.method == "GET" for request in calls)
    assert normalize("email", "Analyst@EXAMPLE.TEST") == "Analyst@example.test"
