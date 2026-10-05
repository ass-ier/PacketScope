import socket

import dpkt

from test_engine import analyze_capture, fixture
from test_protocols import certificate_record, items


def test_scan_beacon_and_retransmission_negative(client):
    capture = analyze_capture(client, fixture.fixtures()["port-scan"])
    findings = items(client, capture["id"], "findings")
    scan = next(f for f in findings if f["rule_id"] == "port-scan")
    assert scan["statistics"]["distinct_ports"] >= 20
    detail = client.get(f"/api/entities/findings/{scan['id']}").json()
    assert len(detail["evidence"]) == scan["evidence_count"] and detail["flows"]
    assert all(e["frame_number"] > 0 and e["flow_id"] for e in detail["evidence"])
    capture = analyze_capture(client, fixture.fixtures()["periodic"])
    beacon = next(f for f in items(client, capture["id"], "findings") if f["rule_id"] == "beacon")
    assert beacon["statistics"]["intervals"] == [60] * 7
    assert "not proof of C2" in beacon["description"]
    capture = analyze_capture(client, fixture.fixtures()["syn-retransmissions"])
    assert not items(client, capture["id"], "findings")


def test_normal_negative_and_rule_configuration(client):
    capture = analyze_capture(client, fixture.conversation() + fixture.dns_pair(start=1) + fixture.fixtures()["normal-tls"])
    assert not items(client, capture["id"], "findings")
    response = client.patch("/api/rules/port-scan", json={"config": {"min_ports":10}})
    assert response.status_code == 200
    assert client.patch("/api/rules/port-scan", json={"config": {"min_ports":-1}}).status_code == 422
    assert client.patch("/api/rules/port-scan", json={"config": {"unknown":10}}).status_code == 422
    client.patch("/api/rules/port-scan", json={"enabled":False})
    capture = analyze_capture(client, fixture.fixtures()["port-scan"])
    assert not any(f["rule_id"] == "port-scan" for f in items(client, capture["id"], "findings"))


def test_host_dns_transfer_and_arp(client):
    host_records = [(fixture.EPOCH + i, fixture.packet(dst=f"10.0.1.{i+1}", flags=2)) for i in range(16)]
    capture = analyze_capture(client, host_records)
    assert any(f["rule_id"] == "host-scan" for f in items(client, capture["id"], "findings"))
    dns_records = [r for i in range(25) for r in fixture.dns_pair(f"{i:04d}abcdefghijklmnopqrstuvwxyz0123456789.fixture.test", start=i, tx=i)]
    capture = analyze_capture(client, dns_records)
    assert any(f["rule_id"] == "dns-anomaly" for f in items(client, capture["id"], "findings"))
    client.patch("/api/rules/large-transfer", json={"config": {"min_bytes":5000}})
    capture = analyze_capture(client, [(fixture.EPOCH, fixture.packet(payload=b"x" * 8000, dport=8888))])
    assert any(f["rule_id"] == "large-transfer" for f in items(client, capture["id"], "findings"))
    arps = []
    for i in (1, 2):
        arp = dpkt.arp.ARP(op=2, sha=bytes([2, 0, 0, 0, 0, i]), spa=socket.inet_aton(fixture.CLIENT),
                           tha=bytes(6), tpa=socket.inet_aton(fixture.SERVER))
        arps.append((fixture.EPOCH + i, bytes(dpkt.ethernet.Ethernet(type=0x806, data=arp))))
    capture = analyze_capture(client, arps)
    assert any(f["rule_id"] == "arp-conflict" for f in items(client, capture["id"], "findings"))


def test_http_indicator_and_capture_time_certificate(client):
    capture = analyze_capture(client, [(fixture.EPOCH, fixture.packet(payload=b"GET /?cmd=harmless HTTP/1.1\r\nHost: fixture.test\r\n\r\n"))])
    assert any(f["rule_id"] == "http-indicator" for f in items(client, capture["id"], "findings"))
    message, _ = certificate_record()
    capture = analyze_capture(client, [(fixture.EPOCH, fixture.packet(dport=443, payload=fixture.client_hello())),
                                       (fixture.EPOCH + .1, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=443, dport=40000, payload=message))])
    finding = next(f for f in items(client, capture["id"], "findings") if f["rule_id"] == "tls-certificate")
    assert "Expired at capture time" not in finding["statistics"]["reasons"]
    assert finding["statistics"]["capture_timestamp"] == fixture.EPOCH
