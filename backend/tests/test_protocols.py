import datetime
import socket
import struct

import dpkt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from test_engine import analyze_capture, fixture


def items(client, cid, collection):
    return client.get(f"/api/captures/{cid}/{collection}?limit=200").json()["items"]


def test_dns_endpoint_and_question_correlation(client):
    first = fixture.dns_pair("first.fixture.test", src="10.0.0.10", answer="198.51.100.21")
    second = fixture.dns_pair("second.fixture.test", src="10.0.0.11", answer="198.51.100.22")
    records = [first[0], second[0], second[1], first[1]]
    capture = analyze_capture(client, records)
    queries = items(client, capture["id"], "dns")
    assert len(queries) == 2
    for query in queries:
        answers = client.get(f"/api/entities/dns/{query['id']}").json()["answers"]
        assert answers[0]["value"] == ("198.51.100.21" if query["source_ip"] == "10.0.0.10" else "198.51.100.22")
        assert answers[0]["name"] == query["name"]


def test_http_out_of_order_retransmission_and_gap(client):
    payload = b"GET /safe HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
    prefix = [(fixture.EPOCH, fixture.packet(flags=2, seq=100))]
    packets = prefix + [(fixture.EPOCH + .1, fixture.packet(seq=121, payload=payload[20:])),
                        (fixture.EPOCH + .2, fixture.packet(seq=101, payload=payload[:20])),
                        (fixture.EPOCH + .3, fixture.packet(seq=101, payload=payload[:20]))]
    capture = analyze_capture(client, packets)
    requests = items(client, capture["id"], "http")
    assert len(requests) == 1 and requests[0]["uri"] == "/safe"
    capture = analyze_capture(client, prefix + packets[1:2])
    assert not items(client, capture["id"], "http")
    assert any("gap" in warning for warning in capture["warnings"])


def test_http_pairing_and_body_visibility(client):
    capture = analyze_capture(client, fixture.conversation())
    http = items(client, capture["id"], "http")[0]
    assert http["method"] == "GET" and http["status_code"] == 200
    assert http["body_complete"] and http["body_size"] == len(b"Benign fixture\n")
    assert http["response_frame"] == 5
    detail = client.get(f"/api/captures/{capture['id']}/packets/5").json()
    assert detail["protocol_evidence"]["HTTP messages"][0]["status_code"] == 200


def test_tls_clienthello_without_certificate(client):
    capture = analyze_capture(client, fixture.fixtures()["normal-tls"])
    tls = items(client, capture["id"], "tls")[0]
    assert tls["sni"] == "fixture.test"
    assert tls["version"] is None
    assert tls["metadata_fields"]["client_legacy_version"] == "TLS 1.2"
    assert tls["ja3"] is not None and len(tls["ja3"]) == 32
    assert tls["metadata_fields"]["certificate_visibility"] == "unavailable"
    assert not client.get(f"/api/entities/tls/{tls['id']}").json()["certificates"]


def certificate_record():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2025, 6, 1, tzinfo=datetime.UTC))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.test")]), critical=False)
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    certificates = len(der).to_bytes(3, "big") + der
    return fixture.tls_handshake(11, len(certificates).to_bytes(3, "big") + certificates), cert


def test_observable_tls_certificate(client):
    message, cert = certificate_record()
    records = [(fixture.EPOCH, fixture.packet(dport=443, payload=fixture.client_hello())),
               (fixture.EPOCH + .1, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=443,
                                                  dport=40000, payload=message, seq=700))]
    capture = analyze_capture(client, records)
    tls = items(client, capture["id"], "tls")[0]
    certificates = client.get(f"/api/entities/tls/{tls['id']}").json()["certificates"]
    assert len(certificates) == 1
    assert certificates[0]["sha256"] == cert.fingerprint(hashes.SHA256()).hex()
    assert certificates[0]["self_signed"] and certificates[0]["sans"] == ["fixture.test"]


def test_arp_dhcp_icmp_smb_metadata(client):
    arp = dpkt.arp.ARP(op=2, sha=b"\x02\x00\x00\x00\x00\x10", spa=socket.inet_aton(fixture.CLIENT),
                       tha=b"\x02\x00\x00\x00\x00\x20", tpa=socket.inet_aton(fixture.SERVER))
    arp_frame = bytes(dpkt.ethernet.Ethernet(type=0x806, data=arp))
    dhcp = dpkt.dhcp.DHCP(op=2, yiaddr=struct.unpack("!I", socket.inet_aton(fixture.CLIENT))[0],
                          opts=[(12, b"workstation"), (51, struct.pack("!I", 3600))])
    dhcp_frame = fixture.packet(src="10.0.0.1", dst="255.255.255.255", sport=67, dport=68,
                                udp=True, payload=bytes(dhcp))
    icmp = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"benign"))
    ip = dpkt.ip.IP(src=socket.inet_aton(fixture.CLIENT), dst=socket.inet_aton(fixture.SERVER), p=1, data=icmp)
    ip.len = len(ip)
    icmp_frame = bytes(dpkt.ethernet.Ethernet(type=0x800, data=ip))
    smb = b"\xfeSMB" + b"\x40\x00" + bytes(58)
    smb_frame = fixture.packet(dport=445, payload=len(smb).to_bytes(4, "big") + smb)
    capture = analyze_capture(client, [(fixture.EPOCH + i, p) for i, p in enumerate([arp_frame, dhcp_frame, icmp_frame, smb_frame])])
    sessions = items(client, capture["id"], "sessions")
    assert {s["protocol"] for s in sessions} >= {"ARP", "DHCP", "ICMP", "SMB"}
    assert any(s["metadata_fields"].get("hostname") == "workstation" for s in sessions)
