"""Benign, deterministic offline traffic. Never sends packets."""
import argparse
import io
import json
import socket
import struct
from pathlib import Path

import dpkt

EPOCH = 1735689600.0
CLIENT, SERVER, DNS = "10.0.0.10", "198.51.100.20", "10.0.0.53"


def packet(src=CLIENT, dst=SERVER, sport=40000, dport=80, payload=b"", flags=dpkt.tcp.TH_ACK,
           seq=100, ack=0, udp=False, ipv6=False):
    transport = dpkt.udp.UDP(sport=sport, dport=dport, data=payload) if udp else dpkt.tcp.TCP(
        sport=sport, dport=dport, seq=seq, ack=ack, flags=flags, data=payload)
    if udp:
        transport.ulen = len(transport)
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    network_type = dpkt.ip6.IP6 if ipv6 else dpkt.ip.IP
    network = network_type(src=socket.inet_pton(family, src), dst=socket.inet_pton(family, dst), data=transport)
    if ipv6:
        network.nxt, network.plen = (17 if udp else 6), len(transport)
    else:
        network.p, network.len = (17 if udp else 6), len(network)
    eth = dpkt.ethernet.Ethernet(src=b"\x02\x00\x00\x00\x00\x10", dst=b"\x02\x00\x00\x00\x00\x20",
                                type=0x86DD if ipv6 else 0x0800, data=network)
    return bytes(eth)


def conversation(start=0, sport=40000, initial=100, body=b"Benign fixture\n"):
    request = b"GET /evidence.txt HTTP/1.1\r\nHost: fixture.test\r\nUser-Agent: Fixture/1.0\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    return [(EPOCH + start + offset, data) for offset, data in [
        (0, packet(sport=sport, seq=initial, flags=2)),
        (.01, packet(src=SERVER, dst=CLIENT, sport=80, dport=sport, seq=700, ack=initial + 1, flags=18)),
        (.02, packet(sport=sport, seq=initial + 1, ack=701)),
        (.03, packet(sport=sport, seq=initial + 1, ack=701, payload=request, flags=24)),
        (.04, packet(src=SERVER, dst=CLIENT, sport=80, dport=sport, seq=701, ack=initial + 1 + len(request), payload=response, flags=24)),
        (.05, packet(sport=sport, seq=initial + 1 + len(request), ack=701 + len(response), flags=17)),
        (.06, packet(src=SERVER, dst=CLIENT, sport=80, dport=sport, seq=701 + len(response), flags=17)),
    ]]


def dns_pair(name="fixture.test", src=CLIENT, sport=51000, tx=42, start=0, answer=SERVER, rcode=0):
    query = dpkt.dns.DNS(id=tx, qd=[dpkt.dns.DNS.Q(name=name, type=1)])
    response = dpkt.dns.DNS(id=tx, qr=1, rcode=rcode, qd=query.qd, an=[] if rcode else [
        dpkt.dns.DNS.RR(name=name, type=1, ttl=60, ip=socket.inet_aton(answer))])
    return [(EPOCH + start, packet(src=src, dst=DNS, sport=sport, dport=53, payload=bytes(query), udp=True)),
            (EPOCH + start + .01, packet(src=DNS, dst=src, sport=53, dport=sport, payload=bytes(response), udp=True))]


def encode(records, format="pcap"):
    buffer = io.BytesIO()
    writer = dpkt.pcapng.Writer(buffer) if format == "pcapng" else dpkt.pcap.Writer(buffer)
    for timestamp, data in records:
        writer.writepkt(data, ts=timestamp)
    return buffer.getvalue()


def tls_handshake(kind, body):
    message = bytes([kind]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message


def client_hello(name="fixture.test"):
    name_bytes = name.encode()
    sni = struct.pack("!H", len(name_bytes) + 3) + b"\x00" + struct.pack("!H", len(name_bytes)) + name_bytes
    extensions = b"\x00\x00" + struct.pack("!H", len(sni)) + sni
    extensions += b"\x00\x0a\x00\x04\x00\x02\x00\x17"
    extensions += b"\x00\x0b\x00\x02\x01\x00"
    body = b"\x03\x03" + bytes(range(32)) + b"\x00\x00\x04\x13\x01\x00\x2f\x01\x00"
    return tls_handshake(1, body + struct.pack("!H", len(extensions)) + extensions)


def arp_conflict():
    records = []
    for index in (1, 2):
        arp = dpkt.arp.ARP(op=2, sha=bytes([2, 0, 0, 0, 0, index]), spa=socket.inet_aton(CLIENT),
                           tha=bytes(6), tpa=socket.inet_aton(SERVER))
        records.append((EPOCH + index, bytes(dpkt.ethernet.Ethernet(type=0x806, data=arp))))
    return records


EXPECTATIONS = {
    "normal-dns": {"packets": 2, "flows": 1, "findings": []},
    "normal-http": {"packets": 7, "flows": 1, "findings": []},
    "normal-tls": {"packets": 1, "flows": 1, "findings": []},
    "port-scan": {"packets": 30, "flows": 30, "findings": ["port-scan"]},
    "periodic": {"packets": 56, "flows": 8, "findings": ["beacon"]},
    "syn-retransmissions": {"packets": 8, "flows": 1, "findings": []},
    "ipv6": {"packets": 1, "flows": 1, "findings": []},
    "large-transfer": {"packets": 128, "flows": 1, "findings": ["large-transfer"]},
    "dns-encoded": {"packets": 50, "flows": 1, "findings": ["dns-anomaly"]},
    "arp-conflict": {"packets": 2, "flows": 1, "findings": ["arp-conflict"]},
    "multiple-hosts": {"packets": 16, "flows": 16, "findings": ["host-scan"]},
    "mixed": {"packets": 11, "flows": 4, "findings": []},
}


def fixtures():
    return {
        "normal-dns": dns_pair(),
        "normal-http": conversation(),
        "normal-tls": [(EPOCH, packet(dport=443, payload=client_hello()))],
        "port-scan": [(EPOCH + i * .1, packet(dport=1000 + i, seq=i, flags=2)) for i in range(30)],
        "periodic": [entry for i in range(8) for entry in conversation(i * 60, initial=100 + i * 1000)],
        "syn-retransmissions": [(EPOCH + i * 60, packet(flags=2)) for i in range(8)],
        "ipv6": [(EPOCH, packet(src="2001:db8::10", dst="2001:db8::20", ipv6=True, flags=2))],
        "large-transfer": [(EPOCH+i*.01, packet(dport=9000, seq=100+i*48000, payload=b"benign" * 8000)) for i in range(128)],
        "dns-encoded": [r for i in range(25) for r in dns_pair(f"{i:04d}abcdefghijklmnopqrstuvwxyz0123456789.fixture.test", start=i, tx=i)],
        "arp-conflict": arp_conflict(),
        "multiple-hosts": [(EPOCH+i, packet(dst=f"10.0.1.{i+1}", flags=2)) for i in range(16)],
        "mixed": sorted(dns_pair() + conversation(start=1) +
                        [(EPOCH+2, packet(dport=443, payload=client_hello())),
                         (EPOCH+3, packet(src="2001:db8::10", dst="2001:db8::20", ipv6=True, flags=2))]),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path("artifacts/fixtures"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = {}
    for name, records in fixtures().items():
        for format in ("pcap", "pcapng"):
            (args.output / f"{name}.{format}").write_bytes(encode(records, format))
        manifest[name] = {"synthetic": True, "expected": EXPECTATIONS[name],
                          "packets": len(records), "wire_bytes": sum(len(data) for _, data in records),
                          "duration": records[-1][0] - records[0][0] if records else 0}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
