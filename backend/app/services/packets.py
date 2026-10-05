import math
import socket
import struct
from dataclasses import dataclass

import dpkt

from app.services.capture import MAGICS


@dataclass
class Frame:
    number: int
    timestamp: float
    offset: int
    captured_length: int
    length: int
    link_type: int
    data: bytes
    warning: str | None = None


def exact(handle, size):
    value = handle.read(size)
    if len(value) != size:
        raise ValueError(f"Truncated capture at byte {handle.tell()}")
    return value


def frames(path, settings):
    """Bounded framing with offsets; dpkt decodes the packet contents."""
    size = path.stat().st_size
    with path.open("rb") as handle:
        magic = exact(handle, 4)
        handle.seek(0)
        if magic in MAGICS:
            endian, scale = MAGICS[magic]
            header = exact(handle, 24)
            link_type = struct.unpack(endian + "I", header[20:24])[0] & 0xFFFF
            number = 0
            while handle.tell() < size:
                sec, fraction, caplen, wirelen = struct.unpack(endian + "IIII", exact(handle, 16))
                if fraction >= scale:
                    raise ValueError("Invalid PCAP fractional timestamp")
                if caplen > settings.max_frame_bytes or wirelen > settings.max_frame_bytes or caplen > wirelen:
                    raise ValueError("Invalid or over-limit PCAP frame length")
                number += 1
                if number > settings.max_packets:
                    raise ValueError(f"Packet limit exceeded ({settings.max_packets})")
                offset = handle.tell()
                yield Frame(number, sec + fraction / scale, offset, caplen, wirelen, link_type,
                            exact(handle, caplen), "Snapshot-truncated frame" if caplen < wirelen else None)
            return
        interfaces = []
        endian = "<"
        number = 0
        while handle.tell() < size:
            start = handle.tell()
            header = exact(handle, 8)
            if header[:4] == b"\x0a\x0d\x0d\x0a":
                bom = exact(handle, 4)
                if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                    raise ValueError("Invalid PCAPNG byte-order magic")
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                block_type = 0x0A0D0D0A
                interfaces = []
            else:
                block_type = struct.unpack(endian + "I", header[:4])[0]
            length = struct.unpack(endian + "I", header[4:8])[0]
            if length < 12 or length % 4 or start + length > size:
                raise ValueError("Truncated or invalid PCAPNG block")
            if length > settings.max_frame_bytes + 1024 * 1024:
                raise ValueError("PCAPNG block resource limit exceeded")
            handle.seek(start + length - 4)
            if exact(handle, 4) != header[4:8]:
                raise ValueError("PCAPNG trailing block length mismatch")
            handle.seek(start + 8)
            if block_type == 0x0A0D0D0A:
                if length < 28:
                    raise ValueError("Invalid PCAPNG section length")
                handle.seek(start + 12)
                if struct.unpack(endian + "H", exact(handle, 2))[0] != 1:
                    raise ValueError("Unsupported PCAPNG section version")
            elif block_type == 1:
                if length < 20 or len(interfaces) >= 256:
                    raise ValueError("Invalid or excessive PCAPNG interfaces")
                link, _, snaplen = struct.unpack(endian + "HHI", exact(handle, 8))
                resolution, time_offset = 1e-6, 0
                while handle.tell() + 4 <= start + length - 4:
                    code, option_length = struct.unpack(endian + "HH", exact(handle, 4))
                    if code == 0:
                        break
                    if handle.tell() + ((option_length + 3) // 4) * 4 > start + length - 4:
                        raise ValueError("Invalid PCAPNG interface option")
                    value = exact(handle, option_length)
                    handle.seek((-option_length) % 4, 1)
                    if code == 9 and option_length == 1:
                        exponent = value[0]
                        resolution = (2 if exponent & 0x80 else 10) ** -(exponent & 0x7F)
                    elif code == 14 and option_length == 8:
                        time_offset = struct.unpack(endian + "q", value)[0]
                interfaces.append((link, snaplen, resolution, time_offset))
            elif block_type in (2, 3, 6):
                if not interfaces:
                    raise ValueError("PCAPNG packet has no interface")
                warning = None
                if block_type == 3:
                    if length < 16:
                        raise ValueError("Invalid simple packet block")
                    wirelen = struct.unpack(endian + "I", exact(handle, 4))[0]
                    interface, high, low = 0, 0, 0
                    caplen = min(wirelen, interfaces[0][1] or wirelen)
                    warning = "PCAPNG simple packet has no timestamp; time-based detection excluded"
                else:
                    if length < 32:
                        raise ValueError("Invalid PCAPNG packet block")
                    raw = exact(handle, 20)
                    interface, high, low, caplen, wirelen = struct.unpack(endian + "IIIII", raw)
                    if block_type == 2:
                        interface = struct.unpack(endian + "H", raw[:2])[0]
                if interface >= len(interfaces):
                    raise ValueError("PCAPNG packet references an unknown interface")
                link, _, resolution, time_offset = interfaces[interface]
                if caplen > settings.max_frame_bytes or wirelen > settings.max_frame_bytes or caplen > wirelen:
                    raise ValueError("Invalid or over-limit PCAPNG frame length")
                if handle.tell() + ((caplen + 3) // 4) * 4 > start + length - 4:
                    raise ValueError("Truncated PCAPNG packet")
                timestamp = ((high << 32) | low) * resolution + time_offset if block_type != 3 else 0.0
                if not math.isfinite(timestamp) or timestamp < 0 or timestamp > 253402300799:
                    raise ValueError("Unsupported packet timestamp")
                number += 1
                if number > settings.max_packets:
                    raise ValueError(f"Packet limit exceeded ({settings.max_packets})")
                offset = handle.tell()
                yield Frame(number, timestamp, offset, caplen, wirelen, link, exact(handle, caplen),
                            warning or ("Snapshot-truncated frame" if caplen < wirelen else None))
            handle.seek(start + length)


PORT_HINTS = {21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP",
              110: "POP3", 123: "NTP", 143: "IMAP", 443: "TLS", 445: "SMB", 8080: "HTTP"}


def mac(value):
    return ":".join(f"{b:02x}" for b in value)


def ip_text(value):
    return socket.inet_ntop(socket.AF_INET6 if len(value) == 16 else socket.AF_INET, value)


def identify(payload, transport, sport, dport):
    if payload.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"HTTP/")):
        return "HTTP", "content"
    if len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4:
        return "TLS", "content"
    if payload.startswith(b"SSH-"):
        return "SSH", "content"
    if payload[4:8] in (b"\xffSMB", b"\xfeSMB"):
        return "SMB", "content"
    for port in (dport, sport):
        if port in PORT_HINTS:
            return PORT_HINTS[port], "port hint"
    return transport, "transport"


def decode(data, link_type):
    fields = {"source_mac": None, "destination_mac": None, "source_ip": None, "destination_ip": None,
              "source_port": None, "destination_port": None, "protocol": "Unknown", "transport": "",
              "ip_version": None, "flags": 0, "payload_length": 0, "metadata_fields": {}}
    metadata = fields["metadata_fields"]
    payload = b""
    try:
        if link_type == 1:
            link = dpkt.ethernet.Ethernet(data)
            fields.update(source_mac=mac(link.src), destination_mac=mac(link.dst))
            network = link.data
            metadata["ethernet_type"] = f"0x{link.type:04x}"
        elif link_type in (101, 228, 229):
            network = dpkt.ip6.IP6(data) if data and data[0] >> 4 == 6 else dpkt.ip.IP(data)
        elif link_type == 113:
            network = dpkt.sll.SLL(data).data
        elif link_type == 276:
            network = dpkt.sll2.SLL2(data).data
        elif link_type in (0, 108):
            raw = data[4:]
            network = dpkt.ip6.IP6(raw) if raw and raw[0] >> 4 == 6 else dpkt.ip.IP(raw)
        else:
            metadata["warning"] = f"Unsupported link-layer type {link_type}"
            return fields, payload
        if isinstance(network, dpkt.arp.ARP):
            fields["protocol"] = "ARP"
            if len(network.spa) == 4 and len(network.tpa) == 4:
                fields.update(source_ip=ip_text(network.spa), destination_ip=ip_text(network.tpa))
            metadata["arp"] = {"operation": network.op, "sender_ip": fields["source_ip"],
                               "target_ip": fields["destination_ip"], "sender_mac": mac(network.sha),
                               "target_mac": mac(network.tha)}
            return fields, payload
        if not isinstance(network, (dpkt.ip.IP, dpkt.ip6.IP6)):
            metadata["warning"] = "Unrecognized network protocol; raw evidence retained"
            return fields, payload
        fields.update(source_ip=ip_text(network.src), destination_ip=ip_text(network.dst),
                      ip_version=network.v, protocol=f"IPv{network.v}")
        metadata["ip"] = {"version": network.v, "hop_limit": getattr(network, "ttl", getattr(network, "hlim", 0))}
        if isinstance(network, dpkt.ip.IP):
            metadata["ip"].update(id=network.id, length=network.len)
            if network.len and network.len > len(network):
                metadata["warning"] = "IP datagram shorter than declared length"
            fragmented = bool(network.offset or network.mf)
        else:
            if network.plen > len(network) - 40:
                metadata["warning"] = "IPv6 payload shorter than declared length"
            fragmented = 44 in getattr(network, "extension_hdrs", {})
        if fragmented:
            metadata["warning"] = "Fragmented IP datagram: transport reconstruction unavailable"
            return fields, payload
        segment = network.data
        if isinstance(segment, (dpkt.tcp.TCP, dpkt.udp.UDP)):
            protocol = "TCP" if isinstance(segment, dpkt.tcp.TCP) else "UDP"
            payload = bytes(segment.data)
            application, identification = identify(payload, protocol, segment.sport, segment.dport)
            fields.update(source_port=segment.sport, destination_port=segment.dport, transport=protocol,
                          protocol=application, payload_length=len(payload))
            metadata["identification"] = identification
            if protocol == "TCP":
                fields["flags"] = segment.flags
                metadata["tcp"] = {"sequence": segment.seq, "acknowledgment": segment.ack,
                                   "flags": segment.flags, "window": segment.win}
            else:
                metadata["udp"] = {"length": segment.ulen}
                if segment.ulen > len(segment):
                    metadata["warning"] = "UDP datagram shorter than declared length"
        elif isinstance(segment, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
            fields["protocol"] = fields["transport"] = "ICMPv6" if network.v == 6 else "ICMP"
            metadata["icmp"] = {"type": segment.type, "code": segment.code}
            payload = bytes(segment.data)
            fields["payload_length"] = len(payload)
        else:
            metadata["warning"] = "Unrecognized transport protocol; no application content inferred"
    except (dpkt.UnpackError, ValueError, IndexError, struct.error, OSError) as exc:
        fields["protocol"] = "Malformed"
        metadata["warning"] = f"Packet decode incomplete: {type(exc).__name__}"
    return fields, payload


def read_packet(path, packet):
    with path.open("rb") as handle:
        handle.seek(packet.offset)
        data = exact(handle, packet.captured_length)
    return decode(data, packet.link_type), data
