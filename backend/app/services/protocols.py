import socket
import struct
import logging
from collections import Counter

import dpkt
from sqlalchemy import select

from app.models import Flow, Host, PacketSummary, Session
from app.services.dns import analyze_dns
from app.services.http import analyze_http
from app.services.packets import mac, read_packet
from app.services.reassembly import tcp_streams
from app.services.tls import analyze_tls

log = logging.getLogger("packetscope.protocols")


def analyze_other(db, path, flow, settings):
    warnings = []
    if flow.application == "SMB" and flow.protocol == "TCP":
        observed = False
        for stream in tcp_streams(db, path, flow, settings):
            warnings.extend(stream.warnings)
            if len(stream.data) < 36:
                continue
            data, packet = stream.data[4:], stream.packet_at(0)
            fields = None
            if data[:4] == b"\xfeSMB" and len(data) >= 64:
                fields = {"version": "SMB2/3 header", "command": int.from_bytes(data[12:14], "little"),
                          "status": hex(int.from_bytes(data[8:12], "little")),
                          "session_id": str(int.from_bytes(data[40:48], "little")),
                          "visibility": "Header observed; no successful authentication or file access inferred"}
            elif data[:4] == b"\xffSMB" and len(data) >= 32:
                fields = {"version": "SMB1", "command": data[4], "user_id": int.from_bytes(data[28:30], "little"),
                          "visibility": "Header observed only"}
            if fields:
                observed = True
                db.add(Session(capture_id=flow.capture_id, flow_id=flow.id, protocol="SMB",
                               timestamp=packet.timestamp, frame_number=packet.frame_number, end_frame=packet.frame_number,
                               status="header observed", metadata_fields=fields))
        if not observed:
            warnings.append("SMB header unavailable or unconfirmed; no session success inferred")
        return warnings
    if flow.application not in ("ARP", "DHCP", "ICMP", "ICMPv6"):
        if flow.identification == "port hint":
            return [f"{flow.application} identified by port only; no content dissector confirmed it"]
        if flow.application in ("TCP", "UDP") and flow.payload_sent + flow.payload_received:
            return ["Unknown application protocol; transport evidence only"]
        return []
    for index, packet in enumerate(db.scalars(select(PacketSummary).where(PacketSummary.flow_id == flow.id)
                                              .order_by(PacketSummary.frame_number)).yield_per(256)):
        if index % 256 == 0:
            db.flush()
        fields = packet.metadata_fields.get("arp") or packet.metadata_fields.get("icmp")
        if flow.application == "DHCP":
            try:
                (_, payload), _ = read_packet(path, packet)
                dhcp = dpkt.dhcp.DHCP(payload)
                options = dict(dhcp.opts)
                fields = {"operation": dhcp.op, "transaction_id": dhcp.xid, "client_mac": mac(dhcp.chaddr[:dhcp.hln]),
                          "assigned_ip": socket.inet_ntoa(struct.pack("!I", dhcp.yiaddr)),
                          "hostname": options.get(12, b"").decode("utf-8", "replace")[:255],
                          "requested_ip": socket.inet_ntoa(options[50]) if len(options.get(50, b"")) == 4 else None,
                          "server": socket.inet_ntoa(options[54]) if len(options.get(54, b"")) == 4 else None,
                          "lease_seconds": int.from_bytes(options[51], "big") if len(options.get(51, b"")) == 4 else None}
                if fields["hostname"]:
                    host = db.scalar(select(Host).where(Host.capture_id == flow.capture_id,
                                                       Host.ip == fields["assigned_ip"]))
                    if host:
                        host.hostname = fields["hostname"]
            except (dpkt.UnpackError, ValueError, OSError) as exc:
                warnings.append(f"DHCP decode incomplete at frame {packet.frame_number}: {type(exc).__name__}")
        if fields:
            db.add(Session(capture_id=flow.capture_id, flow_id=flow.id, protocol=flow.application,
                           timestamp=packet.timestamp, frame_number=packet.frame_number, end_frame=packet.frame_number,
                           status="observed metadata", metadata_fields=fields))
    return warnings


PARSERS = {"DNS": analyze_dns, "HTTP": analyze_http, "TLS": analyze_tls}


def analyze_protocols(db, capture, path, settings, checkpoint):
    warnings = Counter()
    flows = db.scalars(select(Flow).where(Flow.capture_id == capture.id).order_by(Flow.start_time)).all()
    for index, flow in enumerate(flows):
        checkpoint()
        parser = PARSERS.get(flow.application, analyze_other)
        if flow.application in ("HTTP", "TLS") and flow.protocol != "TCP":
            notes = [f"{flow.application} on non-TCP transport is a port hint only; dissector unavailable"]
        else:
            try:
                with db.begin_nested():
                    notes = parser(db, path, flow, settings)
            except (dpkt.UnpackError, dpkt.ssl.SSL3Exception, ValueError, struct.error, UnicodeError, IndexError) as exc:
                log.warning("Protocol parser failed for flow %s: %s", flow.id, type(exc).__name__)
                notes = [f"{flow.application} parser failed ({type(exc).__name__}); transport evidence retained"]
        for note in notes:
            warnings[note] += 1
        if notes:
            flow.reconstruction = "; ".join(notes)[:1000]
        elif flow.application in PARSERS or flow.application in ("SMB", "ARP", "DHCP", "ICMP", "ICMPv6"):
            flow.reconstruction = "Available metadata indexed"
        else:
            flow.reconstruction = "Transport summary only; application stream reconstruction not attempted"
        if index % 100 == 0:
            capture.progress = 65 + int(15 * index / max(1, len(flows)))
            db.commit()
    capture.warnings = capture.warnings + [f"{note} ({count} flows)" for note, count in list(warnings.items())[:100]]
    if len(warnings) > 100:
        capture.warnings += [f"{len(warnings) - 100} additional warning types; inspect flow reconstruction fields"]
    db.commit()
