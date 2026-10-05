import dpkt
from sqlalchemy import select

from app.models import DNSAnswer, DNSQuery, PacketSummary, Session, uid
from app.services.packets import ip_text, read_packet
from app.services.reassembly import tcp_streams

TYPES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 2: "NS", 16: "TXT", 12: "PTR", 33: "SRV"}


def answer_value(answer):
    if answer.type in (1, 28):
        return ip_text(answer.ip if answer.type == 1 else answer.ip6)
    if answer.type == 5:
        return answer.cname
    if answer.type == 2:
        return answer.nsname
    if answer.type == 12:
        return answer.ptrname
    if answer.type == 15:
        preference = answer.preference[0] if isinstance(answer.preference, tuple) else answer.preference
        return f"{preference} {answer.mxname}"
    if answer.type == 16:
        return " ".join(part.decode("utf-8", "replace") if isinstance(part, bytes) else part for part in answer.text)[:4096]
    if answer.type == 33:
        return f"{answer.priority} {answer.weight} {answer.port} {answer.srvname}"
    return bytes(answer.rdata).hex()[:512]


def analyze_dns(db, path, flow, settings):
    pending = {}
    warnings = []
    if flow.protocol == "TCP":
        messages = []
        for stream in tcp_streams(db, path, flow, settings):
            warnings.extend(stream.warnings)
            offset = 0
            while offset + 2 <= len(stream.data):
                length = int.from_bytes(stream.data[offset:offset + 2], "big")
                if offset + 2 + length > len(stream.data):
                    warnings.append("Truncated DNS-over-TCP message")
                    break
                messages.append((stream.packet_at(offset), stream.data[offset + 2:offset + 2 + length]))
                offset += 2 + length
        messages.sort(key=lambda item: item[0].frame_number)
    else:
        def datagrams():
            for packet in db.scalars(select(PacketSummary).where(PacketSummary.flow_id == flow.id)
                                     .order_by(PacketSummary.frame_number)).yield_per(256):
                (_, payload), _ = read_packet(path, packet)
                yield packet, payload
        messages = datagrams()
    for index, (packet, payload) in enumerate(messages):
        if index % 128 == 0:
            db.flush()
        if not payload:
            continue
        try:
            message = dpkt.dns.DNS(payload)
            if not message.qd or len(message.qd) > 32 or len(message.an) > 256:
                warnings.append(f"DNS question/answer limit or missing question at frame {packet.frame_number}")
                continue
            for question in message.qd:
                name = question.name.rstrip(".").lower()
                query_type = TYPES.get(question.type, str(question.type))
                client = (packet.destination_ip, packet.destination_port) if message.qr else (packet.source_ip, packet.source_port)
                server = (packet.source_ip, packet.source_port) if message.qr else (packet.destination_ip, packet.destination_port)
                key = (flow.protocol, client, server, message.id, name, question.type)
                if not message.qr:
                    session = Session(id=uid(), capture_id=flow.capture_id, flow_id=flow.id, protocol="DNS",
                                      timestamp=packet.timestamp, frame_number=packet.frame_number,
                                      end_frame=packet.frame_number, status="query observed",
                                      metadata_fields={"transaction_id": message.id})
                    db.add(session)
                    db.flush()
                    query = DNSQuery(id=uid(), capture_id=flow.capture_id, session_id=session.id, flow_id=flow.id,
                                     frame_number=packet.frame_number, timestamp=packet.timestamp,
                                     source_ip=client[0], server_ip=server[0], transaction_id=message.id,
                                     name=name, query_type=query_type)
                    db.add(query)
                    pending.setdefault(key, []).append((query, session))
                else:
                    candidates = pending.get(key, [])
                    match = next(((q, s) for q, s in candidates if 0 <= packet.timestamp - q.timestamp <= 30
                                  and q.response_frame is None), None)
                    if match is None:
                        db.add(Session(capture_id=flow.capture_id, flow_id=flow.id, protocol="DNS",
                                       timestamp=packet.timestamp, frame_number=packet.frame_number,
                                       end_frame=packet.frame_number, status="unmatched response",
                                       metadata_fields={"name": name, "transaction_id": message.id,
                                                        "answers": [answer_value(a) for a in message.an]}))
                        warnings.append(f"Unmatched DNS response at frame {packet.frame_number}")
                        continue
                    query, session = match
                    query.response_frame, query.response_code = packet.frame_number, message.rcode
                    query.response_time = packet.timestamp - query.timestamp
                    session.end_frame, session.status = packet.frame_number, "response correlated"
                    db.flush()
                    for answer in message.an:
                        db.add(DNSAnswer(capture_id=flow.capture_id, query_id=query.id,
                                         frame_number=packet.frame_number, name=answer.name.rstrip(".").lower(),
                                         type=TYPES.get(answer.type, str(answer.type)),
                                         value=answer_value(answer), ttl=answer.ttl))
            flow.application, flow.identification = "DNS", "content"
        except (dpkt.UnpackError, ValueError, IndexError, UnicodeError) as exc:
            warnings.append(f"DNS decode incomplete at frame {packet.frame_number}: {type(exc).__name__}")
    return sorted(set(warnings))
