import shlex

from fastapi import HTTPException
from sqlalchemy import func, or_, select

from app.models import Capture, Certificate, DNSAnswer, DNSQuery, Finding, Flow, Host, HTTPSession, IOC, PacketSummary, TLSSession


def record(obj):
    return {column.name: getattr(obj, column.name) for column in obj.__table__.columns}


def clauses(model, query="", start=None, end=None):
    result = []
    if query:
        try:
            tokens = shlex.split(query)
        except ValueError as exc:
            raise HTTPException(422, f"Invalid filter: {exc}") from exc
        for token in tokens:
            key, separator, value = token.partition(":")
            if not separator:
                key, value = "protocol", key
            if not value:
                raise HTTPException(422, "Filter value is required")
            if key == "host":
                names = ["source_ip", "destination_ip", "ip", "server_ip", "host"]
            elif key == "destination":
                names = ["destination_ip", "server_ip"]
            elif key == "port":
                try:
                    value = int(value)
                except ValueError as exc:
                    raise HTTPException(422, "Port must be an integer") from exc
                if not 0 <= value <= 65535:
                    raise HTTPException(422, "Port must be between 0 and 65535")
                names = ["source_port", "destination_port"]
            elif key == "protocol":
                names = ["protocol", "application", "transport"]
            elif key in ("severity", "flow_id", "finding_id", "type", "source_ip"):
                names = [key]
            else:
                raise HTTPException(422, f"Unsupported filter '{key}'; use host, destination, port, protocol, severity, flow_id, finding_id or type")
            columns = [getattr(model, name) for name in names if hasattr(model, name)]
            if not columns:
                raise HTTPException(422, f"Filter '{key}' is not available for this evidence type")
            result.append(or_(*[(func.lower(column) == str(value).lower()) if key == "protocol"
                               else column == value for column in columns]))
    time_column = next((getattr(model, name) for name in ("timestamp", "start_time", "first_seen")
                        if hasattr(model, name)), None)
    if time_column is not None:
        if start is not None:
            result.append(time_column >= start)
        if end is not None:
            result.append(time_column <= end)
    return result


def page(db, model, capture_id=None, query="", offset=0, limit=50, start=None, end=None):
    conditions = clauses(model, query, start, end)
    if capture_id:
        conditions.append(model.capture_id == capture_id)
    total = db.scalar(select(func.count()).select_from(model).where(*conditions))
    order = next((getattr(model, name) for name in ("timestamp", "frame_number", "start_time", "first_seen")
                  if hasattr(model, name)), model.id)
    rows = db.scalars(select(model).where(*conditions).order_by(order, model.id).offset(offset).limit(limit))
    return {"items": [record(row) for row in rows], "total": total, "offset": offset, "limit": limit}


def overview(db, capture_id=None):
    conditions = [PacketSummary.capture_id == capture_id] if capture_id else []
    identification = PacketSummary.metadata_fields["identification"].as_string()
    protocols = db.execute(select(PacketSummary.protocol, identification, func.count(), func.sum(PacketSummary.length))
                           .where(*conditions).group_by(PacketSummary.protocol, identification)
                           .order_by(func.count().desc())).all()
    hosts = select(Host)
    flows = select(Flow.destination_ip, func.sum(Flow.bytes_sent).label("bytes"),
                   func.count().label("connections"))
    if capture_id:
        hosts, flows = hosts.where(Host.capture_id == capture_id), flows.where(Flow.capture_id == capture_id)
    counts = {}
    for name, model in [("packets", PacketSummary), ("hosts", Host), ("flows", Flow), ("dns", DNSQuery),
                        ("http", HTTPSession), ("tls", TLSSession), ("iocs", IOC), ("findings", Finding)]:
        statement = select(func.count()).select_from(model)
        if capture_id:
            statement = statement.where(model.capture_id == capture_id)
        counts[name] = db.scalar(statement)
    versions = db.execute(select(PacketSummary.ip_version, func.count()).where(*conditions)
                          .group_by(PacketSummary.ip_version)).all()
    transports = db.execute(select(PacketSummary.transport, func.count()).where(*conditions)
                            .group_by(PacketSummary.transport)).all()
    top_hosts = list(db.scalars(hosts.order_by(Host.bytes_sent.desc()).limit(10)))
    capture_names = dict(db.execute(select(Capture.id, Capture.original_filename)
                                    .where(Capture.id.in_({host.capture_id for host in top_hosts}))).all())
    return {"counts": counts, "protocols": [{"protocol": p + (" (port hint)" if confidence == "port hint" else ""),
                                           "packets": n, "bytes": b} for p, confidence, n, b in protocols],
            "ip_versions": {str(v): n for v, n in versions},
            "transports": [{"protocol": p or "No transport decoded", "packets": n} for p, n in transports],
            "top_talkers": [{**record(row), "capture_name": capture_names[row.capture_id]} for row in top_hosts],
            "top_destinations": [{"id": ip, "destination_ip": ip, "bytes": b, "connections": n} for ip, b, n
                                 in db.execute(flows.group_by(Flow.destination_ip)
                                               .order_by(func.sum(Flow.bytes_sent).desc()).limit(10))],
            "byte_accounting": "Original wire frame lengths, including link layer and retransmissions. Payload counters are observed, not deduplicated."}


def packet_protocol_evidence(db, packet):
    result = {}
    for name, model, frames in [
        ("DNS queries", DNSQuery, [DNSQuery.frame_number, DNSQuery.response_frame]),
        ("DNS answers", DNSAnswer, [DNSAnswer.frame_number]),
        ("HTTP messages", HTTPSession, [HTTPSession.frame_number, HTTPSession.response_frame]),
        ("TLS handshake", TLSSession, [TLSSession.frame_number]),
        ("Certificates", Certificate, [Certificate.frame_number]),
    ]:
        rows = db.scalars(select(model).where(model.capture_id == packet.capture_id,
                                              or_(*(column == packet.frame_number for column in frames))).limit(50))
        result[name] = [record(row) for row in rows]
    return result
