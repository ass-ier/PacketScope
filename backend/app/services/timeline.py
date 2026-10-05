from sqlalchemy import insert, select

from app.models import Evidence, Finding, Flow, Session, TimelineEvent, uid


def build_timeline(db, capture, checkpoint):
    batch = []

    def add(**fields):
        db.info["derived_count"] = db.info.get("derived_count", 0) + 1
        if db.info["derived_count"] > db.info.get("derived_limit", 200000):
            raise RuntimeError("Derived evidence record limit exceeded while indexing timeline")
        batch.append({"id": uid(), "capture_id": capture.id, "session_id": None, "ioc_id": None,
                      "finding_id": None, "severity": None, **fields})
        if len(batch) >= 512:
            db.execute(insert(TimelineEvent), batch)
            batch.clear()
            checkpoint()

    for flow in db.scalars(select(Flow).where(Flow.capture_id == capture.id)).yield_per(256):
        add(timestamp=flow.start_time, kind="flow", summary=f"{flow.source_ip}:{flow.source_port} -> {flow.destination_ip}:{flow.destination_port}",
            protocol=flow.application, host=flow.source_ip, frame_number=flow.first_frame, flow_id=flow.id)
    for session in db.scalars(select(Session).where(Session.capture_id == capture.id,
                                                   Session.protocol.in_(["DNS", "HTTP", "TLS", "ARP", "DHCP", "SMB", "ICMP", "ICMPv6"]))).yield_per(256):
        flow = db.get(Flow, session.flow_id)
        add(timestamp=session.timestamp, kind="session", summary=f"{session.protocol}: {session.status}",
            protocol=session.protocol, host=flow.source_ip, frame_number=session.frame_number,
            flow_id=flow.id, session_id=session.id)
    for finding in db.scalars(select(Finding).where(Finding.capture_id == capture.id)).yield_per(256):
        evidence = db.scalar(select(Evidence).where(Evidence.finding_id == finding.id).order_by(Evidence.timestamp))
        if evidence:
            flow = db.get(Flow, evidence.flow_id) if evidence.flow_id else None
            add(timestamp=finding.timestamp, kind="finding", summary=finding.title,
                protocol=flow.application if flow else "ARP", host=finding.source_ip,
                frame_number=evidence.frame_number, flow_id=evidence.flow_id, finding_id=finding.id,
                severity=finding.severity, session_id=evidence.session_id)
    # One first-observation event per IOC; remaining occurrences stay in Evidence.
    seen = set()
    for evidence in db.scalars(select(Evidence).where(Evidence.capture_id == capture.id, Evidence.ioc_id.is_not(None))
                               .order_by(Evidence.timestamp)).yield_per(256):
        if evidence.ioc_id not in seen:
            seen.add(evidence.ioc_id)
            flow = db.get(Flow, evidence.flow_id) if evidence.flow_id else None
            add(timestamp=evidence.timestamp, kind="ioc", summary=evidence.description,
                protocol=flow.application if flow else "Unknown", host=flow.source_ip if flow else None,
                frame_number=evidence.frame_number, flow_id=evidence.flow_id,
                ioc_id=evidence.ioc_id, session_id=evidence.session_id)
    if batch:
        db.execute(insert(TimelineEvent), batch)
    db.commit()
