from sqlalchemy import String, Text, or_, select

from app.models import Capture, Case, CaseCapture, DNSQuery, Finding, Flow, Host, HTTPSession, IOC, TLSSession
from app.services.query import record


def search(db, query):
    needle = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    results, captures = [], set()
    for kind, model in [("captures", Capture), ("hosts", Host), ("flows", Flow), ("dns", DNSQuery),
                        ("http", HTTPSession), ("tls", TLSSession), ("iocs", IOC), ("findings", Finding), ("cases", Case)]:
        columns = [getattr(model, c.name) for c in model.__table__.columns if isinstance(c.type, (String, Text))]
        predicates = [column.ilike(needle, escape="\\") for column in columns]
        if query.isdigit() and model is Flow:
            predicates += [Flow.source_port == int(query), Flow.destination_port == int(query)]
        for row in db.scalars(select(model).where(or_(*predicates)).limit(20)):
            results.append({"kind": kind, "entity": record(row)})
            if hasattr(row, "capture_id"):
                captures.add(row.capture_id)
    seen = {(r["kind"], r["entity"]["id"]) for r in results}
    for capture_id in sorted(captures)[:20]:
        if ("captures", capture_id) not in seen:
            results.append({"kind": "captures", "entity": record(db.get(Capture, capture_id))})
        for case in db.scalars(select(Case).join(CaseCapture).where(CaseCapture.capture_id == capture_id).limit(20)):
            if ("cases", case.id) not in seen:
                results.append({"kind": "cases", "entity": record(case)})
                seen.add(("cases", case.id))
    return {"query": query, "results": results, "limit_per_type": 20}
