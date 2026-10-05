import time

from fastapi import HTTPException
from sqlalchemy import select

from app.models import Capture, Case, CaseCapture, CaseFinding, CaseHost, CaseIOC, CaseNote, Evidence, Finding, Host, IOC
from app.services.query import record

LINKS = {"capture": (CaseCapture, Capture, "capture_id"), "host": (CaseHost, Host, "host_id"),
         "ioc": (CaseIOC, IOC, "ioc_id"), "finding": (CaseFinding, Finding, "finding_id")}


def get_case(db, case_id):
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "Case not found")
    result = {"case": record(case)}
    for kind, (link, model, field) in LINKS.items():
        result[kind + "s"] = [record(row) for row in db.scalars(
            select(model).join(link, getattr(link, field) == model.id).where(link.case_id == case_id))]
    result["notes"] = [record(row) for row in db.scalars(select(CaseNote).where(CaseNote.case_id == case_id)
                                                       .order_by(CaseNote.created_at))]
    return result


def link_case(db, case_id, kind, entity_id):
    if db.get(Case, case_id) is None:
        raise HTTPException(404, "Case not found")
    link, model, field = LINKS[kind]
    entity = db.get(model, entity_id)
    if entity is None:
        raise HTTPException(404, "Evidence entity not found")
    capture_id = entity.id if kind == "capture" else entity.capture_id
    capture = db.get(Capture, capture_id)
    if capture.analysis_status != "completed":
        raise HTTPException(409, "Only completed captures can be attached to cases")
    existing = db.scalar(select(link).where(link.case_id == case_id, getattr(link, field) == entity_id))
    if existing is None:
        db.add(link(case_id=case_id, **{field: entity_id}))
    if kind != "capture" and not db.scalar(select(CaseCapture).where(CaseCapture.case_id == case_id,
                                                                    CaseCapture.capture_id == capture_id)):
        db.add(CaseCapture(case_id=case_id, capture_id=capture_id))
    db.commit()
    return get_case(db, case_id)


def update_case(db, case_id, changes):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(404, "Case not found")
    for field, value in changes.items():
        setattr(case, field, value)
    case.updated_at = time.time()
    if set(changes) & {"verdict", "confidence", "reasoning"}:
        case.assessed_at = case.updated_at
    db.commit()
    return get_case(db, case_id)


def add_note(db, case_id, text, evidence_ids):
    get_case(db, case_id)
    captures = set(db.scalars(select(CaseCapture.capture_id).where(CaseCapture.case_id == case_id)))
    for evidence_id in evidence_ids:
        evidence = db.get(Evidence, evidence_id)
        if evidence is None or evidence.capture_id not in captures:
            raise HTTPException(422, "Note evidence must belong to a capture linked to this case")
    note = CaseNote(case_id=case_id, text=text, evidence_ids=evidence_ids)
    db.add(note)
    db.commit()
    return record(note)
