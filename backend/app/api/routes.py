from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, Response
from sqlalchemy import func, select

from app.models import Capture, Case, Certificate, DetectionRule, DNSAnswer, DNSQuery, Evidence, ExtractedFile, Finding, Flow, Host, HTTPSession, IOC, PacketSummary, Report, Session, ThreatIntelResult, TimelineEvent, TLSSession
from app.services.capture import capture_path, delete_capture, store_upload, verify_hash
from app.services.packets import read_packet
from app.services.query import overview, packet_protocol_evidence, page
from app.services.ioc import export_iocs
from app.services.search import search
from app.services.detection import update_rule
from app.schemas import CaseCreate, CaseLinkCreate, CaseUpdate, CompareCreate, ExtractionCreate, IntelLookup, NoteCreate, ReportCreate, RuleUpdate
from app.services.cases import add_note, get_case, link_case, update_case
from app.services.graph import build_graph
from app.services.attack import attack_view
from app.services.advanced import compare, extract_http, reverse_scope_handoff
from app.services.intelligence import lookup, provider_status
from app.services.reporting import generate_report

router = APIRouter(prefix="/api")


def database(request: Request):
    with request.app.state.database() as db:
        yield db


def record(obj):
    return {column.name: getattr(obj, column.name) for column in obj.__table__.columns}


def require(db, model, entity_id):
    obj = db.get(model, entity_id)
    if obj is None:
        raise HTTPException(404, f"{model.__name__} not found")
    return obj


@router.get("/health")
def health():
    return {"status": "ok", "mode": "local", "version": "1.0.0"}


@router.post("/captures", status_code=201)
async def upload(request: Request, file: UploadFile, db=Depends(database)):
    return record(await store_upload(file, db, request.app.state.settings))


@router.get("/captures")
def captures(db=Depends(database)):
    return [record(row) for row in db.scalars(select(Capture).order_by(Capture.created_at.desc()).limit(200))]


@router.get("/captures/{capture_id}")
def capture(capture_id: str, db=Depends(database)):
    return record(require(db, Capture, capture_id))


@router.delete("/captures/{capture_id}")
def remove_capture(capture_id: str, request: Request, db=Depends(database)):
    return delete_capture(db, require(db, Capture, capture_id), request.app.state.settings)


@router.get("/settings")
def settings_info(request: Request):
    settings = request.app.state.settings
    return {"max_upload_bytes": settings.max_upload_bytes, "max_packets": settings.max_packets,
            "max_flows": settings.max_flows, "max_hosts": settings.max_hosts,
            "max_stream_bytes": settings.max_stream_bytes, "analysis_timeout": settings.analysis_timeout,
            "max_pending_jobs": settings.max_pending_jobs, "max_captures": settings.max_captures,
            "max_total_packets": settings.max_total_packets, "max_derived_records": settings.max_derived_records,
            "max_capture_storage_bytes": settings.max_storage_bytes, "external_enabled": provider_status()["external_enabled"]}


@router.get("/dashboard")
def dashboard(db=Depends(database)):
    counts = {name: db.scalar(select(func.count()).select_from(model))
              for name, model in [("captures", Capture), ("hosts", Host), ("flows", Flow),
                                  ("iocs", IOC), ("findings", Finding), ("cases", Case)]}
    counts["analyzed"] = db.scalar(select(func.count()).select_from(Capture)
                                  .where(Capture.analysis_status == "completed"))
    return {**overview(db), "counts": counts, "recent_captures": captures(db),
            "recent_findings": [record(row) for row in db.scalars(
                select(Finding).order_by(Finding.timestamp.desc()).limit(8))]}


@router.post("/captures/{capture_id}/analyze", status_code=202)
def start_analysis(capture_id: str, request: Request):
    request.app.state.jobs.submit(capture_id)
    return {"capture_id": capture_id, "status": "queued"}


@router.get("/captures/{capture_id}/analysis")
def analysis_status(capture_id: str, db=Depends(database)):
    return record(require(db, Capture, capture_id))


@router.get("/captures/{capture_id}/overview")
def capture_overview(capture_id: str, db=Depends(database)):
    require(db, Capture, capture_id)
    return overview(db, capture_id)


COLLECTIONS = {"packets": PacketSummary, "hosts": Host, "flows": Flow, "sessions": Session,
               "dns": DNSQuery, "http": HTTPSession, "tls": TLSSession, "certificates": Certificate, "iocs": IOC,
               "findings": Finding, "timeline": TimelineEvent, "evidence": Evidence, "files": ExtractedFile}


@router.post("/captures/compare")
def compare_captures(body: CompareCreate, db=Depends(database)):
    left, right = require(db, Capture, body.baseline_id), require(db, Capture, body.comparison_id)
    if left.analysis_status != "completed" or right.analysis_status != "completed":
        raise HTTPException(409, "Both captures must have completed analysis")
    return compare(db, left, right)


@router.post("/reports", status_code=201)
def create_report(body: ReportCreate, request: Request, db=Depends(database)):
    return record(generate_report(db, require(db, Capture, body.capture_id), request.app.state.settings,
                                  body.format, body.case_id))


@router.get("/reports")
def reports(capture_id: str | None = None, db=Depends(database)):
    statement = select(Report).order_by(Report.created_at.desc()).limit(200)
    if capture_id:
        statement = statement.where(Report.capture_id == capture_id)
    return [record(row) for row in db.scalars(statement)]


@router.get("/reports/{report_id}")
def report_info(report_id: str, db=Depends(database)):
    return record(require(db, Report, report_id))


@router.get("/reports/{report_id}/download")
def report_download(report_id: str, request: Request, db=Depends(database)):
    report = require(db, Report, report_id)
    path = request.app.state.settings.data_dir / "reports" / report.filename
    try:
        verify_hash(path, report.sha256)
    except (ValueError, OSError) as exc:
        raise HTTPException(409, "Report missing or integrity check failed") from exc
    mime = {"pdf": "application/pdf", "markdown": "text/markdown", "json": "application/json", "stix": "application/stix+json"}[report.format]
    return FileResponse(path, filename="packetscope-" + report.filename, media_type=mime,
                        headers={"Content-Security-Policy": "sandbox; default-src 'none'"})


@router.get("/captures/{capture_id}/file-candidates")
def file_candidates(capture_id: str, db=Depends(database)):
    require(db, Capture, capture_id)
    return [record(row) for row in db.scalars(select(HTTPSession).where(
        HTTPSession.capture_id == capture_id, HTTPSession.body_complete.is_(True),
        HTTPSession.body_size > 0).order_by(HTTPSession.timestamp).limit(200))]


@router.post("/http/{http_id}/extract", status_code=201)
def extract(http_id: str, body: ExtractionCreate, request: Request, db=Depends(database)):
    return record(extract_http(db, require(db, HTTPSession, http_id), request.app.state.settings, body.acknowledge_untrusted))


@router.get("/files/{file_id}/download")
def download_file(file_id: str, request: Request, db=Depends(database)):
    file = require(db, ExtractedFile, file_id)
    path = request.app.state.settings.data_dir / "extracted" / file.storage_name
    try:
        verify_hash(path, file.sha256)
    except (OSError, ValueError) as exc:
        raise HTTPException(409, "Extracted evidence missing or integrity check failed") from exc
    return FileResponse(path, media_type="application/octet-stream", filename=file.filename,
                        headers={"Content-Security-Policy": "sandbox; default-src 'none'"})


@router.get("/files/{file_id}/reversescope")
def reversescope(file_id: str, db=Depends(database)):
    return reverse_scope_handoff(db, require(db, ExtractedFile, file_id))


@router.get("/intelligence/providers")
def intel_providers():
    return provider_status()


@router.post("/iocs/{ioc_id}/lookup")
def intel_lookup(ioc_id: str, body: IntelLookup, db=Depends(database)):
    return lookup(db, require(db, IOC, ioc_id), body.provider, body.consent_to_share_indicator)


@router.get("/iocs/{ioc_id}/intelligence")
def intel_results(ioc_id: str, db=Depends(database)):
    require(db, IOC, ioc_id)
    return [record(row) for row in db.scalars(select(ThreatIntelResult).where(ThreatIntelResult.ioc_id == ioc_id)
                                             .order_by(ThreatIntelResult.queried_at.desc()).limit(50))]


@router.post("/cases", status_code=201)
def create_case(body: CaseCreate, db=Depends(database)):
    case = Case(**body.model_dump())
    db.add(case)
    db.commit()
    return record(case)


@router.get("/cases")
def list_cases(db=Depends(database)):
    return [record(case) for case in db.scalars(select(Case).order_by(Case.updated_at.desc()).limit(200))]


@router.get("/cases/{case_id}")
def case_detail(case_id: str, db=Depends(database)):
    return get_case(db, case_id)


@router.patch("/cases/{case_id}")
def case_update(case_id: str, body: CaseUpdate, db=Depends(database)):
    return update_case(db, case_id, body.model_dump(exclude_none=True))


@router.post("/cases/{case_id}/links")
def case_link(case_id: str, body: CaseLinkCreate, db=Depends(database)):
    return link_case(db, case_id, body.kind, body.entity_id)


@router.post("/cases/{case_id}/notes", status_code=201)
def case_note(case_id: str, body: NoteCreate, db=Depends(database)):
    return add_note(db, case_id, body.text, body.evidence_ids)


@router.get("/captures/{capture_id}/graph")
def graph(capture_id: str, q: str = Query("", max_length=500), start: float | None = None,
          end: float | None = None, topology: bool = False, db=Depends(database)):
    require(db, Capture, capture_id)
    return build_graph(db, capture_id, q, start, end, topology)


@router.get("/captures/{capture_id}/attack")
def attack(capture_id: str, db=Depends(database)):
    require(db, Capture, capture_id)
    return attack_view(db, capture_id)


@router.get("/rules")
def detection_rules(db=Depends(database)):
    return [record(rule) for rule in db.scalars(select(DetectionRule).order_by(DetectionRule.id))]


@router.patch("/rules/{rule_id}")
def change_rule(rule_id: str, body: RuleUpdate, db=Depends(database)):
    return update_rule(db, require(db, DetectionRule, rule_id), body.model_dump(exclude_none=True))


@router.get("/search")
def global_search(q: str = Query(..., min_length=1, max_length=200), db=Depends(database)):
    return search(db, q)


@router.get("/captures/{capture_id}/iocs/export")
def ioc_export(capture_id: str, format: str = Query("json", pattern="^(json|csv|txt|stix)$"),
               db=Depends(database)):
    capture = require(db, Capture, capture_id)
    body, mime = export_iocs(db, capture, format)
    return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="iocs-{capture.id}.{format}"'})


@router.get("/captures/{capture_id}/packets/{frame_number}")
def packet_detail(capture_id: str, frame_number: int, request: Request, hex_view: bool = False,
                  db=Depends(database)):
    capture = require(db, Capture, capture_id)
    packet = db.scalar(select(PacketSummary).where(PacketSummary.capture_id == capture_id,
                                                   PacketSummary.frame_number == frame_number))
    if packet is None:
        raise HTTPException(404, "Frame not found")
    path = capture_path(capture, request.app.state.settings)
    try:
        verify_hash(path, capture.sha256)
        (decoded, _), raw = read_packet(path, packet)
    except (ValueError, OSError) as exc:
        raise HTTPException(409, str(exc)) from exc
    return {**record(packet), "capture_sha256": capture.sha256, "decoded": decoded,
            "protocol_evidence": packet_protocol_evidence(db, packet),
            "hex": raw[:4096].hex(" ") if hex_view else None,
            "hex_truncated": hex_view and len(raw) > 4096}


@router.get("/captures/{capture_id}/{collection}")
def capture_collection(capture_id: str, collection: str, q: str = Query("", max_length=500),
                       offset: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200),
                       start: float | None = None, end: float | None = None, db=Depends(database)):
    require(db, Capture, capture_id)
    if collection not in COLLECTIONS:
        raise HTTPException(404, "Unknown evidence collection")
    return page(db, COLLECTIONS[collection], capture_id, q, offset, limit, start, end)


@router.get("/entities/{collection}/{entity_id}")
def entity_detail(collection: str, entity_id: str, db=Depends(database)):
    if collection not in COLLECTIONS:
        raise HTTPException(404, "Unknown evidence collection")
    entity = require(db, COLLECTIONS[collection], entity_id)
    result = {"entity": record(entity)}
    if isinstance(entity, Flow):
        result["packets"] = page(db, PacketSummary, entity.capture_id, f"flow_id:{entity.id}")
        result["sessions"] = page(db, Session, entity.capture_id, f"flow_id:{entity.id}")
    elif isinstance(entity, Host):
        result["flows"] = page(db, Flow, entity.capture_id, f"host:{entity.ip}")
    elif isinstance(entity, DNSQuery):
        result["answers"] = [record(row) for row in db.scalars(select(DNSAnswer).where(DNSAnswer.query_id == entity.id))]
    elif isinstance(entity, TLSSession):
        result["certificates"] = [record(row) for row in db.scalars(select(Certificate).where(Certificate.tls_id == entity.id))]
    elif isinstance(entity, IOC):
        result["evidence"] = [record(row) for row in db.scalars(select(Evidence).where(Evidence.ioc_id == entity.id).limit(200))]
        host_ids = {row["host_id"] for row in result["evidence"] if row["host_id"]}
        flow_ids = {row["flow_id"] for row in result["evidence"] if row["flow_id"]}
        result["hosts"] = [record(row) for row in db.scalars(select(Host).where(Host.id.in_(host_ids)))]
        result["flows"] = [record(row) for row in db.scalars(select(Flow).where(Flow.id.in_(flow_ids)))]
    elif isinstance(entity, Finding):
        result["evidence"] = [record(row) for row in db.scalars(select(Evidence).where(Evidence.finding_id == entity.id))]
        flow_ids = {row["flow_id"] for row in result["evidence"] if row["flow_id"]}
        result["flows"] = [record(row) for row in db.scalars(select(Flow).where(Flow.id.in_(flow_ids)))]
    return result


@router.get("/evidence/{collection}")
def all_evidence(collection: str, q: str = Query("", max_length=500), offset: int = Query(0, ge=0),
                 limit: int = Query(50, ge=1, le=200), db=Depends(database)):
    if collection not in COLLECTIONS:
        raise HTTPException(404, "Unknown evidence collection")
    return page(db, COLLECTIONS[collection], query=q, offset=offset, limit=limit)
