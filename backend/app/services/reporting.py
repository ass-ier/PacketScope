import hashlib
import io
import json
import os
import time
from html import escape

import stix2
from fastapi import HTTPException
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from sqlalchemy import func, select

from app.models import CaseCapture, Certificate, DNSAnswer, DNSQuery, Evidence, ExtractedFile, Finding, Flow, Host, HTTPSession, IOC, PacketSummary, Report, Session, TimelineEvent, TLSSession, uid
from app.services.attack import attack_view
from app.services.capture import capture_path, verify_hash
from app.services.cases import get_case
from app.services.ioc import stix_bundle
from app.services.query import overview, record

SECTIONS = {
    "Affected Hosts": Host, "Network Flows": Flow, "Timeline": TimelineEvent, "DNS Analysis": DNSQuery,
    "DNS Answers": DNSAnswer, "HTTP Analysis": HTTPSession, "TLS Analysis": TLSSession,
    "Certificates": Certificate, "Behavioral Findings": Finding, "IOCs": IOC,
    "Evidence": Evidence, "Extracted Files": ExtractedFile,
}
DISPLAY_FIELDS = {
    Host: ["ip", "hostname", "mac", "connections", "bytes_sent", "bytes_received"],
    Flow: ["id", "source_ip", "destination_ip", "destination_port", "application", "state", "bytes_sent", "bytes_received", "first_frame"],
    TimelineEvent: ["timestamp", "summary", "frame_number", "flow_id"],
    DNSQuery: ["name", "query_type", "source_ip", "response_code", "frame_number", "response_frame"],
    DNSAnswer: ["name", "type", "value", "ttl", "frame_number"],
    HTTPSession: ["method", "host", "uri", "status_code", "body_complete", "frame_number"],
    TLSSession: ["sni", "version", "ja3", "frame_number", "metadata_fields"],
    Certificate: ["sha256", "subject", "issuer", "valid_from", "valid_until", "frame_number"],
    Finding: ["id", "title", "severity", "confidence", "description", "statistics", "rule_snapshot"],
    IOC: ["type", "value", "first_seen", "last_seen", "source"],
    Evidence: ["id", "frame_number", "flow_id", "session_id", "finding_id", "ioc_id"],
    ExtractedFile: ["filename", "sha256", "size", "source_host", "destination_host", "frame_number"],
}
LIMITATIONS = [
    "Capture visibility depends on sensor location, packet loss, snapshot length and capture completeness.",
    "NAT and shared infrastructure can complicate host attribution.",
    "Encrypted traffic cannot be decrypted without appropriate keys; TLS metadata is not decrypted content.",
    "Rule matches can be false positives and sophisticated activity can be missed.",
    "Periodicity is not automatically C2; DNS anomalies are not automatically tunneling.",
    "Fingerprints are indicators, not identities. A suspicious pattern does not prove compromise.",
]


def snapshot(db, capture, case_id=None):
    case = get_case(db, case_id) if case_id else None
    if case and not db.scalar(select(CaseCapture).where(CaseCapture.case_id == case_id, CaseCapture.capture_id == capture.id)):
        raise HTTPException(422, "Selected case is not linked to this capture")
    sections = {}
    for title, model in SECTIONS.items():
        total = db.scalar(select(func.count()).select_from(model).where(model.capture_id == capture.id))
        order = next((getattr(model, name) for name in ("timestamp", "first_seen", "start_time")
                      if hasattr(model, name)), model.id)
        rows = list(db.scalars(select(model).where(model.capture_id == capture.id).order_by(order, model.id).limit(250)))
        sections[title] = {"total": total, "shown": len(rows), "limited": total > len(rows),
                           "items": [{key: getattr(row, key) for key in DISPLAY_FIELDS[model]} for row in rows]}
    return {"schema": "packetscope.investigation.v1", "generated_at": time.time(), "capture": record(capture),
            "overview": overview(db, capture.id), "sections": sections, "attack": attack_view(db, capture.id),
            "analyst_assessment": case["case"] if case else {"verdict": "Unknown", "reasoning": "No analyst assessment supplied"},
            "case": case, "limitations": LIMITATIONS,
            "scope": "Human-readable reports include up to 250 rows per section and disclose exact totals. JSON exports stream all indexed entities."}


def paragraphs(data):
    capture = data["capture"]
    yield "Executive Summary", [
        f"Capture {capture['original_filename']}: {capture['packet_count']} observed packets over {capture['duration']:.3f} seconds.",
        f"{data['sections']['Behavioral Findings']['total']} evidence-based findings; analyst verdict: {data['analyst_assessment']['verdict']}.",
        "No automated compromise verdict is assigned. Affected Hosts below means observed endpoints, not confirmed victims.",
        data["scope"],
    ]
    yield "Capture Information", [f"{key}: {value}" for key, value in capture.items() if key not in ("filename",)]
    yield "Network Overview", [json.dumps(data["overview"], ensure_ascii=True)]
    for title, section in data["sections"].items():
        intro = f"{section['shown']} of {section['total']} indexed records included."
        if section["limited"]:
            intro += " Section is bounded; use JSON for the full indexed record set."
        yield title, [intro] + [json.dumps(row, ensure_ascii=True, sort_keys=True) for row in section["items"]]
    yield "Suspicious Flows", ["Findings link supporting flow IDs in the Evidence section. Traffic not linked to a finding is not thereby proven benign."]
    yield "ATT&CK Mapping", [json.dumps({"technique_id": m["technique_id"], "confidence": m["confidence"],
                                        "source_detection": m["source_detection"]["id"], "rationale": m["rationale"]})
                             for m in data["attack"]["mappings"]] or ["No supported mappings observed."]
    assessment = data["analyst_assessment"]
    yield "Analyst Assessment", [f"Verdict: {assessment['verdict']}",
                                 f"Confidence: {assessment.get('confidence', 'Not assessed')}",
                                 f"Reasoning: {assessment.get('reasoning', '')}",
                                 f"Assessment timestamp: {assessment.get('assessed_at', 'Not assessed')}"] + (
        [f"Analyst note: {note['text']} | Evidence IDs: {', '.join(note['evidence_ids'])}"
         for note in data["case"]["notes"]] if data["case"] else [])
    yield "Recommendations", [
        "Verify capture coverage and sensor placement before drawing conclusions.",
        "Review each finding's frames and flows; compare with authorized services, inventory and change records.",
        "Corroborate suspicious patterns using appropriately authorized host evidence and additional captures.",
        "Preserve original capture hashes and record the rationale for the final analyst assessment.",
    ]
    yield "Limitations", data["limitations"] + capture["warnings"]


def markdown_report(data):
    output = ["# PacketScope forensic investigation", ""]
    for title, texts in paragraphs(data):
        output.extend([f"## {title}", ""])
        for text in texts:
            # Fenced indented blocks keep captured text from becoming executable markup or remote images.
            output.extend(["    " + line for line in text.splitlines()] or ["    No observations."])
            output.append("")
    return "\n".join(output)


def pdf_report(data):
    buffer = io.BytesIO()
    styles = getSampleStyleSheet()
    body = ParagraphStyle("Evidence", parent=styles["BodyText"], fontName="Helvetica", fontSize=8,
                          leading=12, textColor=colors.HexColor("#253d4b"), spaceAfter=8,
                          alignment=TA_LEFT, splitLongWords=True)
    heading = ParagraphStyle("Section", parent=styles["Heading2"], fontSize=13, leading=17,
                             textColor=colors.HexColor("#17675f"), spaceBefore=14, spaceAfter=8)
    story = [Paragraph("PacketScope", styles["Title"]), Paragraph("Forensic investigation report", styles["Heading2"]),
             Paragraph(escape(data["capture"]["original_filename"]), body), Spacer(1, 12)]
    for title, texts in paragraphs(data):
        story.append(Paragraph(escape(title), heading))
        for text in texts:
            # Long attacker-controlled values are split into bounded paragraphs.
            text = text.encode("ascii", "backslashreplace").decode("ascii")
            for offset in range(0, len(text), 3000):
                story.append(Paragraph(escape(text[offset:offset + 3000]), body))
    def page_header(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#627480"))
        canvas.drawString(36, 24, f"PacketScope | Capture {data['capture']['id']}")
        canvas.drawRightString(document.pagesize[0] - 36, 24, f"Page {document.page}")
        canvas.restoreState()
    document = SimpleDocTemplate(buffer, pagesize=(8.27 * inch, 11.69 * inch),
                                 rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=42,
                                 title="PacketScope forensic investigation", author="PacketScope")
    document.build(story, onFirstPage=page_header, onLaterPages=page_header)
    return buffer.getvalue()


def write_json(db, capture, data, handle):
    """Stream all relational rows rather than building a capture-sized Python object."""
    prefix = {key: value for key, value in data.items() if key != "sections"}
    prefix["scope"] = "All indexed normalized entities; raw packet payloads remain in the original capture."
    handle.write(json.dumps(prefix, ensure_ascii=True)[:-1].encode() + b', "entities": {')
    models = {**SECTIONS, "Sessions": Session, "Packet Summaries": PacketSummary}
    for index, (title, model) in enumerate(models.items()):
        if index:
            handle.write(b",")
        handle.write(json.dumps(title).encode() + b":[")
        first = True
        for row in db.scalars(select(model).where(model.capture_id == capture.id).order_by(model.id)).yield_per(256):
            if not first:
                handle.write(b",")
            handle.write(json.dumps(record(row), ensure_ascii=True).encode())
            first = False
            if handle.tell() > 64 * 1024 * 1024:
                raise HTTPException(413, "Report exceeds 64 MiB export limit; use a smaller capture")
        handle.write(b"]")
    handle.write(b"}}")


def generate_report(db, capture, settings, format, case_id=None):
    if capture.analysis_status != "completed":
        raise HTTPException(409, "A completed analysis is required for a forensic report")
    try:
        verify_hash(capture_path(capture, settings), capture.sha256)
    except (ValueError, OSError) as exc:
        raise HTTPException(409, "Original capture integrity check failed") from exc
    data = snapshot(db, capture, case_id)
    folder = settings.data_dir / "reports"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    report_id = uid()
    filename = report_id + "." + ("md" if format == "markdown" else "json" if format == "stix" else format)
    path = folder / filename
    try:
        with path.open("xb") as handle:
            os.chmod(path, 0o600)
            if format == "json":
                write_json(db, capture, data, handle)
            elif format == "markdown":
                handle.write(markdown_report(data).encode())
            elif format == "pdf":
                handle.write(pdf_report(data))
            else:
                bundle = json.loads(stix_bundle(db, capture))
                observed_ids = [obj["id"] for obj in bundle["objects"] if obj["type"] == "observed-data"]
                if observed_ids:
                    note = stix2.Note(abstract="PacketScope analyst assessment",
                                      content=json.dumps({"capture_sha256": capture.sha256,
                                                          "assessment": data["analyst_assessment"],
                                                          "findings": data["sections"]["Behavioral Findings"],
                                                          "limitations": data["limitations"]}),
                                      object_refs=observed_ids)
                    bundle["objects"].append(json.loads(note.serialize()))
                else:
                    # No observations: a custom report object preserves the assessment without inventing traffic.
                    bundle["objects"].append({"type": "x-packetscope-empty-investigation", "spec_version": "2.1",
                                               "id": "x-packetscope-empty-investigation--" + uid(),
                                               "capture_sha256": capture.sha256, "assessment": data["analyst_assessment"]})
                handle.write(json.dumps(bundle, indent=2).encode())
        if path.stat().st_size > 64 * 1024 * 1024:
            raise HTTPException(413, "Report exceeds 64 MiB export limit")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        report = Report(id=report_id, capture_id=capture.id, case_id=case_id, format=format,
                        filename=filename, sha256=digest.hexdigest())
        db.add(report)
        db.commit()
        return report
    except Exception:
        path.unlink(missing_ok=True)
        raise
