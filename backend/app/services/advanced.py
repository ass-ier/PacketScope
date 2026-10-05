import hashlib
import os
import threading
from urllib.parse import urlsplit

from fastapi import HTTPException
from sqlalchemy import select

from app.models import Capture, ExtractedFile, Finding, Flow, Host, IOC, uid
from app.services.capture import capture_path, safe_name, verify_hash
from app.services.http import http_pairs
from app.services.query import record

EXTRACTION_LOCK = threading.Lock()


def compare(db, left, right):
    def values(capture_id):
        hosts = set(db.scalars(select(Host.ip).where(Host.capture_id == capture_id)))
        iocs = list(db.execute(select(IOC.type, IOC.value).where(IOC.capture_id == capture_id)))
        flows = list(db.scalars(select(Flow).where(Flow.capture_id == capture_id)))
        findings = list(db.scalars(select(Finding).where(Finding.capture_id == capture_id)))
        return {"hosts": hosts, "ips": {v for t, v in iocs if t in ("ipv4", "ipv6")},
                "domains": {v for t, v in iocs if t == "domain"}, "iocs": {f"{t}:{v}" for t, v in iocs},
                "protocols": {flow.application for flow in flows},
                "flows": {f"{f.source_ip}:{f.source_port} -> {f.destination_ip}:{f.destination_port} {f.protocol}/{f.application}" for f in flows},
                "findings": {f"{f.rule_id} {f.source_ip} -> {f.destination_ip}" for f in findings}}
    first, second = values(left.id), values(right.id)
    differences = {}
    for key in first:
        sets = {"added": second[key] - first[key], "removed": first[key] - second[key], "common": first[key] & second[key]}
        differences[key] = {name: {"count": len(values), "values": sorted(values)[:200], "limited": len(values) > 200}
                            for name, values in sets.items()}
    return {"baseline": record(left), "comparison": record(right), "differences": differences,
            "semantics": "Set comparison of observed entities; not proof of infection or a statistical baseline."}


def extract_http(db, http, settings, confirm):
    if not confirm:
        raise HTTPException(422, "Explicit acknowledgment of untrusted evidence is required")
    if not http.body_complete or http.body_size is None or http.body_size == 0:
        raise HTTPException(409, "No complete nonempty HTTP body is available for safe extraction")
    capture = db.get(Capture, http.capture_id)
    if capture.analysis_status != "completed":
        raise HTTPException(409, "Analysis must be complete before extraction")
    with EXTRACTION_LOCK:
        existing = db.scalar(select(ExtractedFile).where(ExtractedFile.http_id == http.id))
        if existing:
            return existing
        path = capture_path(capture, settings)
        try:
            verify_hash(path, capture.sha256)
        except (OSError, ValueError) as exc:
            raise HTTPException(409, str(exc)) from exc
        flow = db.get(Flow, http.flow_id)
        pairs, _ = http_pairs(db, path, flow, settings)
        response = next((response for request, response in pairs if response and response["complete"]
                         and response["packet"].frame_number == http.response_frame
                         and response["offset"] == http.metadata_fields.get("response_offset")
                         and (request or response)["packet"].frame_number == http.frame_number), None)
        if response is None:
            raise HTTPException(409, "HTTP body cannot be reliably reconstructed")
        body = response["body"]
        digest = hashlib.sha256(body).hexdigest()
        if digest != http.body_sha256:
            raise HTTPException(409, "Reconstructed body hash does not match indexed evidence")
        file_id = uid()
        folder = settings.data_dir / "extracted"
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        storage_name = file_id + ".evidence"
        destination = folder / storage_name
        filename = safe_name(urlsplit(http.uri or "").path.rsplit("/", 1)[-1] or "http-body") + ".untrusted"
        try:
            with destination.open("xb") as handle:
                os.chmod(destination, 0o600)
                handle.write(body)
            extracted = ExtractedFile(id=file_id, capture_id=capture.id, http_id=http.id, flow_id=http.flow_id,
                                      frame_number=http.response_frame, filename=filename, storage_name=storage_name,
                                      size=len(body), sha256=digest, mime_type=http.content_type or "application/octet-stream",
                                      source_host=http.destination_ip, destination_host=http.source_ip,
                                      timestamp=http.timestamp, protocol="HTTP")
            db.add(extracted)
            db.commit()
            return extracted
        except Exception:
            destination.unlink(missing_ok=True)
            raise


def reverse_scope_handoff(db, file):
    capture = db.get(Capture, file.capture_id)
    return {"schema": "packetscope.hash-handoff.v1", "source": "PacketScope",
            "sha256": file.sha256, "size": file.size, "filename": file.filename,
            "capture_sha256": capture.sha256, "capture_id": capture.id,
            "flow_id": file.flow_id, "frame_number": file.frame_number,
            "integration": "Hash-only envelope. No ReverseScope dependency, network request, payload execution or target mutation."}
