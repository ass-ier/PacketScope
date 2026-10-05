import logging
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException
from sqlalchemy import delete, event, func, insert, select, update

from app.core.config import VERSION
from app.models import Capture, Evidence, Finding, Flow, Host, IOC, PacketSummary, Session, TimelineEvent, uid
from app.services.capture import capture_path, verify_hash
from app.services.flows import FlowBuilder
from app.services.packets import decode, frames
from app.services.protocols import analyze_protocols
from app.services.ioc import extract_iocs
from app.services.detection import detect
from app.services.timeline import build_timeline
from app.services.attack import map_attack

log = logging.getLogger("packetscope.analysis")


class JobRunner:
    def __init__(self, database, settings):
        self.database, self.settings = database, settings
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="capture-analysis")
        self.capacity = threading.BoundedSemaphore(settings.max_pending_jobs)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        with database() as db:
            db.execute(update(Capture).where(Capture.analysis_status.in_(["queued", "parsing", "processing"]))
                       .values(analysis_status="failed", error="Analysis interrupted by application shutdown; retry explicitly",
                               stage="Interrupted"))
            db.commit()

    def submit(self, capture_id):
        with self.lock, self.database() as db:
            capture = db.get(Capture, capture_id)
            if not capture:
                raise HTTPException(404, "Capture not found")
            if capture.analysis_status not in ("stored", "failed"):
                raise HTTPException(409, "Capture is already analyzed or has an active job")
            if not self.capacity.acquire(blocking=False):
                raise HTTPException(429, "Local analysis queue is full; wait for a job to finish")
            capture.analysis_status, capture.progress, capture.error = "queued", 0, None
            capture.stage = "Queued for local analysis"
            db.commit()
            self.executor.submit(self._work, capture_id)

    def _work(self, capture_id):
        try:
            analyze(self.database, self.settings, capture_id, self.stop_event)
        except Exception as exc:
            log.exception("Capture analysis failed for %s", capture_id)
            with self.database() as db:
                capture = db.get(Capture, capture_id)
                capture.analysis_status = "failed"
                capture.error = f"{type(exc).__name__}: {str(exc)[:500]}"
                capture.stage = "Failed; partial observations are not a complete investigation"
                db.commit()
        finally:
            self.capacity.release()

    def close(self):
        self.stop_event.set()
        self.executor.shutdown(wait=True)


def analyze(database, settings, capture_id, stop_event=None):
    started = time.monotonic()

    def checkpoint():
        if time.monotonic() - started > settings.analysis_timeout:
            raise ValueError(f"Analysis time limit exceeded ({settings.analysis_timeout}s)")
        if stop_event and stop_event.is_set():
            raise ValueError("Analysis interrupted by application shutdown")

    with database() as db:
        capture = db.get(Capture, capture_id)
        indexed_elsewhere = db.scalar(select(func.coalesce(func.sum(Capture.packet_count), 0))
                                      .where(Capture.id != capture_id))
        path = capture_path(capture, settings)
        verify_hash(path, capture.sha256)
        for model in (TimelineEvent, Evidence, Finding, IOC):
            db.execute(delete(model).where(model.capture_id == capture_id))
        db.execute(delete(Flow).where(Flow.capture_id == capture_id))
        db.execute(delete(Host).where(Host.capture_id == capture_id))
        db.execute(delete(PacketSummary).where(PacketSummary.capture_id == capture_id))
        capture.analysis_status, capture.stage, capture.progress = "parsing", "Packet parsing / flow reconstruction", 5
        capture.packet_count, capture.start_time, capture.end_time = 0, None, None
        capture.warnings, capture.link_types = [], []
        db.commit()
        builder = FlowBuilder(capture_id, settings, db)
        batch, warnings, links = [], Counter(), set()
        for frame in frames(path, settings):
            checkpoint()
            if indexed_elsewhere + frame.number > settings.max_total_packets:
                raise RuntimeError(f"Workspace packet index limit exceeded ({settings.max_total_packets})")
            fields, _ = decode(frame.data, frame.link_type)
            if frame.warning:
                warnings[frame.warning] += 1
            if fields["metadata_fields"].get("warning"):
                warnings[fields["metadata_fields"]["warning"]] += 1
            fields.update(id=uid(), capture_id=capture_id, frame_number=frame.number, timestamp=frame.timestamp,
                          offset=frame.offset, captured_length=frame.captured_length, length=frame.length,
                          link_type=frame.link_type)
            if frame.warning:
                fields["metadata_fields"]["capture_warning"] = frame.warning
            fields["flow_id"] = builder.accept(fields)
            batch.append(fields)
            links.add(frame.link_type)
            capture.packet_count = frame.number
            capture.start_time = min(capture.start_time, frame.timestamp) if capture.start_time is not None else frame.timestamp
            capture.end_time = max(capture.end_time, frame.timestamp) if capture.end_time is not None else frame.timestamp
            if len(batch) >= 512:
                db.flush()
                db.execute(insert(PacketSummary), batch)
                batch.clear()
                capture.progress = min(60, 5 + int((frame.offset / max(capture.file_size, 1)) * 55))
                db.commit()
        db.flush()
        if batch:
            db.execute(insert(PacketSummary), batch)
        capture.duration = (capture.end_time or 0) - (capture.start_time or 0)
        capture.link_types = sorted(links)
        capture.warnings = [f"{message} ({count} frames)" for message, count in warnings.items()]
        if capture.packet_count == 0:
            capture.warnings += ["Empty capture: no packets or network activity observed"]
        capture.analysis_status, capture.stage, capture.progress = "processing", "Session indexing", 65
        db.commit()
        for flow in builder.flows:
            db.add(Session(capture_id=capture_id, flow_id=flow.id, protocol=flow.protocol,
                           timestamp=flow.start_time, frame_number=flow.first_frame, end_frame=flow.last_frame,
                           status=flow.state, metadata_fields={"byte_accounting": "Wire bytes; includes retransmissions"}))
        db.commit()
        checkpoint()
        db.info["derived_count"] = len(builder.flows)
        db.info["derived_limit"] = settings.max_derived_records

        @event.listens_for(db, "before_flush")
        def derived_budget(session, *_):
            checkpoint()
            session.info["derived_count"] += len(session.new)
            if session.info["derived_count"] > settings.max_derived_records:
                raise RuntimeError(f"Derived evidence record limit exceeded ({settings.max_derived_records})")

        capture.stage, capture.progress = "DNS / HTTP / TLS / protocol analysis", 65
        db.commit()
        analyze_protocols(db, capture, path, settings, checkpoint)
        capture.stage, capture.progress = "IOC extraction and normalization", 82
        db.commit()
        extract_iocs(db, capture, checkpoint)
        capture.stage, capture.progress = "Deterministic behavior analysis", 88
        db.commit()
        detect(db, capture, checkpoint)
        capture.stage, capture.progress = "Timeline and evidence indexing", 94
        db.commit()
        build_timeline(db, capture, checkpoint)
        capture.stage, capture.progress = "Evidence-supported ATT&CK mapping", 97
        db.commit()
        map_attack(db, capture)
        capture.analysis_status, capture.stage, capture.progress = "completed", "Analysis completed", 100
        capture.analysis_version = VERSION
        db.commit()
