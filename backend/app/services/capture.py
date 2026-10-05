import hashlib
import os
import re
import struct
from pathlib import Path

from fastapi import HTTPException, UploadFile
from sqlalchemy import delete, func, select

from app.models import Capture, CaseCapture, ExtractedFile, Report, uid


MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name.replace("\\", "/").split("/")[-1])[:180] or "capture"


def validate_header(path: Path) -> str:
    with path.open("rb") as handle:
        header = handle.read(32)
    if header[:4] in MAGICS:
        if len(header) < 24:
            raise ValueError("Truncated PCAP global header")
        endian, _ = MAGICS[header[:4]]
        major, minor, _, _, snaplen, _ = struct.unpack(endian + "HHIIII", header[4:24])
        if (major, minor) != (2, 4) or not 0 < snaplen <= 16 * 1024 * 1024:
            raise ValueError("Invalid PCAP version or snapshot length")
        return "pcap"
    if header[:4] == b"\x0a\x0d\x0d\x0a":
        if len(header) < 28 or header[8:12] not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
            raise ValueError("Invalid PCAPNG section header")
        endian = "<" if header[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
        length = struct.unpack(endian + "I", header[4:8])[0]
        if length < 28 or length % 4 or length > path.stat().st_size:
            raise ValueError("Truncated or invalid PCAPNG section")
        if struct.unpack(endian + "H", header[12:14])[0] != 1:
            raise ValueError("Unsupported PCAPNG major version")
        with path.open("rb") as handle:
            handle.seek(length - 4)
            if handle.read(4) != header[4:8]:
                raise ValueError("PCAPNG section length mismatch")
        return "pcapng"
    raise ValueError("Not a PCAP or PCAPNG capture (content validation failed)")


async def store_upload(file: UploadFile, db, settings):
    count, used = db.execute(select(func.count(), func.coalesce(func.sum(Capture.file_size), 0))).one()
    if count >= settings.max_captures:
        raise HTTPException(413, f"Capture count limit reached ({settings.max_captures}); remove unneeded captures")
    if used + settings.max_upload_bytes > settings.max_storage_bytes:
        raise HTTPException(413, "Local capture storage quota reached; remove unneeded captures")
    folder = settings.data_dir / "captures"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    capture_id = uid()
    path = folder / (capture_id + ".capture")
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("xb") as handle:
            os.chmod(path, 0o600)
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > settings.max_upload_bytes:
                    raise HTTPException(413, f"Capture exceeds {settings.max_upload_bytes} byte limit")
                digest.update(chunk)
                handle.write(chunk)
        file_type = validate_header(path)
        capture = Capture(id=capture_id, filename=path.name, original_filename=safe_name(file.filename or ""),
                          file_size=size, file_type=file_type, sha256=digest.hexdigest())
        db.add(capture)
        db.commit()
        return capture
    except ValueError as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(400, str(exc)) from exc
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()


def capture_path(capture, settings):
    path = settings.data_dir / "captures" / capture.filename
    if path.parent.resolve() != (settings.data_dir / "captures").resolve():
        raise ValueError("Invalid stored capture path")
    return path


def verify_hash(path, expected):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise ValueError("Capture integrity check failed: SHA-256 changed")


def delete_capture(db, capture, settings):
    if capture.analysis_status in ("queued", "parsing", "processing"):
        raise HTTPException(409, "Cannot delete a capture with an active analysis job")
    if db.scalar(select(CaseCapture.id).where(CaseCapture.capture_id == capture.id).limit(1)):
        raise HTTPException(409, "Capture is preserved by a linked case")
    if db.scalar(select(Report.id).where(Report.capture_id == capture.id).limit(1)):
        raise HTTPException(409, "Capture is preserved by a saved report")
    paths = [capture_path(capture, settings)]
    paths += [settings.data_dir / "extracted" / name for name in db.scalars(
        select(ExtractedFile.storage_name).where(ExtractedFile.capture_id == capture.id))]
    capture_id = capture.id
    db.execute(delete(Capture).where(Capture.id == capture_id))
    db.commit()
    for path in paths:
        path.unlink(missing_ok=True)
    return {"deleted": capture_id}
