import struct
import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import Settings
from app.main import create_app
from app.models import Capture, IOC
from test_engine import analyze_capture, fixture
from test_protocols import items


def wait_status(client, cid):
    for _ in range(500):
        status = client.get(f"/api/captures/{cid}/analysis").json()
        if status["analysis_status"] in ("completed", "failed"):
            return status
        time.sleep(.01)
    pytest.fail("Job failed to terminate")


@pytest.mark.parametrize("format", ["pcap", "pcapng"])
def test_truncated_container_fails_explicitly(client, format):
    content = fixture.encode(fixture.conversation(), format)[:-2]
    response = client.post("/api/captures", files={"file":("truncated.bin", content)})
    assert response.status_code == 201
    cid = response.json()["id"]
    client.post(f"/api/captures/{cid}/analyze")
    status = wait_status(client, cid)
    assert status["analysis_status"] == "failed" and "Truncated" in status["error"]
    assert client.post("/api/reports", json={"capture_id":cid, "format":"json"}).status_code == 409


@pytest.mark.parametrize("change,message", [
    ({"max_packets":2}, "Packet limit"),
    ({"max_flows":2}, "Flow limit"),
    ({"max_hosts":1}, "Host limit"),
    ({"max_frame_bytes":10}, "frame length"),
    ({"analysis_timeout":0}, "time limit"),
    ({"max_total_packets":2}, "Workspace packet index limit"),
    ({"max_derived_records":2}, "Derived evidence record limit"),
])
def test_analysis_resource_limits(tmp_path, change, message):
    settings = replace(Settings(data_dir=tmp_path), **change)
    with TestClient(create_app(settings)) as client:
        content = fixture.encode(fixture.fixtures()["port-scan"])
        capture = client.post("/api/captures", files={"file":("limits.pcap", content)}).json()
        client.post(f"/api/captures/{capture['id']}/analyze")
        status = wait_status(client, capture["id"])
        assert status["analysis_status"] == "failed" and message in status["error"]


def test_streamed_upload_size_limit_and_json_limit(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path, max_upload_bytes=128))) as client:
        content = fixture.encode(fixture.conversation())
        assert client.post("/api/captures", files={"file":("big.pcap", content)}).status_code == 413
        boundary = "packetscope-test-boundary"
        body = f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="large.pcap"\r\n\r\n'.encode()
        body += b"x" * 100000 + f"\r\n--{boundary}--\r\n".encode()
        response = client.post("/api/captures", content=iter([body[:200], body[200:]]),
                               headers={"Content-Type":f"multipart/form-data; boundary={boundary}"})
        assert response.status_code == 413, response.text
        assert client.post("/api/cases", content=b" " * 300000, headers={"Content-Type":"application/json"}).status_code == 413
        assert not list((tmp_path / "captures").glob("*"))


def test_retry_cleans_partial_protocol_and_ioc_state(client, monkeypatch):
    import app.services.analysis as analysis
    real = analysis.detect
    def fail(*_):
        raise RuntimeError("Synthetic detector failure")
    monkeypatch.setattr(analysis, "detect", fail)
    capture = client.post("/api/captures", files={"file":("retry.pcap", fixture.encode(fixture.conversation()))}).json()
    client.post(f"/api/captures/{capture['id']}/analyze")
    assert wait_status(client, capture["id"])["analysis_status"] == "failed"
    monkeypatch.setattr(analysis, "detect", real)
    client.post(f"/api/captures/{capture['id']}/analyze")
    assert wait_status(client, capture["id"])["analysis_status"] == "completed"
    assert len(items(client, capture["id"], "http")) == 1
    with client.app.state.database() as db:
        count = db.scalar(select(func.count()).select_from(IOC).where(IOC.capture_id == capture["id"]))
    assert count == len(items(client, capture["id"], "iocs"))


def test_restart_recovery_and_migration_idempotence(tmp_path):
    settings = Settings(data_dir=tmp_path)
    with TestClient(create_app(settings)) as client:
        capture = client.post("/api/captures", files={"file":("interrupted.pcap", fixture.encode([]))}).json()
        with client.app.state.database() as db:
            row = db.get(Capture, capture["id"])
            row.analysis_status = "parsing"
            db.commit()
    with TestClient(create_app(settings)) as client:
        status = client.get(f"/api/captures/{capture['id']}").json()
        assert status["analysis_status"] == "failed" and "interrupted" in status["error"]
        assert len(client.get("/api/rules").json()) == 9


def test_safe_deletion_and_evidence_retention(client):
    capture = analyze_capture(client, fixture.conversation())
    path = client.app.state.settings.data_dir / "captures" / capture["filename"]
    assert client.delete(f"/api/captures/{capture['id']}").status_code == 200
    assert not path.exists()
    capture = analyze_capture(client, fixture.conversation())
    client.post("/api/reports", json={"capture_id":capture["id"], "format":"json"})
    assert client.delete(f"/api/captures/{capture['id']}").status_code == 409


def block(kind, body):
    size = len(body) + 12
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def test_pcapng_multiple_interfaces_resolution_and_unknown_link(client):
    frame = fixture.packet(flags=2)
    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    ethernet = block(1, struct.pack("<HHI", 1, 0, 65535))
    unknown = block(1, struct.pack("<HHI", 147, 0, 65535) + struct.pack("<HH", 9, 1) + b"\x09\x00\x00\x00" + bytes(4))
    def enhanced(interface, nanos, data):
        return block(6, struct.pack("<IIIII", interface, nanos >> 32, nanos & 0xFFFFFFFF, len(data), len(data)) +
                     data + bytes((-len(data)) % 4))
    content = section + ethernet + unknown + enhanced(0, 1_000_000, frame) + enhanced(1, 2_000_000_000, frame)
    capture = client.post("/api/captures", files={"file":("interfaces.pcapng", content)}).json()
    client.post(f"/api/captures/{capture['id']}/analyze")
    status = wait_status(client, capture["id"])
    assert status["analysis_status"] == "completed"
    assert status["start_time"] == 1 and status["end_time"] == 2
    assert status["link_types"] == [1, 147] and any("Unsupported link-layer" in w for w in status["warnings"])


def test_reconstruction_limits_conflicts_and_malformed_tls(client, tmp_path):
    payload = b"GET /safe HTTP/1.1\r\nHost: fixture.test\r\n\r\n"
    records = [(fixture.EPOCH, fixture.packet(flags=2)), (fixture.EPOCH+.1, fixture.packet(seq=101, payload=payload)),
               (fixture.EPOCH+.2, fixture.packet(seq=101, payload=payload.replace(b"/safe", b"/evil")))]
    capture = analyze_capture(client, records)
    assert any("ambiguous" in w for w in capture["warnings"])
    with TestClient(create_app(Settings(data_dir=tmp_path, max_stream_bytes=10))) as limited:
        capture = analyze_capture(limited, fixture.conversation())
        assert any("byte limit" in w for w in capture["warnings"])
        assert not items(limited, capture["id"], "http")
    capture = analyze_capture(client, [(fixture.EPOCH, fixture.packet(dport=443, payload=b"\x16\x03\x03\xff\xff"))])
    assert any("TLS record truncated" in w for w in capture["warnings"])


def test_origin_filter_validation_and_pagination(client):
    assert client.post("/api/cases", json={"title":"x"}, headers={"Origin":"http://["}).status_code == 403
    assert client.get("/api/evidence/flows?limit=100000").status_code == 422
    assert client.get("/api/evidence/flows?q=unsupported:expression").status_code == 422
    assert client.post("/api/cases", json={"title":"x", "unexpected":True}).status_code == 422


def test_impossible_original_frame_size_cannot_inflate_transfer_findings(client):
    content = fixture.encode([(fixture.EPOCH, fixture.packet(flags=2))])
    content = content[:36] + struct.pack("<I", 0xFFFFFFFF) + content[40:]
    capture = client.post("/api/captures", files={"file":("invalid-wire-length.pcap", content)}).json()
    client.post(f"/api/captures/{capture['id']}/analyze")
    status = wait_status(client, capture["id"])
    assert status["analysis_status"] == "failed" and "frame length" in status["error"]
    assert not items(client, capture["id"], "findings")


def test_queue_bound_and_http_responsiveness(tmp_path, monkeypatch):
    import threading
    import app.services.analysis as analysis
    entered, release = threading.Event(), threading.Event()
    actual = analysis.analyze
    def waiting(*args, **kwargs):
        entered.set()
        if not release.wait(timeout=10):
            raise RuntimeError("Synthetic queue test timed out")
        return actual(*args, **kwargs)
    monkeypatch.setattr(analysis, "analyze", waiting)
    with TestClient(create_app(Settings(data_dir=tmp_path, max_pending_jobs=1))) as client:
        captures = [client.post("/api/captures", files={"file":("queue.pcap", fixture.encode([]))}).json() for _ in range(2)]
        try:
            assert client.post(f"/api/captures/{captures[0]['id']}/analyze").status_code == 202
            assert entered.wait(timeout=2)
            assert client.post(f"/api/captures/{captures[1]['id']}/analyze").status_code == 429
            assert client.post(f"/api/captures/{captures[0]['id']}/analyze").status_code == 409
            assert client.get("/api/health").status_code == 200
            assert client.delete(f"/api/captures/{captures[0]['id']}").status_code == 409
        finally:
            release.set()
        assert wait_status(client, captures[0]["id"])["analysis_status"] == "completed"
