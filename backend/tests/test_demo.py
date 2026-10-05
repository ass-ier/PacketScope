
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings
from app.main import create_app
from app.models import Case
from app.services.demo import database_digest, verify_demo
from test_engine import fixture


@pytest.fixture(scope="module")
def demo_settings(tmp_path_factory):
    return Settings(data_dir=tmp_path_factory.mktemp("synthetic-demo"), demo_mode=True)


@pytest.fixture(scope="module")
def demo_client(demo_settings):
    with TestClient(create_app(demo_settings)) as client:
        yield client


def test_demo_is_complete_real_evidence(demo_client):
    client = demo_client
    assert client.get("/api/health").json()["mode"] == "demo"
    assert client.get("/api/settings").json()["read_only"]
    captures = client.get("/api/captures").json()
    assert len(captures) == 16
    assert {c["file_type"] for c in captures} == {"pcap", "pcapng"}
    assert all(c["analysis_status"] == "completed" and c["original_filename"].startswith("synthetic-") for c in captures)
    assert sum(c["packet_count"] for c in captures) == 324
    assert client.get("/api/evidence/findings").json()["total"] == 9
    assert len(client.get("/api/cases").json()) == 3
    reports = client.get("/api/reports").json()
    assert len(reports) == 64
    assert {r["format"] for r in reports} == {"pdf", "markdown", "json", "stix"}
    files = client.get("/api/evidence/files").json()
    assert files["total"] == 3
    assert client.get(f"/api/files/{files['items'][0]['id']}/download").content == b"Benign fixture\n"
    for format in ("pdf", "markdown", "json", "stix"):
        report = next(r for r in reports if r["format"] == format)
        assert client.get(f"/api/reports/{report['id']}/download").status_code == 200
    comparison = client.get("/api/comparison", params={"baseline_id":captures[0]["id"], "comparison_id":captures[1]["id"]})
    assert comparison.status_code == 200
    providers = client.get("/api/intelligence/providers").json()
    assert not providers["external_enabled"] and all(not p["enabled"] for p in providers["providers"])


@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/captures", None),
    ("POST", "/api/captures/missing/analyze", {}),
    ("DELETE", "/api/captures/missing", None),
    ("POST", "/api/cases", {"title":"Must not write"}),
    ("PATCH", "/api/cases/missing", {"reasoning":"Must not write"}),
    ("PATCH", "/api/rules/port-scan", {"enabled":False}),
    ("POST", "/api/reports", {}),
    ("POST", "/api/http/missing/extract", {"acknowledge_untrusted":True}),
    ("POST", "/api/iocs/missing/lookup", {"provider":"dns", "consent_to_share_indicator":True}),
])
def test_demo_rejects_every_mutation(demo_client, method, path, body):
    with demo_client.app.state.database() as db:
        before = database_digest(db)
    result = demo_client.request(method, path, json=body)
    assert result.status_code == 403 and "Read-only" in result.json()["detail"]
    with demo_client.app.state.database() as db:
        assert database_digest(db) == before


def test_demo_restart_verifies_without_duplicates(demo_client, demo_settings):
    original = demo_client.get("/api/captures").json()
    with TestClient(create_app(demo_settings)) as client:
        assert [c["id"] for c in client.get("/api/captures").json()] == [c["id"] for c in original]
        assert len(client.get("/api/reports").json()) == 64


def test_demo_refuses_personal_or_changed_database(tmp_path):
    with TestClient(create_app(Settings(data_dir=tmp_path))) as client:
        result = client.post("/api/captures", files={"file":("private.pcap", fixture.encode([]))})
        assert result.status_code == 201
    with pytest.raises(RuntimeError, match="non-demo database"):
        with TestClient(create_app(Settings(data_dir=tmp_path, demo_mode=True))):
            pass


def test_demo_rejects_changed_analyst_data(demo_client, demo_settings):
    with demo_client.app.state.database() as db:
        case = db.scalar(select(Case))
        original = case.reasoning
        case.reasoning = "Unverified replacement"
        db.commit()
    try:
        with pytest.raises(RuntimeError, match="Demo database changed"):
            verify_demo(demo_client.app.state.database, demo_settings)
    finally:
        with demo_client.app.state.database() as db:
            db.get(Case, case.id).reasoning = original
            db.commit()
    verify_demo(demo_client.app.state.database, demo_settings)


def test_demo_configuration_refuses_external_intelligence(monkeypatch, tmp_path):
    monkeypatch.setenv("PACKETSCOPE_EXTERNAL_ENABLED", "true")
    with pytest.raises(ValueError, match="cannot be enabled"):
        Settings(data_dir=tmp_path, demo_mode=True)
    monkeypatch.setenv("PACKETSCOPE_EXTERNAL_ENABLED", "false")
    monkeypatch.setenv("RENDER_EXTERNAL_HOSTNAME", "synthetic-demo.onrender.com")
    assert "synthetic-demo.onrender.com" in Settings(data_dir=tmp_path).allowed_hosts
