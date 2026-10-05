import hashlib
import struct


def empty_pcap():
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def test_safe_content_upload(client):
    content = empty_pcap()
    response = client.post("/api/captures", files={"file": ("../../evil.exe", content)})
    assert response.status_code == 201
    capture = response.json()
    assert capture["file_type"] == "pcap"
    assert capture["original_filename"] == "evil.exe"
    assert capture["sha256"] == hashlib.sha256(content).hexdigest()
    path = client.app.state.settings.data_dir / "captures" / capture["filename"]
    assert path.read_bytes() == content
    assert path.stat().st_mode & 0o777 == 0o600
    assert client.get(f"/api/captures/{capture['id']}").status_code == 200
    assert len(client.get("/api/captures").json()) == 1


def test_reject_non_capture_and_cross_origin(client):
    response = client.post("/api/captures", files={"file": ("file.pcap", b"not a capture")})
    assert response.status_code == 400
    assert not list((client.app.state.settings.data_dir / "captures").iterdir())
    assert client.post("/api/captures", headers={"Origin": "https://untrusted.example"},
                       files={"file": ("file.pcap", empty_pcap())}).status_code == 403
    assert client.get("/api/health", headers={"Host": "untrusted.example"}).status_code == 400


def test_empty_dashboard(client):
    assert client.get("/api/dashboard").json()["counts"]["captures"] == 0
    assert client.get("/api/health").json()["mode"] == "local"
