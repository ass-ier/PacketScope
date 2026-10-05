"""Build a public-safe demo using only locally generated, benign capture bytes."""
import hashlib
import importlib.util
import io
import json
import logging
import socket
import struct
from datetime import UTC, datetime
from pathlib import Path

import dpkt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import UploadFile
from sqlalchemy import func, select

from app.models import Base, Capture, Case, Evidence, ExtractedFile, Finding, Host, HTTPSession, IOC, Report
from app.services.advanced import extract_http
from app.services.analysis import analyze
from app.services.capture import capture_path, store_upload, verify_hash
from app.services.cases import add_note, link_case, update_case
from app.services.reporting import generate_report

log = logging.getLogger("packetscope.demo")
DEMO_VERSION = 1


def fixture_module():
    path = Path(__file__).parents[3] / "fixtures" / "generate.py"
    spec = importlib.util.spec_from_file_location("packetscope_demo_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sample_records():
    fixture = fixture_module()
    samples = fixture.fixtures()
    samples["http-review"] = [(fixture.EPOCH, fixture.packet(payload=(
        b"GET /diagnostic?cmd=benign-demo HTTP/1.1\r\nHost: fixture.test\r\n"
        b"User-Agent: PowerShell-Synthetic-Demo\r\n\r\n")))]
    samples["suspicious-connections"] = [
        row for index in range(3) for row in [
            (fixture.EPOCH + index * 20, fixture.packet(dport=4444, sport=42000 + index,
                                                       payload=b"benign " * 100)),
            (fixture.EPOCH + index * 20 + .1, fixture.packet(
                src=fixture.SERVER, dst=fixture.CLIENT, sport=4444, dport=42000 + index,
                payload=b"synthetic response", seq=700)),
        ]
    ]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")])
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(20250101)
                   .not_valid_before(datetime(2024, 1, 1, tzinfo=UTC))
                   .not_valid_after(datetime(2024, 12, 1, tzinfo=UTC))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.test")]), critical=False)
                   .sign(key, hashes.SHA256()))
    der = certificate.public_bytes(serialization.Encoding.DER)
    chain = len(der).to_bytes(3, "big") + der
    samples["tls-certificate"] = [
        (fixture.EPOCH, fixture.packet(dport=443, payload=fixture.client_hello())),
        (fixture.EPOCH + .1, fixture.packet(src=fixture.SERVER, dst=fixture.CLIENT, sport=443, dport=40000,
                                          payload=fixture.tls_handshake(11, len(chain).to_bytes(3, "big") + chain))),
    ]
    dhcp = dpkt.dhcp.DHCP(op=2, yiaddr=struct.unpack("!I", socket.inet_aton(fixture.CLIENT))[0],
                          opts=[(12, b"synthetic-workstation"), (51, struct.pack("!I", 3600))])
    echo = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"synthetic"))
    ip = dpkt.ip.IP(src=socket.inet_aton(fixture.CLIENT), dst=socket.inet_aton(fixture.SERVER), p=1, data=echo)
    ip.len = len(ip)
    smb = b"\xfeSMB" + b"\x40\x00" + bytes(58)
    samples["protocol-metadata"] = [
        (fixture.EPOCH, fixture.packet(src="10.0.0.1", dst="255.255.255.255", sport=67, dport=68,
                                       udp=True, payload=bytes(dhcp))),
        (fixture.EPOCH + 1, bytes(dpkt.ethernet.Ethernet(type=0x800, data=ip))),
        (fixture.EPOCH + 2, fixture.packet(dport=445, payload=len(smb).to_bytes(4, "big") + smb)),
    ]
    return fixture, samples


def database_digest(db):
    digest = hashlib.sha256()
    for table in Base.metadata.sorted_tables:
        digest.update(table.name.encode())
        for row in db.execute(select(table).order_by(*table.primary_key.columns)).mappings():
            digest.update(json.dumps(dict(row), sort_keys=True, ensure_ascii=True).encode())
    return digest.hexdigest()


def demo_manifest_path(settings):
    return settings.data_dir / "synthetic-demo.json"


def verify_demo(database, settings):
    manifest = json.loads(demo_manifest_path(settings).read_text())
    if manifest.get("version") != DEMO_VERSION or manifest.get("synthetic") is not True:
        raise RuntimeError("Unknown demo dataset version; select a new empty demo directory")
    with database() as db:
        if database_digest(db) != manifest["database_sha256"]:
            raise RuntimeError("Demo database changed; refusing to publish unverified or mixed evidence")
        for capture in db.scalars(select(Capture)):
            verify_hash(capture_path(capture, settings), capture.sha256)
        for model, directory, column in ((ExtractedFile, "extracted", "storage_name"), (Report, "reports", "filename")):
            for row in db.scalars(select(model)):
                verify_hash(settings.data_dir / directory / getattr(row, column), row.sha256)
    return manifest


async def seed_demo(database, settings):
    manifest_path = demo_manifest_path(settings)
    if manifest_path.exists():
        manifest = verify_demo(database, settings)
        log.info("Verified existing synthetic demo: %s", manifest["counts"])
        return manifest
    with database() as db:
        for table in Base.metadata.sorted_tables:
            if table.name not in ("attack_techniques", "detection_rules") and db.scalar(
                    select(func.count()).select_from(table)):
                raise RuntimeError("Refusing to seed or publish an existing non-demo database; use a new empty demo directory")
    fixture, samples = sample_records()
    captures = {}
    for index, (name, records) in enumerate(samples.items()):
        format = "pcapng" if index % 2 == 0 else "pcap"
        with database() as db:
            capture = await store_upload(UploadFile(filename=f"synthetic-{name}.{format}",
                                                    file=io.BytesIO(fixture.encode(records, format))), db, settings)
            captures[name] = capture.id
        analyze(database, settings, capture.id)
    with database() as db:
        case_ids = {}
        for title, names, verdict, reasoning in [
            ("Synthetic: baseline protocol investigation", ["mixed", "normal-http", "normal-tls", "protocol-metadata"],
             "Benign", "Known benign fixture provenance. Observe DNS, HTTP and TLS metadata; unavailable certificates are not invented."),
            ("Synthetic: periodic communication review", ["periodic", "syn-retransmissions"],
             "Suspicious", "Eight separate HTTP conversations recur every 60 seconds. This is a demonstration indicator, not proof of C2. Identical unanswered SYNs are the negative control."),
            ("Synthetic: network indicators review", ["port-scan", "multiple-hosts", "dns-encoded", "arp-conflict",
                                                     "large-transfer", "http-review", "tls-certificate", "suspicious-connections"],
             "Suspicious", "Deterministic fixture patterns warrant investigation. These benign generated scenarios demonstrate rules, not a real compromised network."),
        ]:
            case = Case(title=title, description="Preloaded example assessment and notes. All traffic was generated locally; no network activity was performed.")
            db.add(case)
            db.commit()
            for name in names:
                capture_id = captures[name]
                case_ids[capture_id] = case.id
                link_case(db, case.id, "capture", capture_id)
                for finding in db.scalars(select(Finding).where(Finding.capture_id == capture_id)).all():
                    link_case(db, case.id, "finding", finding.id)
                for model, kind in ((Host, "host"), (IOC, "ioc")):
                    row = db.scalar(select(model).where(model.capture_id == capture_id).order_by(model.id))
                    if row:
                        link_case(db, case.id, kind, row.id)
            update_case(db, case.id, {"status": "Investigating", "verdict": verdict, "confidence": "Medium", "reasoning": reasoning})
            evidence = list(db.scalars(select(Evidence.id).where(
                Evidence.capture_id.in_([captures[name] for name in names])).order_by(Evidence.timestamp).limit(3)))
            add_note(db, case.id, "Synthetic demo note: follow the linked observations to their original frames and compare with the baseline. No external reputation results have been generated.", evidence)
        for name in ("normal-http", "mixed", "periodic"):
            http = db.scalar(select(HTTPSession).where(HTTPSession.capture_id == captures[name],
                                                       HTTPSession.body_complete.is_(True), HTTPSession.body_size > 0)
                             .order_by(HTTPSession.timestamp))
            if http:
                extract_http(db, http, settings, confirm=True)
        for capture_id in captures.values():
            for format in ("pdf", "markdown", "json", "stix"):
                generate_report(db, db.get(Capture, capture_id), settings, format, case_ids.get(capture_id))
        counts = {name: db.scalar(select(func.count()).select_from(model)) for name, model in [
            ("captures", Capture), ("cases", Case), ("findings", Finding), ("iocs", IOC),
            ("reports", Report), ("files", ExtractedFile)]}
        manifest = {"version": DEMO_VERSION, "synthetic": True, "counts": counts,
                    "captures": captures, "database_sha256": database_digest(db)}
    with manifest_path.open("x") as handle:
        json.dump(manifest, handle, indent=2)
    log.info("Prepared complete synthetic demo: %s", counts)
    return manifest
