import time
import uuid

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def uid():
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


class Entity:
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)


class Capture(Entity, Base):
    __tablename__ = "captures"
    filename: Mapped[str] = mapped_column(String(80))
    original_filename: Mapped[str] = mapped_column(String(200))
    file_size: Mapped[int] = mapped_column(Integer)
    file_type: Mapped[str] = mapped_column(String(10))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    packet_count: Mapped[int] = mapped_column(default=0)
    start_time: Mapped[float | None] = mapped_column(Float)
    end_time: Mapped[float | None] = mapped_column(Float)
    duration: Mapped[float] = mapped_column(default=0.0)
    analysis_status: Mapped[str] = mapped_column(default="stored", index=True)
    analysis_version: Mapped[str | None] = mapped_column(String(30))
    progress: Mapped[int] = mapped_column(default=0)
    stage: Mapped[str] = mapped_column(default="Capture validated")
    error: Mapped[str | None] = mapped_column(Text)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    link_types: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[float] = mapped_column(default=time.time)


class Captured:
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id", ondelete="CASCADE"), index=True)


class Flow(Entity, Captured, Base):
    __tablename__ = "flows"
    source_ip: Mapped[str] = mapped_column(index=True)
    destination_ip: Mapped[str] = mapped_column(index=True)
    source_port: Mapped[int] = mapped_column(default=0)
    destination_port: Mapped[int] = mapped_column(default=0, index=True)
    protocol: Mapped[str] = mapped_column(index=True)
    application: Mapped[str] = mapped_column(default="Unknown", index=True)
    identification: Mapped[str] = mapped_column(default="transport")
    start_time: Mapped[float] = mapped_column(Float)
    end_time: Mapped[float] = mapped_column(Float)
    duration: Mapped[float] = mapped_column(default=0.0)
    packet_count: Mapped[int] = mapped_column(default=0)
    bytes_sent: Mapped[int] = mapped_column(default=0)
    bytes_received: Mapped[int] = mapped_column(default=0)
    payload_sent: Mapped[int] = mapped_column(default=0)
    payload_received: Mapped[int] = mapped_column(default=0)
    flags: Mapped[int] = mapped_column(default=0)
    state: Mapped[str] = mapped_column(default="observed")
    first_frame: Mapped[int] = mapped_column(Integer)
    last_frame: Mapped[int] = mapped_column(Integer)
    initial_seq: Mapped[int | None] = mapped_column(Integer)
    reconstruction: Mapped[str] = mapped_column(default="not attempted")


class PacketSummary(Entity, Captured, Base):
    __tablename__ = "packets"
    __table_args__ = (
        UniqueConstraint("capture_id", "frame_number"),
        Index("ix_packet_capture_time", "capture_id", "timestamp"),
    )
    frame_number: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[float] = mapped_column(Float)
    offset: Mapped[int] = mapped_column(Integer)
    captured_length: Mapped[int] = mapped_column(Integer)
    length: Mapped[int] = mapped_column(Integer)
    link_type: Mapped[int] = mapped_column(Integer)
    source_mac: Mapped[str | None] = mapped_column(String(40))
    destination_mac: Mapped[str | None] = mapped_column(String(40))
    source_ip: Mapped[str | None] = mapped_column(String(50), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(50), index=True)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(index=True)
    transport: Mapped[str] = mapped_column(default="")
    ip_version: Mapped[int | None] = mapped_column(Integer)
    flags: Mapped[int] = mapped_column(default=0)
    payload_length: Mapped[int] = mapped_column(default=0)
    flow_id: Mapped[str | None] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    metadata_fields: Mapped[dict] = mapped_column(JSON, default=dict)


class Host(Entity, Captured, Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("capture_id", "ip"),)
    ip: Mapped[str] = mapped_column(index=True)
    mac: Mapped[str | None] = mapped_column(String(40))
    hostname: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    protocols: Mapped[list] = mapped_column(JSON, default=list)
    ports: Mapped[list] = mapped_column(JSON, default=list)
    connections: Mapped[int] = mapped_column(default=0)
    bytes_sent: Mapped[int] = mapped_column(default=0)
    bytes_received: Mapped[int] = mapped_column(default=0)


class Session(Entity, Captured, Base):
    __tablename__ = "sessions"
    flow_id: Mapped[str] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    protocol: Mapped[str] = mapped_column(index=True)
    timestamp: Mapped[float] = mapped_column(Float)
    frame_number: Mapped[int] = mapped_column(Integer)
    end_frame: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(default="observed")
    metadata_fields: Mapped[dict] = mapped_column(JSON, default=dict)


class DNSQuery(Entity, Captured, Base):
    __tablename__ = "dns_queries"
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"), index=True)
    flow_id: Mapped[str] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    frame_number: Mapped[int] = mapped_column(Integer)
    response_frame: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[float] = mapped_column(Float)
    source_ip: Mapped[str] = mapped_column(index=True)
    server_ip: Mapped[str] = mapped_column(index=True)
    transaction_id: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(index=True)
    query_type: Mapped[str] = mapped_column(String(20))
    response_code: Mapped[int | None] = mapped_column(Integer)
    response_time: Mapped[float | None] = mapped_column(Float)


class DNSAnswer(Entity, Captured, Base):
    __tablename__ = "dns_answers"
    query_id: Mapped[str] = mapped_column(ForeignKey("dns_queries.id", ondelete="CASCADE"), index=True)
    frame_number: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(index=True)
    type: Mapped[str] = mapped_column(String(20))
    value: Mapped[str] = mapped_column(Text, index=True)
    ttl: Mapped[int] = mapped_column(Integer)


class HTTPSession(Entity, Captured, Base):
    __tablename__ = "http_sessions"
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"), index=True)
    flow_id: Mapped[str] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    frame_number: Mapped[int] = mapped_column(Integer)
    response_frame: Mapped[int | None] = mapped_column(Integer)
    timestamp: Mapped[float] = mapped_column(Float)
    source_ip: Mapped[str] = mapped_column(index=True)
    destination_ip: Mapped[str] = mapped_column(index=True)
    method: Mapped[str | None] = mapped_column(String(30))
    host: Mapped[str | None] = mapped_column(String(255), index=True)
    uri: Mapped[str | None] = mapped_column(Text)
    status_code: Mapped[int | None] = mapped_column(Integer)
    user_agent: Mapped[str | None] = mapped_column(Text)
    referer: Mapped[str | None] = mapped_column(Text)
    content_type: Mapped[str | None] = mapped_column(String(255))
    request_size: Mapped[int] = mapped_column(default=0)
    response_size: Mapped[int] = mapped_column(default=0)
    body_sha256: Mapped[str | None] = mapped_column(String(64))
    body_size: Mapped[int | None] = mapped_column(Integer)
    body_complete: Mapped[bool] = mapped_column(default=False)
    metadata_fields: Mapped[dict] = mapped_column(JSON, default=dict)


class TLSSession(Entity, Captured, Base):
    __tablename__ = "tls_sessions"
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"), index=True)
    flow_id: Mapped[str] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    frame_number: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[float] = mapped_column(Float)
    source_ip: Mapped[str] = mapped_column(index=True)
    destination_ip: Mapped[str] = mapped_column(index=True)
    sni: Mapped[str | None] = mapped_column(String(255), index=True)
    version: Mapped[str | None] = mapped_column(String(40))
    cipher_suite: Mapped[str | None] = mapped_column(String(60))
    ja3: Mapped[str | None] = mapped_column(String(32), index=True)
    metadata_fields: Mapped[dict] = mapped_column(JSON, default=dict)


class Certificate(Entity, Captured, Base):
    __tablename__ = "certificates"
    tls_id: Mapped[str] = mapped_column(ForeignKey("tls_sessions.id", ondelete="CASCADE"), index=True)
    frame_number: Mapped[int] = mapped_column(Integer)
    subject: Mapped[str] = mapped_column(Text)
    issuer: Mapped[str] = mapped_column(Text)
    serial: Mapped[str] = mapped_column(Text)
    valid_from: Mapped[float] = mapped_column(Float)
    valid_until: Mapped[float] = mapped_column(Float)
    signature_algorithm: Mapped[str] = mapped_column(String(100))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    sans: Mapped[list] = mapped_column(JSON)
    self_signed: Mapped[bool] = mapped_column(Boolean)


class IOC(Entity, Captured, Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("capture_id", "type", "value"),)
    type: Mapped[str] = mapped_column(index=True)
    value: Mapped[str] = mapped_column(Text, index=True)
    first_seen: Mapped[float] = mapped_column(Float)
    last_seen: Mapped[float] = mapped_column(Float)
    source: Mapped[str] = mapped_column(String(60))


class Evidence(Entity, Captured, Base):
    __tablename__ = "evidence"
    packet_id: Mapped[str | None] = mapped_column(ForeignKey("packets.id", ondelete="CASCADE"), index=True)
    frame_number: Mapped[int] = mapped_column(Integer)
    timestamp: Mapped[float] = mapped_column(Float)
    flow_id: Mapped[str | None] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[str | None] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"), index=True)
    host_id: Mapped[str | None] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), index=True)
    ioc_id: Mapped[str | None] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), index=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    description: Mapped[str] = mapped_column(Text)


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(30))
    confidence: Mapped[str] = mapped_column(String(40))
    enabled: Mapped[bool] = mapped_column(default=True)
    config: Mapped[dict] = mapped_column(JSON)
    logic: Mapped[str] = mapped_column(Text)
    evidence_fields: Mapped[list] = mapped_column(JSON)
    attack_mapping: Mapped[list] = mapped_column(JSON, default=list)


class Finding(Entity, Captured, Base):
    __tablename__ = "findings"
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id"), index=True)
    title: Mapped[str] = mapped_column(String(180))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(index=True)
    confidence: Mapped[str] = mapped_column(String(40))
    source_ip: Mapped[str | None] = mapped_column(String(50), index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(50), index=True)
    timestamp: Mapped[float] = mapped_column(Float)
    evidence_count: Mapped[int] = mapped_column(Integer)
    statistics: Mapped[dict] = mapped_column(JSON)
    rule_snapshot: Mapped[dict] = mapped_column(JSON)


class TimelineEvent(Entity, Captured, Base):
    __tablename__ = "timeline_events"
    timestamp: Mapped[float] = mapped_column(Float, index=True)
    kind: Mapped[str] = mapped_column(index=True)
    summary: Mapped[str] = mapped_column(Text)
    protocol: Mapped[str] = mapped_column(index=True)
    host: Mapped[str | None] = mapped_column(String(50), index=True)
    frame_number: Mapped[int] = mapped_column(Integer)
    flow_id: Mapped[str | None] = mapped_column(ForeignKey("flows.id", ondelete="CASCADE"), index=True)
    session_id: Mapped[str | None] = mapped_column(ForeignKey("sessions.id", ondelete="CASCADE"))
    ioc_id: Mapped[str | None] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"))
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    severity: Mapped[str | None] = mapped_column(String(30))


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(180))
    tactic: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)


class FindingTechnique(Entity, Base):
    __tablename__ = "finding_techniques"
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    technique_id: Mapped[str] = mapped_column(ForeignKey("attack_techniques.id"), index=True)
    confidence: Mapped[str] = mapped_column(String(40))
    rationale: Mapped[str] = mapped_column(Text)


class Case(Entity, Base):
    __tablename__ = "cases"
    title: Mapped[str] = mapped_column(String(200), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(default="Open")
    verdict: Mapped[str] = mapped_column(default="Unknown")
    confidence: Mapped[str] = mapped_column(default="Low")
    reasoning: Mapped[str] = mapped_column(Text, default="")
    assessed_at: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[float] = mapped_column(default=time.time)
    updated_at: Mapped[float] = mapped_column(default=time.time)


class CaseLink(Entity):
    case_id: Mapped[str] = mapped_column(ForeignKey("cases.id", ondelete="CASCADE"), index=True)


class CaseCapture(CaseLink, Base):
    __tablename__ = "case_captures"
    __table_args__ = (UniqueConstraint("case_id", "capture_id"),)
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id"), index=True)


class CaseHost(CaseLink, Base):
    __tablename__ = "case_hosts"
    __table_args__ = (UniqueConstraint("case_id", "host_id"),)
    host_id: Mapped[str] = mapped_column(ForeignKey("hosts.id"), index=True)


class CaseIOC(CaseLink, Base):
    __tablename__ = "case_iocs"
    __table_args__ = (UniqueConstraint("case_id", "ioc_id"),)
    ioc_id: Mapped[str] = mapped_column(ForeignKey("iocs.id"), index=True)


class CaseFinding(CaseLink, Base):
    __tablename__ = "case_findings"
    __table_args__ = (UniqueConstraint("case_id", "finding_id"),)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)


class CaseNote(CaseLink, Base):
    __tablename__ = "case_notes"
    text: Mapped[str] = mapped_column(Text)
    evidence_ids: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[float] = mapped_column(default=time.time)


class ExtractedFile(Entity, Captured, Base):
    __tablename__ = "extracted_files"
    http_id: Mapped[str] = mapped_column(ForeignKey("http_sessions.id"), index=True, unique=True)
    flow_id: Mapped[str] = mapped_column(ForeignKey("flows.id"))
    frame_number: Mapped[int] = mapped_column(Integer)
    filename: Mapped[str] = mapped_column(String(200))
    storage_name: Mapped[str] = mapped_column(String(80))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    mime_type: Mapped[str] = mapped_column(String(255))
    source_host: Mapped[str] = mapped_column(String(50))
    destination_host: Mapped[str] = mapped_column(String(50))
    timestamp: Mapped[float] = mapped_column(Float)
    protocol: Mapped[str] = mapped_column(default="HTTP")
    created_at: Mapped[float] = mapped_column(default=time.time)


class ThreatIntelResult(Entity, Base):
    __tablename__ = "threat_intel_results"
    ioc_id: Mapped[str] = mapped_column(ForeignKey("iocs.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(30))
    result: Mapped[dict] = mapped_column(JSON)
    queried_at: Mapped[float] = mapped_column(default=time.time)


class Report(Entity, Base):
    __tablename__ = "reports"
    capture_id: Mapped[str] = mapped_column(ForeignKey("captures.id"), index=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), index=True)
    format: Mapped[str] = mapped_column(String(20))
    filename: Mapped[str] = mapped_column(String(100))
    sha256: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[float] = mapped_column(default=time.time)
