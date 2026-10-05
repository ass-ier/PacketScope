import csv
import datetime
import io
import ipaddress
import json
import re
from urllib.parse import urlsplit, urlunsplit

import stix2
from fastapi import HTTPException
from sqlalchemy import func, select
from stix2 import properties

from app.models import Certificate, DNSAnswer, DNSQuery, Evidence, Flow, Host, HTTPSession, IOC, TLSSession, uid
from app.services.query import record


def normalize(kind, value):
    value = str(value).strip()
    if not value or any(ord(c) < 32 for c in value):
        return None
    try:
        if kind in ("ipv4", "ipv6"):
            address = ipaddress.ip_address(value)
            return str(address) if address.version == (4 if kind == "ipv4" else 6) else None
        if kind == "domain":
            domain = value.rstrip(".").encode("idna").decode("ascii").lower()
            if len(domain) > 253 or "." not in domain or not all(re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label) for label in domain.split(".")):
                return None
            try:
                ipaddress.ip_address(domain)
                return None
            except ValueError:
                return domain
        if kind == "url":
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname or parsed.username:
                return None
            host = parsed.hostname.encode("idna").decode("ascii").lower()
            if ":" in host:
                host = f"[{host}]"
            port = parsed.port
            authority = host + (f":{port}" if port and port != (80 if parsed.scheme.lower() == "http" else 443) else "")
            return urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))
        if kind == "email":
            local, domain = value.rsplit("@", 1)
            normalized = normalize("domain", domain)
            return f"{local}@{normalized}" if local and normalized else None
        if kind in ("sha256", "sha1", "md5", "certificate-sha256", "ja3"):
            size = {"sha256": 64, "sha1": 40, "md5": 32, "certificate-sha256": 64, "ja3": 32}[kind]
            return value.lower() if re.fullmatch(f"[a-fA-F0-9]{{{size}}}", value) else None
        if kind == "mac":
            return value.lower() if re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value) else None
    except (ValueError, UnicodeError):
        return None
    return None


def text_indicators(text):
    text = text[:65536]
    for value in re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text):
        yield "email", value
    for value in re.findall(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b", text):
        yield {64: "sha256", 40: "sha1", 32: "md5"}[len(value)], value


def extract_iocs(db, capture, checkpoint):
    indicators = {}
    seen_evidence = set()
    hosts = {host.ip: host for host in db.scalars(select(Host).where(Host.capture_id == capture.id))}

    def add(kind, value, source, frame, timestamp, flow_id=None, session_id=None, host=None, last_seen=None):
        normalized = normalize(kind, value)
        if normalized is None:
            return
        key = kind, normalized
        if key not in indicators:
            ioc = IOC(id=uid(), capture_id=capture.id, type=kind, value=normalized,
                      first_seen=timestamp, last_seen=last_seen or timestamp, source=source)
            indicators[key] = ioc
            db.add(ioc)
            db.flush()
        ioc = indicators[key]
        ioc.first_seen, ioc.last_seen = min(ioc.first_seen, timestamp), max(ioc.last_seen, last_seen or timestamp)
        evidence_key = ioc.id, frame, flow_id, session_id, host
        if evidence_key not in seen_evidence:
            seen_evidence.add(evidence_key)
            db.add(Evidence(capture_id=capture.id, frame_number=frame, timestamp=timestamp,
                            flow_id=flow_id, session_id=session_id, host_id=hosts[host].id if host in hosts else None,
                            ioc_id=ioc.id, description=f"Observed {kind} in {source}; not a maliciousness assertion"))

    for flow in db.scalars(select(Flow).where(Flow.capture_id == capture.id)).yield_per(256):
        checkpoint()
        for ip in (flow.source_ip, flow.destination_ip):
            kind = "ipv6" if ":" in ip else "ipv4"
            add(kind, ip, "flow endpoints", flow.first_frame, flow.start_time, flow.id, host=ip, last_seen=flow.end_time)
            if ip in hosts and hosts[ip].mac:
                add("mac", hosts[ip].mac, "observed link-layer", flow.first_frame, flow.start_time, flow.id, host=ip,
                    last_seen=flow.end_time)
    for query in db.scalars(select(DNSQuery).where(DNSQuery.capture_id == capture.id)).yield_per(256):
        checkpoint()
        add("domain", query.name, "DNS question", query.frame_number, query.timestamp, query.flow_id, query.session_id, query.source_ip)
        for answer in db.scalars(select(DNSAnswer).where(DNSAnswer.query_id == query.id)):
            kind = "ipv4" if answer.type == "A" else "ipv6" if answer.type == "AAAA" else "domain"
            value = answer.value.split()[-1] if answer.type in ("MX", "SRV") else answer.value
            if answer.type != "TXT":
                add(kind, value, "DNS answer", answer.frame_number, query.timestamp + (query.response_time or 0),
                    query.flow_id, query.session_id, query.source_ip)
            else:
                for kind, value in text_indicators(answer.value):
                    add(kind, value, "DNS TXT", answer.frame_number, query.timestamp, query.flow_id, query.session_id, query.source_ip)
    for http in db.scalars(select(HTTPSession).where(HTTPSession.capture_id == capture.id)).yield_per(256):
        checkpoint()
        values = []
        if http.host:
            try:
                host = urlsplit("http://" + http.host).hostname
            except ValueError:
                host = None
            if host:
                values.append(("domain", host))
                if http.uri:
                    values.append(("url", http.uri if http.uri.startswith("http://") else "http://" + http.host + http.uri))
        values.extend(text_indicators(json.dumps(http.metadata_fields, ensure_ascii=True)))
        values.extend(text_indicators(http.uri or ""))
        for kind, value in values:
            add(kind, value, "HTTP metadata", http.frame_number, http.timestamp, http.flow_id, http.session_id, http.source_ip)
    for tls in db.scalars(select(TLSSession).where(TLSSession.capture_id == capture.id)).yield_per(256):
        checkpoint()
        for kind, value in (("domain", tls.sni), ("ja3", tls.ja3)):
            if value:
                add(kind, value, "TLS ClientHello", tls.frame_number, tls.timestamp, tls.flow_id, tls.session_id, tls.source_ip)
        for cert in db.scalars(select(Certificate).where(Certificate.tls_id == tls.id)):
            add("certificate-sha256", cert.sha256, "TLS certificate", cert.frame_number, tls.timestamp, tls.flow_id, tls.session_id, tls.source_ip)
    db.commit()


@stix2.CustomObservable("x-packetscope-fingerprint", [
    ("algorithm", properties.StringProperty(required=True)),
    ("value", properties.StringProperty(required=True)),
], id_contrib_props=["algorithm", "value"])
class Fingerprint:
    pass


def stix_bundle(db, capture):
    if db.scalar(select(func.count()).select_from(IOC).where(IOC.capture_id == capture.id)) > 10000:
        raise HTTPException(413, "STIX export is limited to 10,000 IOCs; use JSON/TXT/CSV for this capture")
    objects = []
    constructors = {"ipv4": stix2.IPv4Address, "ipv6": stix2.IPv6Address, "domain": stix2.DomainName,
                    "url": stix2.URL, "email": stix2.EmailAddress, "mac": stix2.MACAddress}
    for ioc in db.scalars(select(IOC).where(IOC.capture_id == capture.id).order_by(IOC.type, IOC.value)):
        if ioc.type in constructors:
            observable = constructors[ioc.type](value=ioc.value)
        elif ioc.type in ("sha256", "sha1", "md5"):
            algorithm = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}[ioc.type]
            observable = stix2.File(hashes={algorithm: ioc.value})
        elif ioc.type == "certificate-sha256":
            observable = stix2.X509Certificate(hashes={"SHA-256": ioc.value})
        else:
            observable = Fingerprint(algorithm=ioc.type, value=ioc.value)
        evidence = list(db.scalars(select(Evidence).where(Evidence.ioc_id == ioc.id).limit(200)))
        observation_count = db.scalar(select(func.count()).select_from(Evidence).where(Evidence.ioc_id == ioc.id))
        observed = stix2.ObservedData(first_observed=datetime.datetime.fromtimestamp(ioc.first_seen, datetime.UTC),
                                      last_observed=datetime.datetime.fromtimestamp(ioc.last_seen, datetime.UTC),
                                      number_observed=max(1, observation_count), object_refs=[observable.id], allow_custom=True)
        note = stix2.Note(abstract="PacketScope observed evidence",
                          content=f"Capture SHA-256 {capture.sha256}; IOC {ioc.id}; representative frames "
                                  f"{', '.join(str(e.frame_number) for e in evidence)}. Observed, not classified as malicious.",
                          object_refs=[observed.id])
        objects.extend([observable, observed, note])
    return stix2.Bundle(objects=objects, allow_custom=True).serialize(pretty=True)


def export_iocs(db, capture, format):
    rows = [record(ioc) for ioc in db.scalars(select(IOC).where(IOC.capture_id == capture.id)
                                             .order_by(IOC.type, IOC.value))]
    if format == "stix":
        return stix_bundle(db, capture), "application/stix+json"
    if format == "json":
        return json.dumps({"capture_sha256": capture.sha256, "classification": "observed", "iocs": rows}, indent=2), "application/json"
    if format == "txt":
        return "\n".join(row["value"] for row in rows) + ("\n" if rows else ""), "text/plain"
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["type", "value", "first_seen", "last_seen", "capture_sha256"])
    for row in rows:
        value = row["value"]
        if value.startswith(("=", "+", "-", "@", "\t", "\r")):
            value = "'" + value
        writer.writerow([row["type"], value, row["first_seen"], row["last_seen"], capture.sha256])
    return buffer.getvalue(), "text/csv"
