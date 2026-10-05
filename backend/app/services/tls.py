import hashlib
import struct

import dpkt
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes

from app.models import Certificate, Session, TLSSession, uid
from app.services.reassembly import tcp_streams

VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def grease(value):
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def vector16(data):
    if len(data) % 2:
        raise ValueError("Odd TLS vector length")
    return list(struct.unpack("!" + "H" * (len(data) // 2), data))


def client_metadata(body):
    hello = dpkt.ssl.TLSClientHello(body)
    extensions = getattr(hello, "extensions", [])
    ciphers = [suite.code for suite in hello.ciphersuites if not grease(suite.code)]
    groups, formats, sni, offered = [], [], None, []
    extension_ids = []
    for kind, value in extensions:
        if not grease(kind):
            extension_ids.append(kind)
        if kind == 0 and len(value) >= 5:
            length = int.from_bytes(value[3:5], "big")
            if value[2] == 0 and length == len(value) - 5:
                sni = value[5:].decode("idna").lower().rstrip(".")
        elif kind == 10 and len(value) >= 2:
            groups = [v for v in vector16(value[2:]) if not grease(v)]
        elif kind == 11 and value:
            formats = list(value[1:])
        elif kind == 43 and value:
            offered = [VERSIONS.get(v, hex(v)) for v in vector16(value[1:]) if not grease(v)]
    raw = ",".join([str(hello.version), "-".join(map(str, ciphers)), "-".join(map(str, extension_ids)),
                    "-".join(map(str, groups)), "-".join(map(str, formats))])
    return {"sni": sni, "ja3": hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest(),
            "ja3_string": raw, "client_legacy_version": VERSIONS.get(hello.version, hex(hello.version)),
            "offered_versions": offered, "offered_ciphers": [hex(value) for value in ciphers]}


def certificate_fields(der):
    cert = x509.load_der_x509_certificate(der)
    try:
        sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    self_signed = False
    if cert.subject == cert.issuer:
        try:
            cert.verify_directly_issued_by(cert)
            self_signed = True
        except (ValueError, TypeError, InvalidSignature):
            pass
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "serial": str(cert.serial_number), "valid_from": cert.not_valid_before_utc.timestamp(),
            "valid_until": cert.not_valid_after_utc.timestamp(), "signature_algorithm": cert.signature_algorithm_oid.dotted_string,
            "sha256": cert.fingerprint(hashes.SHA256()).hex(), "sans": sans, "self_signed": self_signed}


def analyze_tls(db, path, flow, settings):
    streams = tcp_streams(db, path, flow, settings)
    warnings = [w for stream in streams for w in stream.warnings]
    first_packet, client, version, cipher = None, {}, None, None
    certificates = []
    encrypted = False
    for stream in streams:
        position = 0
        handshake = bytearray()
        handshake_packet = None
        while position + 5 <= len(stream.data):
            record_length = int.from_bytes(stream.data[position + 3:position + 5], "big")
            if record_length > 18432 or position + 5 + record_length > len(stream.data):
                warnings.append("TLS record truncated or outside supported bounds")
                break
            try:
                record = dpkt.ssl.TLSRecord(stream.data[position:position + 5 + record_length])
                packet = stream.packet_at(position)
                first_packet = first_packet or packet
                if record.type == 23:
                    encrypted = True
                if record.type == 22:
                    if not handshake:
                        handshake_packet = packet
                    handshake.extend(record.data)
                    while len(handshake) >= 4:
                        kind = handshake[0]
                        length = int.from_bytes(handshake[1:4], "big")
                        if length > settings.max_stream_bytes:
                            raise ValueError("TLS handshake exceeds reconstruction limit")
                        if len(handshake) < 4 + length:
                            break
                        body = bytes(handshake[4:4 + length])
                        del handshake[:4 + length]
                        if kind == 1:
                            client = client_metadata(body)
                        elif kind == 2:
                            hello = dpkt.ssl.TLSServerHello(body)
                            negotiated = hello.version
                            for extension, value in getattr(hello, "extensions", []):
                                if extension == 43 and len(value) == 2:
                                    negotiated = int.from_bytes(value, "big")
                            version = VERSIONS.get(negotiated, hex(negotiated))
                            cipher = hex(hello.ciphersuite.code)
                        elif kind == 11 and version != "TLS 1.3":
                            if len(body) < 3 or int.from_bytes(body[:3], "big") != len(body) - 3:
                                raise ValueError("Invalid observable TLS certificate list")
                            offset = 3
                            while offset + 3 <= len(body):
                                cert_length = int.from_bytes(body[offset:offset + 3], "big")
                                offset += 3
                                if cert_length > 65536 or cert_length == 0 or offset + cert_length > len(body) or len(certificates) >= 16:
                                    raise ValueError("Certificate length/count limit")
                                certificates.append((handshake_packet, certificate_fields(body[offset:offset + cert_length])))
                                offset += cert_length
                        handshake_packet = packet
            except (dpkt.UnpackError, ValueError, IndexError, UnicodeError, struct.error) as exc:
                warnings.append(f"TLS metadata incomplete: {type(exc).__name__}")
                break
            position += 5 + record_length
        if handshake:
            warnings.append("TLS handshake fragmented beyond captured contiguous records")
    if first_packet:
        session = Session(id=uid(), capture_id=flow.capture_id, flow_id=flow.id, protocol="TLS",
                          timestamp=first_packet.timestamp, frame_number=first_packet.frame_number,
                          end_frame=flow.last_frame, status="metadata only",
                          metadata_fields={"warnings": sorted(set(warnings))})
        db.add(session)
        db.flush()
        tls = TLSSession(id=uid(), capture_id=flow.capture_id, session_id=session.id, flow_id=flow.id,
                         frame_number=first_packet.frame_number, timestamp=first_packet.timestamp,
                         source_ip=flow.source_ip, destination_ip=flow.destination_ip, sni=client.get("sni"),
                         version=version, cipher_suite=cipher, ja3=client.get("ja3"),
                         metadata_fields={**client, "warnings": sorted(set(warnings)),
                                          "certificate_visibility": "observed" if certificates else "unavailable",
                                          "encrypted_records_observed": encrypted, "ja4": "unsupported",
                                          "visibility": "No arbitrary TLS decryption. Offered versions are not negotiated versions."})
        db.add(tls)
        db.flush()
        for packet, fields in certificates:
            db.add(Certificate(capture_id=flow.capture_id, tls_id=tls.id, frame_number=packet.frame_number, **fields))
        flow.application, flow.identification = "TLS", "content"
    return sorted(set(warnings))
