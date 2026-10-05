import hashlib
import io
import re

import dpkt

from app.models import HTTPSession, Session, uid
from app.services.reassembly import tcp_streams


def messages(stream, response=False, methods=None):
    """Decode HTTP/1 framing only. Return bounded bodies in memory, never execute."""
    offset, index = 0, 0
    while offset < len(stream.data):
        start = offset
        end = stream.data.find(b"\r\n\r\n", offset)
        if end < 0 or end - offset > 65536:
            yield {"warning": "HTTP headers incomplete or over 64 KiB", "offset": start}
            return
        header = stream.data[offset:end]
        first, _, remainder = header.partition(b"\r\n")
        try:
            line = first.decode("ascii")
            if response:
                match = re.fullmatch(r"HTTP/1\.[01] (\d{3})(?: .*)?", line)
                if not match:
                    return
                status = int(match.group(1))
                method, uri = None, None
            else:
                match = re.fullmatch(r"([A-Z-]{1,30}) (\S{1,16384}) HTTP/1\.[01]", line)
                if not match:
                    return
                method, uri, status = match.group(1), match.group(2), None
            headers = dpkt.http.parse_headers(io.BytesIO(remainder + b"\r\n\r\n"))
            # Duplicate framing fields create ambiguous message boundaries.
            if any(isinstance(headers.get(key), list) for key in ("content-length", "transfer-encoding", "host")):
                yield {"warning": "Ambiguous duplicate HTTP framing headers", "offset": start}
                return
            offset = end + 4
            body, complete = b"", True
            body_start = offset
            no_body = response and (status in (204, 304) or status < 200 or
                                    (methods and index < len(methods) and methods[index] == "HEAD"))
            if not no_body:
                if "transfer-encoding" in headers:
                    if headers["transfer-encoding"].lower() != "chunked" or "content-length" in headers:
                        yield {"warning": "Unsupported or ambiguous HTTP transfer encoding", "offset": start}
                        return
                    source = io.BytesIO(stream.data[offset:])
                    try:
                        body = dpkt.http.parse_body(source, headers)
                        offset += source.tell()
                    except dpkt.UnpackError:
                        complete = False
                        offset = len(stream.data)
                elif "content-length" in headers:
                    length = int(headers["content-length"])
                    if length < 0:
                        raise ValueError("Negative Content-Length")
                    body = stream.data[offset:offset + length]
                    complete = len(body) == length
                    offset += len(body)
                elif response:
                    body, complete = stream.data[offset:], False
                    offset = len(stream.data)
            blocking = [w for w in stream.warnings if "without an observed SYN" not in w]
            yield {"offset": start, "packet": stream.packet_at(start), "method": method, "uri": uri,
                   "status": status, "headers": headers, "body": body, "complete": complete and not blocking,
                   "size": offset - start, "body_offset": body_start}
            if not complete or (response and status == 101):
                return
            if not response or status >= 200:
                index += 1
        except (ValueError, UnicodeError, dpkt.UnpackError) as exc:
            yield {"warning": f"HTTP parse incomplete: {type(exc).__name__}", "offset": start}
            return


def http_pairs(db, path, flow, settings):
    streams = tcp_streams(db, path, flow, settings)
    request_stream = next((s for s in streams if re.match(rb"[A-Z-]{1,30} \S+ HTTP/1", s.data)), None)
    response_stream = next((s for s in streams if s.data.startswith(b"HTTP/1.")), None)
    requests = list(messages(request_stream)) if request_stream else []
    methods = [r.get("method") for r in requests if "warning" not in r]
    responses = list(messages(response_stream, True, methods)) if response_stream else []
    warnings = [w for s in streams for w in s.warnings]
    warnings += [r["warning"] for r in requests + responses if "warning" in r]
    requests = [r for r in requests if "warning" not in r]
    responses = [r for r in responses if "warning" not in r and r["status"] >= 200]
    pairs = [(requests[i] if i < len(requests) else None, responses[i] if i < len(responses) else None)
             for i in range(max(len(requests), len(responses)))]
    return pairs, sorted(set(warnings))


def analyze_http(db, path, flow, settings):
    pairs, warnings = http_pairs(db, path, flow, settings)
    for request, response in pairs:
        first = request or response
        packet = first["packet"]
        req_headers = request["headers"] if request else {}
        res_headers = response["headers"] if response else {}
        session = Session(id=uid(), capture_id=flow.capture_id, flow_id=flow.id, protocol="HTTP",
                          timestamp=packet.timestamp, frame_number=packet.frame_number,
                          end_frame=response["packet"].frame_number if response else packet.frame_number,
                          status="request/response observed" if request and response else "one-sided observation",
                          metadata_fields={"visibility": "Cleartext HTTP/1 only", "warnings": warnings})
        db.add(session)
        db.flush()
        body_complete = bool(response and response["complete"])
        if response and not body_complete and "HTTP body incomplete or reconstruction ambiguous" not in warnings:
            warnings.append("HTTP body incomplete or reconstruction ambiguous")
        body = response["body"] if response else None
        db.add(HTTPSession(capture_id=flow.capture_id, session_id=session.id, flow_id=flow.id,
                           frame_number=packet.frame_number, timestamp=packet.timestamp,
                           response_frame=response["packet"].frame_number if response else None,
                           source_ip=packet.source_ip if request else packet.destination_ip,
                           destination_ip=packet.destination_ip if request else packet.source_ip,
                           method=request["method"] if request else None, host=req_headers.get("host"),
                           uri=request["uri"] if request else None, status_code=response["status"] if response else None,
                           user_agent=req_headers.get("user-agent"), referer=req_headers.get("referer"),
                           content_type=res_headers.get("content-type"), request_size=request["size"] if request else 0,
                           response_size=response["size"] if response else 0,
                           body_sha256=hashlib.sha256(body).hexdigest() if body_complete else None,
                           body_size=len(body) if body is not None else None, body_complete=body_complete,
                           metadata_fields={"warnings": warnings, "body_framing_complete": body_complete,
                                            "request_offset": request["offset"] if request else None,
                                            "response_offset": response["offset"] if response else None,
                                            "content_encoding": res_headers.get("content-encoding"),
                                            "request_headers": req_headers, "response_headers": res_headers}))
    if pairs:
        flow.application, flow.identification = "HTTP", "content"
    else:
        warnings.append("HTTP not confirmed by observable content; port hint only")
    return warnings
