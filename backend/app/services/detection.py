import ipaddress
import json
import math
import statistics
from collections import Counter, defaultdict, deque
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import unquote

from fastapi import HTTPException
from sqlalchemy import select

from app.models import Certificate, DNSQuery, DetectionRule, Evidence, Finding, Flow, Host, HTTPSession, Session, TLSSession, uid
from app.services.query import record

RULE_PATH = Path(__file__).parents[3] / "detection-rules/defaults.json"
INTERNAL = [ipaddress.ip_network(network) for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def internal(ip):
    address = ipaddress.ip_address(ip)
    return any(address in network for network in INTERNAL)


def seed_rules(db):
    for rule in json.loads(RULE_PATH.read_text()):
        if db.get(DetectionRule, rule["id"]) is None:
            db.add(DetectionRule(**rule))
    db.commit()


def update_rule(db, rule, changes):
    defaults = next(item for item in json.loads(RULE_PATH.read_text()) if item["id"] == rule.id)
    if changes.get("config") is not None:
        config = {**rule.config, **changes["config"]}
        if set(config) != set(defaults["config"]):
            raise HTTPException(422, "Unknown detection configuration field")
        for key, default in defaults["config"].items():
            value = config[key]
            if isinstance(default, list):
                if not isinstance(value, list) or not value or len(value) > 100:
                    raise HTTPException(422, f"{key} must be a nonempty list of at most 100 values")
                if key == "ports":
                    valid = all(type(item) is int and 1 <= item <= 65535 for item in value)
                else:
                    valid = all(isinstance(item, str) and 1 <= len(item) <= 100 for item in value)
            else:
                valid = type(value) in (int, float) and math.isfinite(value) and 0 < value <= 1_000_000_000
                if isinstance(default, int):
                    valid = valid and float(value).is_integer()
                if key in ("max_cv", "nxdomain_ratio"):
                    valid = valid and value <= 1
            if not valid:
                raise HTTPException(422, f"Invalid threshold for {key}")
        rule.config = config
    if changes.get("enabled") is not None:
        rule.enabled = changes["enabled"]
    if changes.get("attack_mapping") is not None:
        allowed = {"port-scan": {"T1046"}, "host-scan": {"T1046"}, "beacon": {"T1071"}}.get(rule.id, set())
        if not set(changes["attack_mapping"]).issubset(allowed):
            raise HTTPException(422, "Mapping is not supported by this rule's evidence semantics")
        rule.attack_mapping = changes["attack_mapping"]
    db.commit()
    return record(rule)


def timestamp(row):
    return getattr(row, "timestamp", getattr(row, "start_time", 0))


def windows(rows, seconds):
    rows = sorted((row for row in rows if timestamp(row) > 0), key=timestamp)
    left = 0
    for right, row in enumerate(rows):
        while timestamp(row) - timestamp(rows[left]) > seconds:
            left += 1
        yield rows[left:right + 1]


def entropy(value):
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values()) if value else 0


def distinct_window(rows, seconds, field, threshold):
    queue, counts = deque(), Counter()
    for row in sorted((row for row in rows if timestamp(row) > 0), key=timestamp):
        queue.append(row)
        counts[getattr(row, field)] += 1
        while timestamp(row) - timestamp(queue[0]) > seconds:
            old = getattr(queue.popleft(), field)
            counts[old] -= 1
            if not counts[old]:
                del counts[old]
        if len(counts) >= threshold:
            return list(queue), sorted(counts)
    return [], []


def dns_matches(pattern, host):
    pattern, host = pattern.rstrip(".").lower(), host.rstrip(".").lower()
    if pattern.startswith("*."):
        return host.count(".") == pattern.count(".") and host.endswith(pattern[1:])
    return pattern == host


def detect(db, capture, checkpoint):
    rules = {rule.id: rule for rule in db.scalars(select(DetectionRule).where(DetectionRule.enabled.is_(True)))}
    flows = list(db.scalars(select(Flow).where(Flow.capture_id == capture.id)))
    hosts = {host.ip: host.id for host in db.scalars(select(Host).where(Host.capture_id == capture.id))}

    def emit(rule_id, rows, stats, source=None, destination=None, reasons=None):
        if rule_id not in rules or not rows:
            return
        rule = rules[rule_id]
        selected = sorted(rows, key=timestamp)
        evidence = selected[:200]
        description = rule.description + (" " + "; ".join(reasons) if reasons else "")
        finding = Finding(id=uid(), capture_id=capture.id, rule_id=rule_id, title=rule.name,
                          description=description, severity=rule.severity, confidence=rule.confidence,
                          source_ip=source, destination_ip=destination, timestamp=timestamp(selected[0]),
                          evidence_count=len(evidence), statistics={**stats, "supporting_observations": len(rows),
                                                                   "evidence_is_representative": len(rows) > 200},
                          rule_snapshot=record(rule))
        db.add(finding)
        db.flush()
        for row in evidence:
            frame = getattr(row, "frame_number", getattr(row, "first_frame", None))
            db.add(Evidence(capture_id=capture.id, frame_number=frame, timestamp=timestamp(row),
                            flow_id=row.id if isinstance(row, Flow) else getattr(row, "flow_id", None),
                            session_id=row.id if isinstance(row, Session) else getattr(row, "session_id", None),
                            host_id=hosts.get(source), finding_id=finding.id,
                            description=f"{rule.name}: representative supporting observation"))

    by_pair, by_source, by_endpoint = defaultdict(list), defaultdict(list), defaultdict(list)
    for flow in flows:
        checkpoint()
        if flow.protocol != "TCP":
            continue
        by_pair[(flow.source_ip, flow.destination_ip)].append(flow)
        by_source[flow.source_ip].append(flow)
        by_endpoint[(flow.source_ip, flow.destination_ip, flow.destination_port)].append(flow)
    if "port-scan" in rules:
        config = rules["port-scan"].config
        for (src, dst), group in by_pair.items():
            window, ports = distinct_window(group, config["window_seconds"], "destination_port", config["min_ports"])
            if window:
                emit("port-scan", window, {"destination_ports": ports, "distinct_ports": len(ports),
                                          "window_seconds": timestamp(window[-1]) - timestamp(window[0])}, src, dst)
    if "host-scan" in rules:
        config = rules["host-scan"].config
        for src, group in by_source.items():
            window, destinations = distinct_window([flow for flow in group if internal(flow.destination_ip)],
                                                    config["window_seconds"], "destination_ip", config["min_hosts"])
            if window:
                emit("host-scan", window, {"destination_hosts": destinations,
                                          "window_seconds": timestamp(window[-1]) - timestamp(window[0])}, src)
    for (src, dst, port), group in by_endpoint.items():
        checkpoint()
        bidirectional = sorted([flow for flow in group if flow.bytes_received > 0 and flow.payload_sent > 0
                                and flow.start_time > 0], key=lambda flow: flow.start_time)
        if "beacon" in rules:
            config = rules["beacon"].config
            if len(bidirectional) >= config["min_connections"]:
                intervals = [b.start_time - a.start_time for a, b in zip(bidirectional, bidirectional[1:])]
                mean = statistics.mean(intervals)
                cv = statistics.pstdev(intervals) / mean if mean else float("inf")
                if mean >= config["min_interval"] and cv <= config["max_cv"]:
                    emit("beacon", bidirectional, {"intervals": intervals, "mean_seconds": mean,
                                                   "coefficient_of_variation": cv, "port": port,
                                                   "applications": sorted({flow.application for flow in bidirectional})}, src, dst)
        if "suspicious-connection" in rules:
            config = rules["suspicious-connection"].config
            payload_bytes = sum(flow.payload_sent + flow.payload_received for flow in bidirectional)
            if (port in config["ports"] and not internal(dst) and len(bidirectional) >= config["min_connections"]
                    and payload_bytes >= config["min_payload_bytes"]):
                emit("suspicious-connection", bidirectional, {"port": port, "connections": len(bidirectional),
                                                             "payload_bytes": payload_bytes}, src, dst)
    if "large-transfer" in rules:
        config = rules["large-transfer"].config
        for flow in flows:
            ratio = flow.bytes_sent / max(flow.bytes_received, 1)
            if (internal(flow.source_ip) and not internal(flow.destination_ip) and flow.bytes_sent >= config["min_bytes"]
                    and ratio >= config["min_ratio"]):
                emit("large-transfer", [flow], {"wire_bytes_sent": flow.bytes_sent, "wire_bytes_received": flow.bytes_received,
                                               "ratio": ratio, "accounting": "Original wire frame lengths; retransmissions included"},
                     flow.source_ip, flow.destination_ip)
    if "dns-anomaly" in rules:
        config = rules["dns-anomaly"].config
        grouped = defaultdict(list)
        for query in db.scalars(select(DNSQuery).where(DNSQuery.capture_id == capture.id)):
            grouped[query.source_ip].append(query)
        for src, queries in grouped.items():
            for window in windows(queries, config["window_seconds"]):
                if len(window) < config["min_queries"]:
                    continue
                labels = [q.name.split(".")[0] for q in window]
                length, random = statistics.mean(map(len, labels)), statistics.mean(map(entropy, labels))
                negative = sum(q.response_code == 3 for q in window) / len(window)
                encoded = sum(label.isalnum() and len(label) >= config["min_label_length"] for label in labels)
                if (len(window) >= config["high_frequency"] or negative >= config["nxdomain_ratio"] or
                        (length >= config["min_label_length"] and random >= config["min_entropy"] and encoded / len(window) >= .8)):
                    emit("dns-anomaly", window, {"query_count": len(window), "mean_label_length": length,
                                                 "mean_entropy": random, "nxdomain_ratio": negative,
                                                 "encoded_looking_labels": encoded}, src)
                    break
    if "arp-conflict" in rules:
        associations = defaultdict(list)
        for session in db.scalars(select(Session).where(Session.capture_id == capture.id, Session.protocol == "ARP")):
            if session.metadata_fields.get("operation") == 2:
                associations[session.metadata_fields.get("sender_ip")].append(session)
        for ip, rows in associations.items():
            macs = sorted({row.metadata_fields["sender_mac"] for row in rows})
            if len(macs) >= rules["arp-conflict"].config["min_macs"]:
                emit("arp-conflict", rows, {"ip": ip, "mac_addresses": macs}, ip)
    if "http-indicator" in rules:
        config = rules["http-indicator"].config
        for http in db.scalars(select(HTTPSession).where(HTTPSession.capture_id == capture.id)):
            reasons = []
            if http.method and http.method not in config["allowed_methods"]:
                reasons.append(f"Unusual method {http.method}")
            if any(agent.lower() in (http.user_agent or "").lower() for agent in config["user_agents"]):
                reasons.append("Configured user-agent substring observed")
            if len(http.uri or "") > config["max_uri_length"]:
                reasons.append("Long request URI")
            if any(pattern in unquote(http.uri or "").lower() for pattern in ("cmd=", "/bin/sh", "powershell", "exec=")):
                reasons.append("Command-looking URI parameter; not executed or proven malicious")
            if http.response_size > config["max_response_bytes"]:
                reasons.append("Large reconstructed HTTP response")
            if reasons:
                emit("http-indicator", [http], {"method": http.method, "uri": http.uri, "user_agent": http.user_agent,
                                               "reasons": reasons}, http.source_ip, http.destination_ip, reasons)
    if "tls-certificate" in rules:
        for cert, tls in db.execute(select(Certificate, TLSSession).join(TLSSession)
                                    .where(Certificate.capture_id == capture.id)):
            reasons = []
            if tls.timestamp > 0 and tls.timestamp > cert.valid_until:
                reasons.append("Expired at capture time")
            if tls.timestamp > 0 and tls.timestamp < cert.valid_from:
                reasons.append("Not yet valid at capture time")
            if cert.self_signed:
                reasons.append("Verified self-signed certificate")
            if cert.valid_until - cert.valid_from < rules["tls-certificate"].config["short_validity_days"] * 86400:
                reasons.append("Short validity period")
            if tls.sni and cert.sans and not any(dns_matches(san, tls.sni) for san in cert.sans):
                reasons.append("SNI does not match observed DNS SANs")
            if reasons:
                observed = SimpleNamespace(timestamp=tls.timestamp, frame_number=cert.frame_number,
                                           flow_id=tls.flow_id, session_id=tls.session_id)
                emit("tls-certificate", [observed], {"certificate_sha256": cert.sha256, "certificate_frame": cert.frame_number,
                                                "capture_timestamp": tls.timestamp, "valid_from": cert.valid_from,
                                                "valid_until": cert.valid_until, "reasons": reasons},
                     tls.source_ip, tls.destination_ip, reasons)
    db.commit()
