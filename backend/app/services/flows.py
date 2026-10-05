import dpkt

from app.models import Flow, Host, uid


class FlowBuilder:
    def __init__(self, capture_id, settings, db):
        self.capture_id, self.settings, self.db = capture_id, settings, db
        self.current = {}
        self.hosts = {}
        self.flows = []

    def accept(self, packet):
        fields, timestamp, frame = packet, packet["timestamp"], packet["frame_number"]
        src, dst = fields["source_ip"], fields["destination_ip"]
        if not src or not dst:
            return None
        sport, dport = fields["source_port"] or 0, fields["destination_port"] or 0
        transport = fields["transport"] or fields["protocol"]
        forward, reverse = (src, sport), (dst, dport)
        key = (transport, *sorted((forward, reverse)))
        flow = self.current.get(key)
        flags = fields["flags"]
        seq = fields["metadata_fields"].get("tcp", {}).get("sequence")
        syn = bool(flags & dpkt.tcp.TH_SYN and not flags & dpkt.tcp.TH_ACK)
        new = flow is None
        if flow:
            idle = timestamp - flow.end_time > (120 if transport == "TCP" else 30)
            same_syn = syn and seq == flow.initial_seq and forward == (flow.source_ip, flow.source_port)
            # Retransmitted unanswered SYNs are one attempt, even across an idle gap.
            retransmission = same_syn and flow.state == "syn observed"
            new = (idle and not retransmission) or (syn and not same_syn) or (
                syn and same_syn and flow.state in ("closed", "reset"))
        if new:
            if len(self.flows) >= self.settings.max_flows:
                raise ValueError(f"Flow limit exceeded ({self.settings.max_flows})")
            flow = Flow(id=uid(), capture_id=self.capture_id, source_ip=src, destination_ip=dst,
                        source_port=sport, destination_port=dport, protocol=transport,
                        application=fields["protocol"], identification=fields["metadata_fields"].get(
                            "identification", "content"), start_time=timestamp, end_time=timestamp,
                        first_frame=frame, last_frame=frame, initial_seq=seq if syn else None,
                        packet_count=0, bytes_sent=0, bytes_received=0, payload_sent=0, payload_received=0,
                        flags=0, state="observed", duration=0.0)
            self.current[key] = flow
            self.flows.append(flow)
            self.db.add(flow)
        forward_direction = forward == (flow.source_ip, flow.source_port)
        flow.start_time, flow.end_time = min(flow.start_time, timestamp), max(flow.end_time, timestamp)
        flow.duration = flow.end_time - flow.start_time
        flow.last_frame = frame
        flow.packet_count += 1
        flow.flags |= flags
        if forward_direction:
            flow.bytes_sent += fields["length"]
            flow.payload_sent += fields["payload_length"]
        else:
            flow.bytes_received += fields["length"]
            flow.payload_received += fields["payload_length"]
        if fields["metadata_fields"].get("identification") == "content":
            flow.application, flow.identification = fields["protocol"], "content"
        if transport == "TCP":
            if flags & dpkt.tcp.TH_RST:
                flow.state = "reset"
            elif flags & dpkt.tcp.TH_FIN:
                flow.state = "closed"
            elif flow.state not in ("closed", "reset"):
                if syn and flow.state == "observed":
                    flow.state = "syn observed"
                elif flags & dpkt.tcp.TH_SYN and flags & dpkt.tcp.TH_ACK:
                    flow.state = "syn-ack observed"
                elif flags & dpkt.tcp.TH_ACK and flow.state == "syn-ack observed":
                    flow.state = "handshake observed"
        for ip, port, mac_field, sent in [(src, sport, "source_mac", True), (dst, dport, "destination_mac", False)]:
            if ip not in self.hosts:
                if len(self.hosts) >= self.settings.max_hosts:
                    raise ValueError(f"Host limit exceeded ({self.settings.max_hosts})")
                host = Host(id=uid(), capture_id=self.capture_id, ip=ip, mac=fields[mac_field],
                            first_seen=timestamp, last_seen=timestamp, protocols=[], ports=[], connections=0,
                            bytes_sent=0, bytes_received=0)
                self.hosts[ip] = host
                self.db.add(host)
            host = self.hosts[ip]
            host.first_seen, host.last_seen = min(host.first_seen, timestamp), max(host.last_seen, timestamp)
            host.protocols = sorted(set(host.protocols + [fields["protocol"]]))
            host.ports = sorted(set(host.ports + ([port] if port else [])))
            if new:
                host.connections += 1
            if sent:
                host.bytes_sent += fields["length"]
            else:
                host.bytes_received += fields["length"]
        return flow.id
