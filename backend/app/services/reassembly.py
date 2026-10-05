from dataclasses import dataclass, field

import dpkt
from sqlalchemy import select

from app.models import PacketSummary
from app.services.packets import decode, exact


@dataclass
class Stream:
    data: bytes = b""
    spans: list = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    source_ip: str = ""
    destination_ip: str = ""

    def packet_at(self, offset):
        for start, end, packet in self.spans:
            if start <= offset < end:
                return packet
        return self.spans[0][2] if self.spans else None


def signed_sequence(sequence, anchor):
    return ((sequence - anchor + 2**31) % 2**32) - 2**31


def tcp_streams(db, path, flow, settings):
    segments = [[], []]
    anchors = [None, None]
    retained = [0, 0]
    warnings = [set(), set()]
    query = select(PacketSummary).where(PacketSummary.flow_id == flow.id).order_by(PacketSummary.frame_number)
    with path.open("rb") as handle:
        for packet in db.scalars(query).yield_per(256):
            direction = 0 if (packet.source_ip, packet.source_port) == (flow.source_ip, flow.source_port) else 1
            tcp = packet.metadata_fields.get("tcp", {})
            if not tcp:
                continue
            sequence = tcp["sequence"]
            if packet.flags & dpkt.tcp.TH_SYN:
                anchors[direction] = (sequence + 1) % 2**32
                sequence = anchors[direction]
            if not packet.payload_length:
                continue
            if retained[direction] + packet.payload_length > settings.max_stream_bytes:
                warnings[direction].add("TCP reconstruction byte limit reached")
                continue
            if len(segments[direction]) >= settings.max_stream_segments:
                warnings[direction].add("TCP reconstruction segment limit reached")
                continue
            handle.seek(packet.offset)
            _, payload = decode(exact(handle, packet.captured_length), packet.link_type)
            retained[direction] += len(payload)
            segments[direction].append((sequence, payload, packet))
            if packet.captured_length < packet.length:
                warnings[direction].add("Snapshot-truncated TCP stream")
    result = []
    for direction in range(2):
        stream = Stream(source_ip=flow.source_ip if direction == 0 else flow.destination_ip,
                        destination_ip=flow.destination_ip if direction == 0 else flow.source_ip)
        chunks = segments[direction]
        if chunks:
            anchor = anchors[direction]
            if anchor is None:
                first = chunks[0][0]
                anchor = min(chunks, key=lambda item: signed_sequence(item[0], first))[0]
                warnings[direction].add("TCP stream begins without an observed SYN; earlier content may be missing")
            chunks.sort(key=lambda item: signed_sequence(item[0], anchor))
            data = bytearray()
            for sequence, payload, packet in chunks:
                position = signed_sequence(sequence, anchor)
                if position < 0:
                    warnings[direction].add("TCP sequence precedes observed stream origin")
                    continue
                if position > len(data):
                    warnings[direction].add("TCP sequence gap: only contiguous prefix reconstructed")
                    break
                overlap = min(len(payload), len(data) - position)
                if overlap and data[position:position + overlap] != payload[:overlap]:
                    warnings[direction].add("Conflicting TCP retransmission: reconstruction is ambiguous")
                if overlap < len(payload):
                    start = len(data)
                    data.extend(payload[overlap:])
                    stream.spans.append((start, len(data), packet))
            stream.data = bytes(data)
        stream.warnings = sorted(warnings[direction])
        result.append(stream)
    return result
