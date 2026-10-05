# Packet model

Packet summaries retain capture ID, one-based frame number, timestamp, original
wire length, captured length, on-disk payload offset, link type, addresses,
transport ports/flags and payload length. Raw payload bytes stay in the original
capture, never in a JSON blob. Detail rereads one bounded frame and verifies the
capture hash first. Optional hex output is capped at 4096 bytes and marked if cut.

Supported framing: micro/nanosecond PCAP in both byte orders, PCAPNG enhanced,
obsolete and simple packet blocks, multiple sections/interfaces and timestamp
resolution/offset options. Simple blocks have no timestamps; warnings explicitly
exclude time-based conclusions. Invalid framing fails the job. Malformed individual
packets remain visible with decode warnings.
For untimed simple blocks, numeric timestamp zero is an explicit storage sentinel,
not an observed 1970 event; the accompanying capture warning must be retained when
consuming the API/export.

Link decoding: Ethernet/VLAN through dpkt, raw IP, loopback, Linux cooked v1/v2.
Unknown link/transport types and fragmented IP datagrams retain evidence with
explicit visibility warnings; fragment reconstruction is not attempted.

Packet detail also joins actual DNS/HTTP/TLS/certificate observations whose
request/response/reference frame matches the selected packet. The UI renders
these as expandable structured fields, not invented per-packet session content.
Protocol distributions and packet/flow tables explicitly label port-only hints.
