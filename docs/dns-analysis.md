# DNS analysis

UDP DNS and bounded, length-prefixed DNS over TCP are decoded with dpkt.
Correlation keys include transport, both IP/port endpoints, transaction ID,
normalized question name and type. Replies match unanswered queries within 30s.
Unmatched replies are retained as sessions with explicit visibility notices.

Query and answer records are relational, with request/response frame references,
query type, response code, latency, answer name/value and TTL. A, AAAA, CNAME,
MX, NS, TXT, PTR and SRV are decoded. Other types retain bounded RDATA hex.
DNS over HTTPS/TLS and mDNS-specific semantics are not inferred.
