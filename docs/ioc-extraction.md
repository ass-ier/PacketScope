# Observed indicators

An IOC is an investigable observation, not a malicious verdict. IP/IPv6/MAC
endpoints, DNS names/answers, HTTP hosts/URLs and visible email/hash strings,
TLS SNI, certificate SHA-256 and JA3 are normalized and deduplicated per capture.
Domains use lowercase IDNA; IPs canonical notation; URL paths/queries retain
case and encoding while scheme/host/default port normalize. Fragments are not
network request evidence. Invalid candidates are not invented into valid IOCs.

Relational Evidence rows preserve representative frame, flow, session and host
associations and timestamps. First/last occurrence survives deduplication.
The explorer links to those observations; global search traverses related
captures and cases. Results and evidence views are bounded.

TXT, CSV, JSON and STIX exports work offline. CSV neutralizes formula prefixes.
STIX 2.1 exports cyber-observables with ObservedData and evidence Notes, **not
malicious Indicator objects**. JA3 uses an explicit custom fingerprint SCO.
No reputation, live DNS resolution or external enrichment occurs automatically.
