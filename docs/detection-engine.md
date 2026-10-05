# Deterministic evidence-based rules

Nine rule definitions live in `detection-rules/defaults.json` and are seeded into
SQLite. Settings/API edits validate named thresholds, enabled state and supported
ATT&CK mappings. No eval, shell commands or uploaded rule code. Changes apply to
future captures; every finding snapshots its rule and configuration.

| Rule | Default condition |
|---|---|
| Port scan | 20 distinct TCP destination ports to one host in 10s |
| Host scan | 15 internal destination hosts from one source in 30s |
| Periodicity | 6 bidirectional TCP conversations, mean interval >=2s, CV <=0.1 |
| DNS | 20 queries/60s plus long high-entropy encoded-looking labels or >=80% NXDOMAIN; alternatively 100 queries/60s |
| Large transfer | >=5 MiB outbound wire bytes and >=5:1 ratio, internal to external |
| Repeated connection | Configured port, external destination, 3 bidirectional conversations, >=512 payload bytes |
| ARP conflict | Two sender MACs claim one IP in observed replies |
| HTTP metadata | Unusual method, configured agent substring, long/command-looking URI, large reconstructed response |
| TLS certificate | Expired/not-yet-valid **at capture time**, short validity, verified self-signature or detectable SAN mismatch |

Internal means RFC1918 IPv4 or ULA IPv6, not every special-use address that Python
labels private. All counters derive from normalized evidence. Retransmitted SYNs
are not new connections. Periodicity requires bidirectional activity, and never
proves C2. Findings include actual statistics, confidence, severity and up to 200
representative evidence references; larger support sets are explicitly labelled.

These are conservative indicators, not baselines learned from a network.
Backups, health checks, software updates, inventories, misconfiguration, shared
hosting and duplicate-address transitions can trigger benign matches. Missing
traffic, NAT and sophisticated activity can evade these rules.
