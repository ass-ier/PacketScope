# Safe, synthetic capture fixtures

`generate.py` constructs bytes locally with dpkt. It sends no traffic, includes
no malicious executable and never contacts the named addresses. IPv4 TEST-NET,
IPv6 documentation and `.test` domain values are deliberate.

```sh
.venv/bin/python fixtures/generate.py --output artifacts/fixtures
```

Both PCAP and PCAPNG are generated for each fixture. Exact expectations live in
`EXPECTATIONS` and are verified by `test_fixture_acceptance.py` for both formats.
Generated capture files are ignored rather than committed.

| Fixture / purpose | Packets | Flows | Expected rule IDs |
|---|---:|---:|---|
| Normal DNS query/answer | 2 | 1 | None |
| Normal HTTP request/response | 7 | 1 | None |
| Normal TLS ClientHello, no certificate | 1 | 1 | None |
| Distinct TCP port attempts | 30 | 30 | port-scan |
| Eight periodic closed HTTP conversations | 56 | 8 | beacon |
| Identical unanswered SYN retransmissions | 8 | 1 | None |
| IPv6 connection attempt | 1 | 1 | None |
| 6.14 MB benign outbound payload | 128 | 1 | large-transfer |
| Long encoded-looking DNS labels | 50 | 1 | dns-anomaly |
| Conflicting ARP reply associations | 2 | 1 | arp-conflict |
| Multiple internal destinations | 16 | 16 | host-scan |
| Mixed DNS/HTTP/TLS/IPv6 | 11 | 4 | None |

Additional in-test fixtures cover DNS collisions and answer types, DHCP, ICMP,
SMB header visibility, certificate validity, partial/ambiguous HTTP and TCP
reordering. Private certificate keys exist only in test-process memory.
