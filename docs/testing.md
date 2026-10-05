# Verification and practical performance

## Reproducible commands

From the repository root, after installation:

```sh
cd backend
../.venv/bin/pytest --cov=app --cov-report=term-missing
../.venv/bin/ruff check app tests migrations benchmark.py
../.venv/bin/pip-audit --progress-spinner=off
cd ../frontend
npm run typecheck
npm run build
npm audit --audit-level=moderate
PLAYWRIGHT_BROWSERS_PATH=../artifacts/pw-browsers npx playwright install chromium
npm run test:e2e
```

Browser tests use a separate auto-started/stopped server on 127.0.0.1:8766 and an
ignored synthetic database at `artifacts/e2e-data`. The normal data directory is
not touched. Repeated runs append their own clearly named synthetic cases.

## Recorded acceptance

The final suite includes **99 passing backend tests**, including **10 independent
black-box acceptance cases**, and **2 passing Playwright tests**. The optional
black-box fixture directory is not bundled: ordinary fresh-checkout runs report
**89 passed / 10 skipped**. Code coverage was approximately **92% of backend
statements**, including complete exercised flow-builder and graph branches.

One upstream Starlette test-client deprecation warns that `httpx2` will replace
its current `httpx` transport. It does not fail a test or affect production
analysis. Migrating that test adapter is a future compatibility task.

| Coverage area | Evidence |
|---|---|
| Intake | Content, path sanitization, hash, owner-only permissions, invalid/malformed/truncated/empty, multipart streaming limit |
| Containers | PCAP/PCAPNG parity, big-endian nanosecond PCAP, multiple NG interfaces/resolution, unknown link warnings |
| Flows | Directional wire counts, timing, closure, reset, idle reuse, same-tuple conversations, retransmission negatives |
| Protocols | IPv4/IPv6, DNS endpoint/ID/question correlation and A/AAAA/CNAME/MX/NS/TXT/PTR/SRV, DNS/TCP, HTTP chunked/pipelined/reordered/gapped/conflicting streams |
| TLS | Exact JA3 string/hash, negotiated vs offered versions, missing/encrypted certificate visibility, real X.509 fingerprint, capture-time expiry |
| Additional protocols | ARP reply conflict, DHCP hostname/lease metadata, ICMP and SMB headers |
| Detection | Positive/negative controls, measured interval array, port/host scan, DNS, transfer, combined suspicious connection, HTTP/TLS indicators and config validation |
| Investigation | IOC normalization/dedup/evidence, search/exports, chronological timeline/filtering, graph edge-to-flow integrity, case links/notes/assessment |
| Reporting | PDF parsed with pypdf, actual expected text; Markdown/JSON/STIX; report hash, capture hash, analyst assessment and changed-evidence refusal |
| Safety/recovery | Queue full/duplicate job, HTTP responsiveness, startup recovery, clean retry, resource/time limits, protected deletion, external-off and mock-only provider calls |
| Browser | Upload both formats, analysis, DNS/TLS evidence, finding-to-frame traversal, ATT&CK, graph selection, case/notes/assessment, extraction, all reports, comparison and search |
| Accessibility | axe-core WCAG2A/AA/2.1AA at 1440px and 390px, zero violations on tested dashboard; no mobile document overflow; keyboard skip link |

`fixtures/README.md` documents exact counts/flows/findings for 12 generated
fixtures, each tested in both formats. Every fixture is synthetic and offline.

### Independent acceptance inputs

The coordinating session supplied independently generated/tcpdump-checked
normal, DNS-collision, port-scan, tuple-reuse and SYN-retransmission captures in
both formats. All 10 passed:

* exact SHA-256, packet counts, duration and total wire bytes;
* crossed DNS replies sharing transaction IDs/ports correctly separated by host;
* eight closed HTTP connections on one reused tuple remain eight conversations;
* identical unanswered SYNs remain one attempt and produce no beacon/scan finding;
* normal TLS has SNI but no fabricated certificate.

To rerun with an available directory containing that manifest and its captures:

```sh
cd backend
PACKETSCOPE_ACCEPTANCE_FIXTURES=/absolute/path/to/acceptance-captures \
  ../.venv/bin/pytest tests/test_external_acceptance.py
```

## Measured workload

```sh
cd backend
../.venv/bin/python benchmark.py --packets 10000 --output ../artifacts/performance-10000.json
../.venv/bin/python benchmark.py --packets 100000 --output ../artifacts/performance-100000.json
```

Recorded on macOS ARM64, Python 3.12.11, eight logical CPUs. Each command uses a
fresh temporary database and streams fixture generation, then verifies completed
analysis and the exact packet count. Process RSS includes framework/test-client
and fixture setup, not just the parser.

| Packets | Capture bytes | Analysis | Throughput | Peak process RSS | SQLite + WAL |
|---:|---:|---:|---:|---:|---:|
| 10,000 | 890,024 | 1.155 s | 8,655 pkt/s | 133.9 MiB | 12,615,912 bytes |
| 100,000 | 8,900,024 | 12.821 s | 7,800 pkt/s | 157.9 MiB | 80,768,168 bytes |

Both workloads produce 512 UDP flows, 65 hosts, 67 IOCs and zero findings. Memory
does not contain an entire raw capture; packet inserts are batched and TCP
reassembly is per-flow and bounded. SQLite metadata can exceed raw capture size.
These measurements do not establish multi-gigabyte, worst-case protocol or
multiuser scalability. The 128 MiB upload ceiling is an enforced ceiling, not a
benchmark claim.

## Dependency and design checks

Final `pip-audit --progress-spinner=off` and `npm audit --audit-level=moderate`
reported no known vulnerabilities. All runtime and development dependencies
were included. Initial outdated transitive packages were upgraded and the full
suite rerun. Rollup is explicitly pinned to a patched release that avoids a
CPU-bound transform regression observed with the initially resolved version.

The required Impeccable deterministic detector returned `[]`. Real desktop/mobile
inspection found and fixed a hash-navigation bug, a screen-reader-only element
causing mobile overflow, and low secondary-text contrast. Browser workflows and
axe checks were rerun after those fixes. Screenshots show actual synthetic
investigations, not mockups.
