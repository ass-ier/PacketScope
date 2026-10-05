# Architecture

FastAPI routes orchestrate services; SQLAlchemy stores normalized evidence in
SQLite (WAL, foreign keys, indexed entity relationships). Alembic owns schema
versioning. React/TypeScript provides a local, responsive Operate workspace.
Vite proxies same-origin API calls to loopback FastAPI.

Captures are random-name, owner-readable files. Content validation and streamed
SHA-256 hashing precede analysis. Raw network payloads are not database fields.
All important entities have stable IDs; frames remain tied to capture identity.

Foundation acceptance: content-based upload, sanitized display name, owner-only
storage, SHA-256 and persisted capture register.

## Module boundaries

`backend/app/services/` contains independent capture, packets, flows, reassembly,
DNS, HTTP, TLS, additional protocols, IOC, detection, timeline, ATT&CK, graph,
cases, search, advanced extraction/comparison, intelligence and reporting
modules. Flat service modules keep these boundaries explicit without empty
subpackages. `core/` owns database/runtime safety and `schemas/` validates inputs.

`frontend/src/` separates shared components/hooks/types/API helpers from
investigation, graph, cases, search, ATT&CK, advanced workflows, reporting and
settings pages. Native HTML controls and React Flow preserve familiar keyboard
and navigation behavior. An error boundary protects the saved-data workflow.

## Schema

| Tables | Relationships |
|---|---|
| captures | Immutable stored filename/hash and persisted analysis state/progress/visibility |
| packets | Capture + unique one-based frame; offset, link, timestamp, endpoints; optional flow |
| hosts, flows, sessions | Capture-scoped hosts; bidirectional flow identity; protocol sessions link flows |
| dns_queries, dns_answers | Questions link sessions/flows; answers link exact correlated questions |
| http_sessions, tls_sessions, certificates | HTTP/TLS sessions link flows and frames; certificates link TLS |
| iocs, evidence | Unique type/value per capture; Evidence links frame/flow/session/host/IOC/finding |
| detection_rules, findings | Validated config; findings preserve source rule snapshots and statistics |
| timeline_events | Ordered event references to frames and related investigation entities |
| attack_techniques, finding_techniques | Small offline catalog and evidence-grounded finding mappings |
| cases, case_captures, case_hosts, case_iocs, case_findings, case_notes | Relational investigation membership, notes, timestamped analyst assessment |
| extracted_files, threat_intel_results, reports | Explicit file evidence; timestamped optional external data; immutable export metadata |

There are 26 tables and 85 explicit indexes in the initial schema. A frozen
`migrations/versions/0001_schema.sql` keeps revision 0001 independent of future
Python model edits. New schema changes require a new migration. Foreign keys
and WAL are enabled per connection; SQLite is for one local application worker.

## Evidence and lifecycle invariants

Capture SHA-256 anchors every chain. Packet/flow/session IDs are stable for
completed analyses; completed captures cannot be reanalyzed in place. Failed
jobs may be retried and their partial derived rows are replaced. Cases accept
only completed evidence; linked cases/reports prevent capture deletion.

The worker commits packet batches and stage progress, checks elapsed time and
shutdown cancellation, bounds flow/host state and derived-record production.
Protocol failures roll back that dissector's partial work and emit visible
warnings while transport evidence remains available. Fatal resource or container
errors fail the overall job rather than pretending completion.

Reports are generated on demand rather than fabricated during analysis.
External intelligence adapters are outside the analysis path and are gated by
server opt-in plus per-indicator consent.
