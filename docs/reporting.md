# Forensic reports

POST `/api/reports` with capture ID, optional linked case ID and format (`pdf`,
`markdown`, `json`, `stix`). Generation requires completed analysis and a verified
original SHA-256. GET `/api/reports/{id}` retrieves persisted metadata;
`/download` verifies the report hash and serves a download attachment.

PDF (ReportLab) and Markdown include executive summary, capture information,
observed/affected hosts, network overview, timeline, DNS/HTTP/TLS, certificates,
suspicious-flow explanation, findings, IOCs, supported ATT&CK mappings, evidence,
files, analyst assessment/notes, recommendations and explicit limitations.
Up to 250 records per section are included, with exact totals and truncation
disclosure. PDF renders non-ASCII source text as escaped code points so evidence
is not silently lost through missing font glyphs.

JSON streams all indexed normalized section entities and sessions in bounded
database batches, including packet summaries. Raw payloads remain only in the capture. STIX uses actual
cyber-observables/ObservedData, evidence Notes and analyst assessment; it does
not turn routine observations into malicious Indicators. Empty captures use an
explicit custom empty-investigation object, not invented observations.

Saved reports are immutable hashed files with owner-only permissions. A later
assessment change requires a new report; old evidence snapshots are preserved.
Exports fail explicitly above 64 MiB. Captured content is escaped/indented, never
executed as templates or remotely fetched imagery.
STIX also has a 10,000-IOC limit to bound its object construction; its observed
counts use real evidence-association totals, with representative frame lists.
