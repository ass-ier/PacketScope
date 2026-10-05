# Security model

## Trust boundary

PacketScope is a local, single-analyst workstation application. Bind to
127.0.0.1, use one Uvicorn worker and do not expose it through a public proxy.
There is no multiuser login, authorization model, encryption-at-rest layer or
container sandbox. OS account security and disk protection remain necessary.

Network content is untrusted bytes, never executable input. No parser, detector,
reporter or extractor calls a shell, executes a payload, performs active probing,
decompresses a captured archive, loads captured HTML or resolves an observed
domain automatically. SQL parameters are bound through SQLAlchemy. React escapes
text, and report rendering escapes/indents captured values.

## Intake and storage

* ASGI request-size accounting runs before multipart parsing, including streamed
  requests without Content-Length. Only one capture upload proceeds at a time.
* Capture content must contain valid PCAP/PCAPNG framing headers. Individual
  malformed frames and unsupported link/protocol visibility are reported.
* Display names are sanitized; storage names are UUIDs, outside static assets.
  Files are created exclusively with owner-read/write permissions.
* Upload, packet, frame, host, flow, derived-record, queue and elapsed-time ceilings
  prevent unbounded processing. Workspace packet/capture quotas also apply.
* SHA-256 is rechecked before packet detail, extraction and reporting. Changed
  evidence produces a conflict error, not a plausible-looking result.
* SQLite is relational with foreign keys. Cases/reports preserve capture
  references. Failed jobs are explicit; restart recovery marks interrupted work.

Capture-file quota is not a complete disk quota: normalized SQLite records,
exports, browser tests and user-created reports consume additional space. The
workspace packet ceiling bounds indexed input, but the analyst must monitor
disk capacity and keep backups. Disk/permission failures are logged and returned,
not silently ignored.

## Browser and downloads

Trusted Host validation and cross-origin write rejection limit browser-to-local
service attacks. Production responses set no-sniff, no-referrer, no-store,
frame denial and a self-only CSP (inline styles only for graph layout).
Development Vite is loopback-only. CSP was verified to block inline checker
injection; accessibility tests bypass it only in their isolated audit context.

Explicit extraction requires acknowledgment of untrusted content. Only a complete
HTTP body with a matching indexed hash can be written. Output remains a 0600
`.evidence` file, downloaded as `application/octet-stream`, `attachment`, and
`.untrusted`, with sandbox policy. The app never opens it automatically.
CSV exports neutralize leading spreadsheet formula characters.

## Optional external intelligence

`PACKETSCOPE_EXTERNAL_ENABLED=true` is required, and each lookup must separately
consent to share the indicator. API keys are server environment variables, never
included in API status, reports or the repository. Fixed provider origins,
redirect refusal, 8s timeouts, 1 MiB response limits and disabled ambient proxies
bound requests. Results/errors are timestamped and separate from capture evidence.

No live provider requests were used during validation. Mock transports verified
request/response contracts. ReverseScope handoff exports a hash-only envelope;
it neither reads nor mutates a ReverseScope installation.

## Dependencies and limitations

Top-level Python versions plus a complete lockfile and npm package-lock are
committed. Final `pip-audit` and `npm audit` reported no known advisories in the
installed dependency sets. Audit results are point-in-time, not a proof of
absence of vulnerabilities. Registries/audits saw dependency metadata only,
never captures, indicators, API keys or analyst notes.

dpkt/cryptography/reportlab operate in the application process; they are not
OS-isolated hostile-file sandboxes. The cooperative timeout cannot interrupt a
single stuck native/library call. Small bounded input slices, derived-record
budgets and explicit unsupported formats reduce exposure; process isolation is
a documented next hardening step before accepting arbitrary Internet uploads.

## Public synthetic demo profile

The optional Vercel/Render preview is a separate, read-only profile, started with
`backend/demo.py`. It generates only repository-owned synthetic fixtures before
serving traffic. Existing unmarked databases are refused. A manifest verifies
all relational rows and stored capture/report/extraction hashes on reuse, so an
accidentally mixed or edited dataset fails startup instead of being published.
This guards configuration mistakes; it is not a signature against a malicious
OS administrator who can change both the database and its manifest.

All non-GET/HEAD/OPTIONS requests are rejected before body parsing in demo mode,
and external intelligence cannot be enabled. No analysis worker or OpenAPI UI
is exposed in that profile. Capture comparison uses a read-only GET endpoint.
The frontend explicitly labels synthetic content and removes mutation actions.
The Docker container runs as non-root and only approved source files enter its
build context. Vercel forwards same-origin `/api` traffic to the configured
Render origin; it does not grant anonymous editing access.

Only this preloaded sample profile is intended for a public portfolio preview.
It adds no authentication to ordinary local mode. Never point demo mode at a
real evidence directory or use it as an Internet-facing upload service.
