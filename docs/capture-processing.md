# Capture processing

Upload streams to a random owner-only filename while computing SHA-256; actual
container magic/headers, not the supplied suffix, determine format. Upload and
analysis are separate actions. Analysis uses one local worker and a four-job
bounded queue. HTTP remains responsive. Progress is persisted between batches.

Statuses: stored, queued, parsing, processing, completed, failed. On restart,
interrupted jobs become failed with an explicit retry message. Failed analysis
can be retried; partial rows are replaced. Completed evidence is immutable.
Shutdown requests cooperative cancellation before closing the database.

Hard ceilings: 128 MiB upload, 250,000 packets, 30,000 flows, 20,000 hosts,
256 KiB/frame, 600 seconds/job. Packet summaries are bulk-inserted in batches of
512. Flow/host maps are bounded by the configured ceilings. Exceeding a ceiling
fails explicitly; partial observations are never labelled a completed analysis.

Additional final ceilings: one million indexed packets per workspace, 200,000
derived analysis records per capture, 200 stored captures and a 2 GiB aggregate
capture-file quota. Request-body accounting runs before multipart spooling,
including chunked/no-Content-Length uploads, and one upload proceeds at a time.
Derived records flush incrementally; resource exhaustion is a failed job, not
an optional parser warning. Workspace database/export disk growth is separate
from the capture-file quota and must be monitored.
