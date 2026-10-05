# Optional advanced workflows

Capture comparison computes added/removed/common hosts, IPs, domains, protocols,
flow endpoint signatures, IOCs and finding signatures. Counts are exact within
the accepted capture; value lists cap at 200 and disclose truncation.

File extraction is explicit and only accepts complete nonempty HTTP/1 response
bodies. The original capture hash is verified; reassembled body hash must match
the indexed hash. Bodies are stored with random `.evidence` names, owner-only
permissions, never executed or decompressed, and downloaded only as octet-stream
attachments with `.untrusted` suffix and sandbox headers. Incomplete, ambiguous,
close-delimited and over-limit bodies are not extractable.

ReverseScope integration is a versioned **hash-only handoff envelope** at
`GET /api/files/{id}/reversescope`. It includes source capture identity and frame/
flow references. It does not assume a ReverseScope API, mutate that repository,
send a file, execute a binary or require ReverseScope to be installed. A future
consumer can accept `packetscope.hash-handoff.v1` without changing the core.

Intelligence adapters: RDAP registration metadata, DNS-over-HTTPS current
resolution and VirusTotal lookup. Core analysis never invokes them. Set
`PACKETSCOPE_EXTERNAL_ENABLED=true` explicitly to permit lookups; VirusTotal
additionally needs `PACKETSCOPE_VT_API_KEY` in the server environment. Each request
also requires consent to share the selected indicator. Never commit keys.

Providers have fixed service origins, 8s network timeouts, 1 MiB response limits,
no redirects and no ambient proxy use. RDAP uses ARIN; referrals to other RIRs
are deliberately not followed, so out-of-region lookups can fail explicitly.
Add a reviewed provider-specific adapter for another RIR. External data is timestamped,
separate from capture evidence, and never fabricated when unavailable.
