# HTTP analysis

Cleartext HTTP/1 request/response metadata comes from bounded TCP sequence
reassembly, not one-packet string matching. Segments are ordered and identical
overlaps deduplicated. Gaps stop reconstruction at the contiguous prefix;
conflicting overlaps, missing SYNs and resource truncation remain visible.

Requests and responses pair in stream order. Only observed methods, hosts, URIs,
headers, status, sizes and body hashes are stored. HEAD/204/304 responses have no
body. Interim 1xx responses are not paired as final responses. Chunked and
Content-Length framing are supported; duplicate/contradictory framing is rejected.
Unframed close-delimited bodies remain incomplete and cannot be extracted.

Each direction retains at most 256 KiB/2048 segments including retransmissions;
this is a visibility boundary, not a claim to reconstruct every transfer.
No decompression, executable inspection, HTTP/2 decoding or HTTPS decryption is
attempted. Bodies remain in original capture evidence until explicit extraction.
