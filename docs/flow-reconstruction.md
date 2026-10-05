# Flow reconstruction

Canonical bidirectional transport endpoints group packets. Orientation follows the
first observed packet, not an invented client role. A new SYN with a different
initial sequence, a SYN after observed closure, or idle separation creates a new
conversation. Idle thresholds: TCP 120s, others 30s. Identical unanswered SYN
retransmissions remain one attempt, even across idle gaps.

TCP state labels describe observations: SYN, SYN/ACK, handshake, FIN closure or
reset. A FIN means closure observed, not proof of a complete graceful teardown.
Flow/session IDs preserve tuple reuse. Out-of-order timestamps use min/max timing.

`bytes_sent`/`bytes_received` are **original wire frame lengths**, including link
layer, retransmissions and bytes not retained by a short snapshot. Payload counters
also include retransmissions; they are not unique application byte counts.
Protocol reconstruction separately deduplicates TCP sequence ranges.

Host inventory includes observed endpoints (including broadcast/multicast where
present); it is not proof that every destination responded or is an active host.
Its MAC value is the link-layer address observed alongside that IP in the capture,
not proof of the remote host's physical NIC identity. Across a routed link it may
be a next-hop router's MAC; ARP claims are separately preserved as protocol evidence.
