# TLS metadata

TLS records and handshake fragments are reconstructed across bounded TCP
segments. Observable ClientHello yields SNI, offered cipher/version metadata and
JA3 (GREASE values excluded). ServerHello yields the negotiated version and
selected cipher. A client's legacy version is **not** a negotiated version.

Visible pre-encryption certificate messages are decoded with cryptography:
subject, issuer, serial, validity, algorithm, SHA-256, DNS SANs, and verified
self-signature status. Missing/encrypted certificates remain unavailable.
TLS 1.3 normally encrypts certificates; arbitrary TLS is never decrypted.

JA4 is explicitly unsupported, not synthesized. JA3 fingerprints indicate a
handshake configuration, not an identity or proof of malware. ECH, QUIC, encrypted
SNI, session resumption and missing packets constrain available observations.
No trust-store validation or live certificate lookup is performed.
