# Inner stored-record format

This codec is the next layer inside DPAPI, not a file-store implementation. DPAPI
success alone does not establish that decrypted application data is well formed.

A fixed 48-byte header binds magic, schema version 1, record kind (account/identity/
policy), reserved zero bytes, payload length and SHA256 (prefix+payload). Unknown
versions/kinds, cross-kind reads, length mismatches and checksum failures fail
explicitly before returning a borrowed payload. Payload length is 1..65488 bytes,
so the complete inner record fits the 64 KiB DPAPI limit. The digest is corruption
checking inside DPAPI, not a replacement authentication key or a defense against
someone already able to encrypt as the same user.

Encoding preallocates the exact buffer and keeps it in a private Zeroizing wrapper;
there is no Debug/Clone/Serialize or implicit Deref on the exported record type.
Decode borrows from its caller's decrypted Secret, avoiding another plaintext copy.
Normal zeroization limits still apply to hashing internals, swap, crash dumps and
copies created by callers. SHA2 and zeroize dependencies are pinned and locked.

The three portable regression tests cover roundtrip, wrong-kind reads, each single
byte position corrupted, empty/oversized inputs, truncation and the exact maximum.
Malformed headers are also checked with a recomputed checksum, independently of
checksum failure; borrowed payload pointers are verified for all three kinds.
These are controlled corruption tests, not a claim to detect every conceivable
malicious transformation. Domain parsers must still validate account/token and WG
identity semantics, including key/identity consistency, before using payloads.

Private Windows directory/file ACLs, atomic staged-write commit, interrupted write
recovery and transaction-owner integration remain the next implementation layer.
No account/key files or live settings are read or changed by this codec.
