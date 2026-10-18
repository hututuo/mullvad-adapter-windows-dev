# Inner DNS canary validation

The Ruby canary sends one IN/A question over the worker's loopback SOCKS5 route
to10.64.0.1:53/TCP. A positive DNS result requires more than a matching transaction
ID and nonzero declared ANCOUNT. The complete framed packet must decode through
the standard Resolv DNS wire decoder, with no truncated records or trailing data.
It must have QR=response, opcode QUERY, TC=0, reserved Z=0, RCODE=0, exactly the
expected case-insensitive IN/A question, and a related IN/A answer. The stdlib
decoder rejects non-backward and cyclic compression pointers; decoded names are
also limited to63-byte labels and255-byte total encoded length by a local decoder
subclass, including names nested in NS/MX/SOA/SRV and other known records.

Answers may traverse an unambiguous CNAME chain with at most16 hops. Unrelated
A records, AAAA-only replies to this A question, missing terminal A, alias loops,
conflicting aliases or an A+CNAME owner combination do not pass. The parser
consumes authority/additional records too and rejects malformed tails. It limits
the frame to DNS's65535-byte TCP length and4096 total resource records. This is
DNS syntax/question/answer validation, not DNSSEC, account authentication, a
reachability proof for the returned address, or an independent proof of a VPN.

Nine tests include real Socket.pair/thread exchanges for positive compressed
A/CNAME replies and negative flags/question/id/answer/count/compression cases.
Pure decoder tests additionally enumerate every truncated prefix and verify
name/CNAME-hop/record-count limits. Valid AD/CD flags, OPT and nested NS authority remain accepted. No test sends
packets to a live resolver.
The higher-level IP/DNS/HTTPS classification is unchanged: DNS alone does not
prove data-plane liveness or authorize a new protected worker.

The decoder helper subclasses Resolv::DNS::Message::MessageDecoder locally,
without monkey-patching it or constructing a resolver. Questions use raw type/
class checks; OPT records require a unique additional-section root owner, zero
extended RCODE and complete code/length/value option envelopes (RFC6891). Unknown
option values remain opaque; AD/CD and DO are not rejected. SVCB/HTTPS also use
local strict target-name and ordered parameter-envelope parsing, avoiding the
stdlib SvcParam dynamic class cache; their values remain opaque and cannot
supply A evidence. Other known resource classes decode normally under the strict name
reader. Unknown type/class RDATA is consumed as bounded opaque bytes and cannot
supply an A answer. It does not create the stdlib's globally cached Generic
classes/constant names from untrusted response numbers; a regression checks that
ClassHash does not grow. No semantic validation of unknown RDATA is claimed. It performs
no lookup or filesystem access. The existing canary timeout and socket ensure
cleanup remain in force. Exact runtime versions and native execution evidence
belong in the private verification record rather than being inferred here.
