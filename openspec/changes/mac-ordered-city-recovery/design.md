# Design

A dedicated recovery mutex serializes the ladder without being read by the status HTTP handler. Short state updates publish recovery fields through the existing immutable status snapshots; monotonic elapsed/countdown fields are decorated on a copied snapshot. A control epoch fences pending/in-flight recovery and is checked again at the state commit point alongside the physical network epoch. The operation gate still owns explicit UI commands.

The ladder pins one catalogue-authorized inlet and transport for each activation through thread-local attempt context. Same-peer activation uses existing break-before-make. The ladder owns the next attempt, so activation cannot silently roll back or expand its transports/inlets. Cross-relay activation retains existing peer-key and lifecycle guards. A local launch/stop/probe failure defers; only a completed negative data observation scores a failed inlet or finishes a relay's allowed trials. Protected circuits preserve their profile and entry semantics, and cannot use ordinary relay history as protected readiness proof.

Health confirmation, worker-crash, disconnected and post-network-resume rebuilding use this owner. Network resume first probes the existing path and keeps it if alive. Cold initial startup and explicit transport/protection changes retain their own existing contracts.

SwiftUI reserves a home progress card, decodes optional daemon fields for compatibility and gates controls on fresh status. Countdown values are daemon observations, not a UI timer that could turn stale data into live progress. No live network fault is induced by the tests.
