# Shared-core development skeleton

> Imported module notes include historical stage limits. For the current maintenance entry and implemented Windows map, read [development](../docs/development.md) and [Windows maintenance](../docs/windows-maintenance.md). These notes do not override current source routing or provide new runtime acceptance.

This workspace is development-only. It does not create a live tunnel, claim Windows installation acceptance, or replace the Ruby owner. Run `cargo test --locked` here. The shared Ruby fixture check is scripts/test-shared-contract.rb and runs separately from packaged daemon tests.

- `domain`: pure attachment/recovery/protection/ownership decisions using an explicit monotonic clock.
- `protocol`: versioned JSON with a 4-byte little-endian length, maximum 65,536 bytes, bounded request IDs and strict commands.
- `control`: single-owner mock operation registry and bounded work executor. Every mock mutation returns `unavailable_mock_backend` rather than fabricating connection success.
- `agent`: isolated `--mock-stdio` framed development endpoint. This transport is not an authorized production IPC interface.
- `platform`: Windows user/session DACL, impersonation identity check, single instance and bounded local pipe prototype. Linux `cargo check -p adapter-platform --features windows-api-check` checks API signatures only; it does not run Windows APIs or substitute for a Windows build.

No account secrets, identity import, engine management, route changes, autostart registration or installer are enabled by the mock runner. Named pipes, process jobs, real installation and data-path acceptance are separate gates. Do not connect the mock protocol to a production daemon.

## Contract fixtures

`crates/protocol/fixtures/legacy` contains the old HTTP response fixtures. Generate with `ruby scripts/export-contract-fixtures.rb` from the repository root. This uses fake processes and documentation addresses, never a live daemon. Timestamps, source digest and ephemeral paths are normalized. The operation example is synthesized from the operation shape. These fixtures capture field contracts, not an implemented HTTP compatibility server.

`canary-cases.json` exhaustively enumerates 32 readiness/required-PQ combinations and is tested by both Ruby and Rust. Readiness intentionally retains the legacy IP-or-HTTPS liveness definition; HTTPS plus DNS may establish ready when the literal-IP diagnostic is unavailable. New fallback candidates require readiness; an existing original path may be preserved with DNS/service degradation. The legacy acceptance of some degraded non-PQ startup candidates is not the target fallback contract.

## Explicit stage limits

This is P0/P1 partial implementation, not completed P0–P5. Full old-client Swift decode/conformance, event-sequence replay parity, Windows-hosted IPC security and lifetime tests, Job Object cleanup, DPAPI/storage, Mihomo routing, native Tauri/pipe acceptance, offline WebView2 installation and real Windows/PQ acceptance are still required. Never relabel a pure-domain test as routing or installation evidence.

Native pipe responses require a bounded ResponseAck frame carrying the request ID before the server advances or closes the session. The original five-second session deadline bounds acknowledgement waits. The debug stdio transport does not require this pipe-specific close acknowledgement.
