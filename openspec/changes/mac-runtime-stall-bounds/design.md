# Design

Keep the installed engines and state ownership unchanged. A single in-file command runner owns new process groups for diagnostic children only, drains stdout/stderr nonblocking, retains at most64KiB per stream, and uses a monotonic deadline with bounded cleanup. Canary collection has an independent aggregate deadline; pending probe threads are cancelled, and their runner ensure blocks clean their children. No new runtime file dependency is introduced.

`LocalProbeTimeout` represents an indeterminate local observation, separate from a normal curl exit28. It propagates through probe aggregation and candidate evidence. Active health, startup, dead-worker recovery and city selection stop the current attempt on local failure rather than quarantining remote candidates. Same-peer rebuild retains its existing break-before-make and explicit rollback semantics. A controller response's absolute deadline prevents incremental reads from extending the startup budget.

Both front data supervision and controller-degraded supervision share the same fallback-service observation. An independent HTTPS success preserves the data path even if the literal-IP diagnostic fails. Existing context checks still precede selector/repair changes. These are independent observations, not proof of a process deadlock; passive historical logs without phase stacks cannot establish that cause.

Synthetic regressions use temporary state, owned fixture children and one ephemeral loopback HTTP server. They never create a WireGuard tunnel or operate the installed application. Installation, external data-plane validation and long-term acceptance remain separate.
