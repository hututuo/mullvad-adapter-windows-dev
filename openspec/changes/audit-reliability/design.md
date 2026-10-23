# Design

Mac-generated front and worker controllers receive separate random lifetime
credentials; configs remain private and internal HTTP supplies Bearer auth.
Worker ownership is registered before controller startup, and uncertain cleanup
retains the slot/peer reservation. Interrupt masking covers resource acquisition
through registration, including Ruby Thread.kill; cancellable waits remain outside
that region. A local SOCKS connection/greeting failure cannot consume a relay.
Independent successful data evidence still preserves a live path.

Control-path logging uses the existing bounded asynchronous writer. Status writes
have a one-second application deadline, and the UI sends a random request ID.
Numeric accept-to-handler, request-read, publication and UI elapsed timings can be
correlated with receive/finish events. Host scheduling can delay deadlines; a lost
queued log is not proof a request never arrived.

Windows route trials retain persistent recovery intent. Local worker failures keep
their target with capped backoff inside existing round budgets. Automatic chain
qualification carries both a native intent epoch and an agent-issued ticket.
Cancellation and durable commit share a mutex: the owner uses try_lock and reports
busy during an already-started commit; acknowledgement invalidates every later
commit using the cancelled ticket. This is separate from renderer generation.

Report schema 2 uses a typed status allowlist rather than serializing Dashboard;
existing validated event history remains bounded. Candidate builds bind requested
SHA to clean checked-out inputs and recheck their content around build stages.
Expected caches are excluded; this is provenance validation, not a hermetic build.
