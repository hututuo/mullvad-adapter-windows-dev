# Requirements

- LS-1 WHEN control locks are held by slow work THEN HTTP status reads return the most recent valid publication without acquiring those locks; publisher skips rather than waits. No control guard or atomic commit is weakened.
- LS-2 WHEN publication is missing/older than 3 s THEN return a typed unavailable/stale response; never renew old data or report it fresh. Returned JSON remains immutable after live state changes.
- LS-3 WHEN account/city/metrics requests are delayed THEN status uses its own connection pool and polling cadence. Never retry mutations or change tunnel ownership.
- LS-4 WHEN status succeeds THEN preserve actual observation age, conservatively including request/scheduling time; a delayed publication over 3 s must not revive ready. Log only bounded numeric timing/category fields. Legacy responses remain compatible, cancellation/ordering fences stay intact.
- LS-5 Tests use fake/temporary instances only; production network, account, engine processes, startup and installed software stay untouched. Packaging/install are deferred by user request.
