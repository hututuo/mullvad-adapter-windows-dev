# Bounded Windows network stability improvements

Delay new tunnel work while physical bindings settle, retain interrupted same-node intents, and make API bootstrap independent of system DNS. Preserve original-path and same-city policy, unique identity ownership, readiness freshness, cancellation and fail-closed front. No physical network/power changes or automatic device mutations. This does not implement new tunnel transports or promise that an upstream-blocked UDP path will work.
