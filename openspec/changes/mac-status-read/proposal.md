# Mac local status reliability

A single failed status read currently marks the whole adapter unreachable, including cancellation, malformed replies and server errors. Concurrent responses can overwrite newer observations. Fix the UI control-state boundary and add bounded, private diagnostics without changing the tunnel owner, recovery policy or daemon.
