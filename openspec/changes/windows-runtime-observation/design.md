# Design

DNS and HTTPS transports distinguish local failure before the SOCKS CONNECT
request from upstream rejection. Canary collection emits its existing closed
phase diagnostics first, then returns LocalFailure if there is no independent
successful IP/hostname result and any local phase was unavailable. Successful
traffic retains the existing Ready/degraded matrix. Ownership rejection still
cancels siblings and rejects the entire collection. Existing active local failure
handling rechecks, then rebuilds the original path; no new relay failure is minted.

Pass the existing front/worker startup Instant into read-only controller calls,
local listener connection and chain endpoint resolution. Clamp leaf budgets to
remaining parent time and reject late resolver responses. Per-call controller
configuration must not persist an expired startup deadline into later operations.
Native owner queries cannot be forcibly interrupted; scoped probes remain joined
and cleanup has its own budget. Do not remove ownership/epoch checks to obtain a
nominal timing guarantee. Tests use ephemeral loopback fixtures or injected probes.
