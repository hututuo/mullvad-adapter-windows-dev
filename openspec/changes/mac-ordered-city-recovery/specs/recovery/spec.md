# Recovery requirements

## MAC-REC-01 Confirmation and preservation
WHEN one fresh data observation fails, THEN keep the current worker and perform the existing ~2-second recheck. Only two consecutive current-context data failures admit automatic recovery. IP or hostname HTTPS success means the tunnel remains alive; DNS-only degradation cannot initiate relay switching. Physical offline, stale/canceled observations and local probe failures are not negative relay evidence. A healthy worker with broken front ingress is repaired locally first.

## MAC-REC-02 Ordered serial attempts
WHEN the saved official inlet remains authorized, THEN retry the exact relay/inlet up to three times: immediately, then 1 second and 5 seconds after each previous failed attempt has cleaned up. Next try at most two distinct ranked SS inlets on that relay, then at most four other eligible relays in the selected city with at most two inlets each. Every attempt must remain in the requested transport family and protection profile; no implicit rollback or transport sweep. When the original inlet was withdrawn, show that the current official inlet is being used, rather than claim an exact-path retry. Relay/entry withdrawal is honored. Candidates come from catalogue and local measured history, never developer machine addresses.

## MAC-REC-03 Ownership, budget and interruption
WHEN automatic health, worker-crash or disconnected recovery compete, THEN one recovery owner runs and other automatic callers do not queue. The round admits new starts for 300 seconds; the in-flight attempt and cleanup retain their own bounds. User retry-current, retry-round and stop are authenticated local controls. Stop/manual preemption invalidates queued and in-flight recovery tokens; canceled work cannot commit. Network epoch and active generation remain guarded. A local termination error keeps old peer ownership and defers rather than launching another instance. Exhaustion waits the existing 30-second cooldown; local component deferral uses the local-network retry interval. Stop preserves existing traffic and suppresses future automatic recovery until an explicit connection action.

## MAC-REC-04 Main-page evidence
WHEN recovery progresses, THEN the home page shows the phase, actual target/inlet, total attempts, elapsed round budget, retry countdown and next step, with controls to retry the original node, restart the round or stop. The card has reserved height. A stale status read displays last recorded progress and disables controls. Old daemon responses remain decodable without fabricating progress. Show up to four city candidates. Mac must explicitly disclose the absence of chain fallback.

## MAC-REC-05 Traceability
WHEN a worker starts or a canary completes, THEN log an allowlist of relay, actual inlet/port/interface, instance token, network epoch and per-phase probe evidence under existing bounded rotation. Hardware active-interface set changes are recorded without treating an available-to-available notification as physical disconnection. No private identity, account, configuration or application traffic contents enter these new events.

Deterministic tests prove policy/state behavior only. Installed egress, interruption timing and sustained stability are separate acceptance evidence; historical failures without per-attempt path/packet evidence remain unresolved.
