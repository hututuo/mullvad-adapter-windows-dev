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

## MAC-REC-07 Background pacing and failure evidence

Health, front-path observation and city maintenance use one nonqueuing background observation gate. The front-path default interval is 30 seconds; the existing failed-health fast recheck remains. Candidate maintenance sends at most one ICMP observation per five seconds globally, only with a ready active path. A local ICMP timeout is unknown, does not quarantine the relay, and does not abort future candidates. No spare WireGuard identity is brought up to maintain candidates.

After consecutive automatic exhausted recovery rounds, cooldowns are 30, 60, 120, then 120 seconds with default settings (superseding the fixed cooldown in MAC-REC-03). The first round's ordered attempts remain unchanged. Fresh ready evidence or a physical offline epoch resets the backoff; explicit manual retry bypasses the timer while preserving ownership fences. Fully validated current-context success reconciles old local-network failed/degraded/local-repair state without clearing a newer paused/pending recovery.

Background catalogue refresh uses one HTTP attempt per refresh; consecutive failed refreshes wait at least 30, 60, 120, 240, then 300 seconds. Valid cached data remains usable. Success returns to normal catalogue TTL; explicit refresh keeps its separate contract. The dedicated Clash control-path HTTPS observation shares the background observation gate and is skipped during ordered recovery. No OpenAI/ChatGPT background probes are added.

Before a failed worker can be reused, persist an allowlisted aggregate of at most its last 16 KiB of engine log, with worker/path correlation. No raw application destinations, payloads or credentials are included. Absence of exposed engine handshake/UDP counters is explicitly recorded, not inferred from inner TCP errors. An explicit passive diagnostic may count authenticated SS-carried WG packet types; it never generates network probes, changes the daemon, or treats a handshake-shaped response as proof of accepted WG keys or working application traffic.

## MAC-REC-06 Resume-owner liveness and explicit retries

WHEN original-path verification after attachment recovery raises a local probe timeout/unavailable result, THEN keep the network recovery pending, defer by the existing local interval, and keep the health owner running. No negative relay sample or extra worker may be created solely from that exception. A later successful original-path verification must finish the same network epoch. The complete monitor iteration, including wait/admission and resume work, catches ordinary errors, logs an allowlisted error class/phase and waits before retrying; monitor start/stop events expose owner lifecycle without signaling engines.

WHEN an authenticated manual retry-current/retry-round runs while network recovery is pending, THEN it uses the authorized resume activation path rather than being rejected by the generic automatic-recovery guard. Existing physical-offline, token, epoch, generation, same-city and peer-ownership fences still apply. A verified successful manual rebuild finishes that epoch's resume state. A failed selection must not claim an old unverified/resume-pending path was restored merely because its earlier liveness value was pass.

## MAC-REC-08 Independent offline evidence

WHEN the external network or the interactive agent is unavailable, THEN an independently supervised local recorder continues observing local worker physical-interface UDP counters and allowlisted WireGuard events from the local HTTP log stream. It must not request Internet targets, change global engine logging, hold adapter lifecycle locks, launch tunnels or change routes. It must continue previously identified worker observation across a stale/unavailable status API and label that context as stale.

Only fixed event names/counts, path correlation and timing are persisted. Raw debug content, keys, configuration and application destinations must never be persisted. Ring logs are bounded to 4MB total; the first and latest samples of the current incident survive within a separate 64KiB snapshot plus one previous incident. Diagnostic export includes these files without requiring a healthy external network. Singleton locking prevents duplicate recorder loops. Recorders do not claim replay coverage before subscription or zero packet loss in engine event queues. Lifecycle installation/rollback affects only the recorder service, preserving the current adapter/core connection.

## MAC-REC-09 HTTPS destination recovery

WHEN a worker receives a public literal-IP TLS connection on port 443/8443 with no hostname, THEN recover a visible ClientHello server name through the pinned engine and use the existing WireGuard in-tunnel resolver for that name. Preserve explicit hostname requests, private/link-local destinations, other ports and unrecognized protocols; no DIRECT fallback, system DNS listener, new identity or background website probes may be introduced. Opaque or absent SNI cannot be claimed recovered. Probe readiness must never be reported as proof all application destinations work.

WHEN observing an IPv6 outer endpoint on macOS, THEN request ICMPv6 echo without the IPv4-only `-W <milliseconds>` form and retain the existing aggregate subprocess deadline. Echo observations remain optional and cannot turn successful IP/DNS/HTTPS evidence into a relay failure.
