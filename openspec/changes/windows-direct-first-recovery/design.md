# Implementation

`recovery_plan` owns debounce, exact-original short retry count, the fixed relay
set, explicit chain phase and direct-return backoff. `Connections` remains the
single policy owner. Both Unready and Prepared→Abort→Stopped classify a fresh
negative only after cleanup; Domain fences candidate/epoch/instance/time, and
the operation registry additionally fences physical binding changes during drain.
Domain explicitly continues original rebuilds without manual-preempt budget reset.

`InletTrials` caps endpoint failures independently by route (primary direct 3,
other direct 2, chain 2; 13 distinct total). Bounded passive success summaries are
DPAPI-protected and saved on a separate one-job worker; they rank only currently
authorized choices. No full WG standby measurement runs in the background.

The native Clash command reads source leaves and probes an SS-only owned engine
through its authenticated physical UDP carrier. Two random-ID DNS exchanges and
carrier witness qualify the carrier; final whole-tunnel readiness remains a
separate serial connection transaction. The renderer never receives credentials.
The app schedules preparation independently of which page is open. Manual tests
and automatic direct return retain prior path facts and restore it serially on
failure. No DIRECT fallback is added to the application front.

Main-page progress is owner-produced structured IPC. A route trial can briefly
interrupt long connections; this is not a parallel hot standby or a kill switch.
Signed release, clean-OS installation, disruptive network/sleep tests and Mac
production deployment remain separate acceptance scopes. OpenSpec files are
maintained as Markdown, without claiming CLI initialization or validation.
