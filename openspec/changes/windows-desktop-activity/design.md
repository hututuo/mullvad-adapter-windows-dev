# Design

Read fixed per-user event filenames through the protected log opener; tail at most 512 KiB/file, return at most 500 allowlisted typed events. Never open agent AppRoot or acquire its owner lock. Preserve exact probe outcomes and recorded relay; never invent missing relay names. Chinese messages retain expandable technical codes.

HKCU Run stores only this executable, quoted absolute path plus --autostart. Reads never create entries. Missing means OFF. Refuse foreign same-name values; explicit toggle writes/readbacks only owned registration. Login launch hides main window; normal launch shows it. Existing connect_on_start stays independent.

Windows notification area supports icon/tooltip, not permanent text. Use coloured globe and node/ICMP tooltip. Separate opt-in opaque 260x80 status window has no backend/account capability. Close destroys it. A 5 s status tick reuses main-window dashboard replies; only while hidden with cache older than 7 s may it poll verified IPC; snapshots older than 15 s become unknown, not disconnected.

Only expose existing ICMP maintenance for current relay/city, within 180 s, physically online/connected. Native UI rechecks future/stale/wrong-relay evidence. ICMP is outer reachability, not tunnel egress. No new probes or second identity tunnel. Missing measurement stays absent.
