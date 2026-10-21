# Requirements

- WS-1 WHEN control is busy or owner work stops THEN status reads use an independent pipe and immutable publication without control gate/queue/disk/network waits.
- WS-2 WHEN a publication is missing or older than 3 s THEN report typed pending/stale, never refresh its timestamp; retain capture/observation age across native, renderer and tray.
- WS-3 WHEN any client uses the status channel THEN enforce SID/session and major/source/build/boot/request checks and bounded frame/deadline/ACK; reject every mutation and private-key request. Keep control/peer/recovery/protection semantics unchanged.
- WS-4 WHEN the status channel is busy/unavailable THEN do not infer tunnel failure or launch another backend if the control owner exists; startup remains verified, unique and coordinated; explicit stop prevents automatic restart.
- WS-5 WHEN status reads fail, arrive late, are cancelled or recover THEN keep last known data with its age, classify busy/pending/stale/invalid/security/sustained transport separately, fence old completions and keep operation feedback independent. Never renew old connected/latency indicators.
- WS-6 Only tests run for this change. No package/install/live tunnel/physical interruption/power change. Windows-native fixtures run on isolated CI and do not prove installed or egress acceptance.
